#!/usr/bin/env python3
"""
WiFi Guard - Evil Twin / Rogue AP Detector + Auto-Disconnect
---------------------------------------------------------------
Watches nearby WiFi networks and alerts you by email if it ever sees
your home network's name (SSID) being broadcast from a DIFFERENT
router (a different BSSID / MAC address). That's the classic sign of
an "evil twin" attack, where someone clones your WiFi name to trick
your devices into connecting to them instead.

NEW: It also checks what network your computer is CURRENTLY connected
to. If you are connected to a network that has your home WiFi's name
but an unrecognized BSSID, it will automatically disconnect you AND
email you about it. (Windows only for the auto-disconnect part.)

Works on Windows and Linux for scanning/alerts. Auto-disconnect
currently only works on Windows (uses the `netsh` command).

HOW TO SET IT UP
-----------------
1. Fill in WATCHED_NETWORKS below with each WiFi name you want to
   protect, and the real BSSID(s) (MAC addresses) for each one.
2. Fill in your email settings.
3. Run: python wifi_guard.py
4. Leave it running in a terminal.

HOW TO FIND A ROUTER'S BSSID (its MAC address)
---------------------------------------------------
Windows:  netsh wlan show networks mode=bssid
Linux:    nmcli -f ssid,bssid dev wifi list

Look for the network's SSID in the list - the BSSID next to it
is what you put in WATCHED_NETWORKS below. If a router has multiple
bands (2.4GHz and 5GHz) or multiple access points (mesh system),
add ALL of their BSSIDs under that same network name, otherwise it
will think your own second AP is an attacker.

YOU CAN WATCH MULTIPLE NETWORKS AT ONCE
-----------------------------------------
Add as many entries to WATCHED_NETWORKS as you like - your home
WiFi, your phone's hotspot, an office network, etc. Each one gets
its own list of known-good BSSIDs.
"""

import subprocess
import platform
import re
import time
import smtplib
import ssl
import logging
import ctypes
from ctypes import wintypes
from email.mime.text import MIMEText
from datetime import datetime, timedelta

# ============== CONFIG - FILL THIS IN ==============

WATCHED_NETWORKS = {
    "YourHomeWiFiName": [
        "AA:BB:CC:DD:EE:01",   # 2.4GHz BSSID
        "AA:BB:CC:DD:EE:02",   # 5GHz BSSID
    ],
    "YourPhoneHotspotName": [
        "AA:BB:CC:DD:EE:03",
    ],
    # Add as many networks as you want to protect, in this format:
    # "SomeOtherWiFiName": ["AA:BB:CC:DD:EE:FF"],
}

SCAN_INTERVAL_SECONDS = 30            # how often to scan for nearby networks (passive check)
CONNECTION_CHECK_SECONDS = 5          # how often to check what you're CURRENTLY connected to (fast check)
ALERT_COOLDOWN_MINUTES = 10           # don't re-email for the same clone more than once per this window
AUTO_DISCONNECT = True                # set False if you only want alerts, no automatic disconnect

# Email (sender) settings - using Gmail as an example
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "your_sender@gmail.com"
SENDER_APP_PASSWORD = "your-16-char-app-password"    # NOT your normal password - see README
RECEIVER_EMAIL = "your_receiver@gmail.com"           # where you want alerts sent

# =====================================================

logging.basicConfig(
    filename="wifi_guard.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

_last_alert_time = {}  # bssid -> datetime, used for cooldown
_last_scan_results = []  # most recent full scan: list of (ssid, bssid, security)


def scan_networks():
    """Returns a list of (ssid, bssid, security_type) tuples currently visible."""
    system = platform.system()
    if system == "Windows":
        return _scan_windows()
    elif system == "Linux":
        return _scan_linux()
    else:
        raise RuntimeError(f"Unsupported OS: {system}. This script supports Windows and Linux.")


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", _GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_uint)]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1)]


def _trigger_fresh_wifi_scan():
    """
    Forces Windows to do a REAL over-the-air WiFi scan right now, instead
    of relying on whatever it has cached. Without this, Windows can go a
    long time reusing old scan results while already connected to a
    strong, stable network - which can hide a newly-appeared clone AP.
    """
    try:
        wlanapi = ctypes.windll.wlanapi
        handle = wintypes.HANDLE()
        negotiated_version = wintypes.DWORD()
        if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(handle)) != 0:
            return False

        iface_list_ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(iface_list_ptr)) != 0:
            wlanapi.WlanCloseHandle(handle, None)
            return False

        iface_list = iface_list_ptr.contents
        if iface_list.dwNumberOfItems > 0:
            guid = iface_list.InterfaceInfo[0].InterfaceGuid
            wlanapi.WlanScan(handle, ctypes.byref(guid), None, None, None)

        wlanapi.WlanCloseHandle(handle, None)
        return True
    except Exception as e:
        logging.error(f"Could not trigger a fresh WiFi scan: {e}")
        return False


def _scan_windows():
    """
    Triggers a fresh over-the-air scan, waits for it to complete, then
    parses `netsh wlan show networks mode=bssid` output on Windows.
    Returns a list of (ssid, bssid, authentication) tuples.
    """
    if _trigger_fresh_wifi_scan():
        time.sleep(3)  # give Windows a few seconds to finish the real scan

    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as e:
        logging.error(f"Windows scan failed: {e}")
        return []

    networks = []
    current_ssid = None
    current_auth = None
    for line in output.splitlines():
        line = line.strip()
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
        auth_match = re.match(r"Authentication\s*:\s*(.*)", line)
        bssid_match = re.match(r"BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
            current_auth = None
        elif auth_match:
            current_auth = auth_match.group(1).strip()
        elif bssid_match and current_ssid is not None:
            networks.append((current_ssid, bssid_match.group(1).upper(), current_auth or "Unknown"))
    return networks


def _scan_linux():
    """
    Parses `nmcli -f ssid,bssid,security dev wifi list` output on Linux
    (requires NetworkManager). Returns a list of (ssid, bssid, security) tuples.
    """
    try:
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as e:
        logging.error(f"Linux scan failed: {e}")
        return []

    networks = []
    for line in output.splitlines():
        # nmcli -t uses ':' as separator, but BSSID itself contains ':' escaped as '\:'
        line = line.replace("\\:", "~")
        parts = line.split(":")
        if len(parts) >= 3:
            ssid = parts[0].replace("~", ":")
            bssid = parts[1].replace("~", ":").upper()
            security = parts[2] if parts[2] else "Open"
            if ssid:
                networks.append((ssid, bssid, security))
    return networks


def send_email_alert(ssid, fake_bssid, disconnected=False):
    """Sends an email warning that a clone AP was detected."""
    known_for_this_ssid = WATCHED_NETWORKS.get(ssid, [])
    subject = f"⚠ WiFi Guard Alert: Possible fake '{ssid}' network detected"
    action_line = (
        "I automatically disconnected your computer from this network.\n\n"
        if disconnected
        else "This network was seen nearby but your computer was not connected to it.\n\n"
    )
    body = (
        f"WiFi Guard detected a network broadcasting the name "
        f"('{ssid}') from an UNKNOWN router.\n\n"
        f"Suspicious BSSID: {fake_bssid}\n"
        f"Your known router(s) for this network: {', '.join(known_for_this_ssid)}\n"
        f"Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{action_line}"
        f"This could mean someone nearby is running an 'evil twin' attack, "
        f"trying to trick your devices into connecting to a fake copy of "
        f"your network. Avoid reconnecting to it. Consider changing "
        f"your WiFi password and checking your router's admin page.\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        logging.info(f"Alert email sent for '{ssid}' BSSID {fake_bssid} (disconnected={disconnected})")
        print(f"[ALERT SENT] Possible clone of '{ssid}' at {fake_bssid}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        print(f"[ERROR] Could not send alert email: {e}")


def send_duplicate_ssid_alert(ssid, entries):
    """
    Sends an email when the SAME network name is seen from multiple
    routers with DIFFERENT security types - useful anywhere, even
    networks you've never registered (like a cafe's WiFi).
    """
    subject = f"⚠ WiFi Guard Alert: '{ssid}' appears twice with different security"
    lines = "\n".join(f"  - BSSID {b}  |  Security: {s}" for b, s in entries)
    body = (
        f"WiFi Guard noticed the network name '{ssid}' being broadcast by "
        f"MORE THAN ONE router nearby, and they do NOT all use the same "
        f"security type:\n\n"
        f"{lines}\n\n"
        f"Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"This is a common sign of an 'evil twin' attack - someone nearby "
        f"copying a real network's name, often with weaker or no password, "
        f"to trick people into connecting. This can happen at cafes, "
        f"airports, hotels, or anywhere with public WiFi.\n\n"
        f"If you are at this location right now: do NOT connect to the "
        f"one with weaker/no security. Ask staff which network and "
        f"password are the real ones before connecting.\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        logging.info(f"Duplicate-SSID alert sent for '{ssid}'")
        print(f"[ALERT SENT] '{ssid}' seen with mismatched security: {entries}")
    except Exception as e:
        logging.error(f"Failed to send duplicate-SSID email: {e}")
        print(f"[ERROR] Could not send duplicate-SSID alert: {e}")


def send_open_twin_alert(ssid, open_bssid, secured_twin, disconnected=False):
    """
    Sends an email when you were connected to the OPEN/unsecured copy
    of a network that also has a secured version nearby.
    """
    secured_bssid, secured_security = secured_twin
    subject = f"⚠ WiFi Guard Alert: Connected to risky OPEN version of '{ssid}'"
    action_line = (
        "I automatically disconnected your computer from it.\n\n"
        if disconnected
        else "Auto-disconnect is currently off, so you are still connected.\n\n"
    )
    body = (
        f"Your computer was connected to '{ssid}' with NO PASSWORD (open network), "
        f"at BSSID {open_bssid}.\n\n"
        f"A SECURED version of the same network name was also seen nearby:\n"
        f"  BSSID {secured_bssid}  |  Security: {secured_security}\n\n"
        f"Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{action_line}"
        f"Connecting to an open copy of a network that should be secured is a "
        f"classic evil-twin trick, since anyone nearby can read unencrypted "
        f"traffic on an open network. If you are at a cafe, airport, or similar "
        f"place, ask staff which network and password are the correct ones.\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        logging.info(f"Open-twin alert sent for '{ssid}' ({open_bssid})")
        print(f"[ALERT SENT] Connected to open twin of '{ssid}' at {open_bssid}")
    except Exception as e:
        logging.error(f"Failed to send open-twin email: {e}")
        print(f"[ERROR] Could not send open-twin alert: {e}")


def get_current_connection():
    """
    Returns (ssid, bssid, security) of the network this computer is
    CURRENTLY connected to, or (None, None, None) if not connected or
    unsupported OS. Windows only for now.
    """
    if platform.system() != "Windows":
        return None, None, None

    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as e:
        logging.error(f"Could not read current connection: {e}")
        return None, None, None

    ssid = None
    bssid = None
    security = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID") and not line.startswith("SSID 1") and "BSSID" not in line:
            ssid = line.split(":", 1)[1].strip()
        elif line.startswith("AP BSSID"):
            bssid = line.split(":", 1)[1].strip()
        elif line.startswith("Authentication"):
            security = line.split(":", 1)[1].strip()
    return ssid, bssid, security


def _is_open_security(security):
    """True if a security label means 'no password' / open network."""
    if not security:
        return False
    s = security.lower()
    return "open" in s


def disconnect_wifi():
    """Forces Windows to disconnect from the current WiFi network."""
    try:
        subprocess.run(["netsh", "wlan", "disconnect"], check=True)
        logging.info("Disconnected from WiFi due to suspected evil twin.")
        print("[ACTION] Disconnected from the suspicious network.")
        return True
    except Exception as e:
        logging.error(f"Failed to disconnect: {e}")
        print(f"[ERROR] Could not auto-disconnect: {e}")
        return False


def _is_known_bssid(ssid, bssid):
    """True if this BSSID is one of the known-good addresses for this SSID."""
    known_list = [b.strip().upper() for b in WATCHED_NETWORKS.get(ssid, [])]
    return bssid.upper() in known_list


def check_current_connection():
    """
    Checks what network you're actively connected to right now.
    - If it matches one of our WATCHED_NETWORKS but an unknown BSSID,
      disconnect + alert (strict check, needs pre-registered network).
    - If it's an OPEN/unsecured network, and we've also seen the SAME
      name broadcast by another BSSID with real security (WPA2/WPA3),
      disconnect + alert too - this works for ANY network, registered
      or not, like a cafe you've never saved before.
    """
    ssid, bssid, security = get_current_connection()
    if ssid is None or bssid is None:
        return  # not connected, or unsupported OS

    bssid = bssid.upper()

    # --- Check A: registered network, unknown BSSID (strict) ---
    if ssid in WATCHED_NETWORKS and not _is_known_bssid(ssid, bssid):
        logging.warning(f"CONNECTED to suspected evil twin: SSID='{ssid}' BSSID={bssid}")
        disconnected = False
        if AUTO_DISCONNECT:
            disconnected = disconnect_wifi()

        now = datetime.now()
        alert_key = (ssid, bssid)
        last = _last_alert_time.get(alert_key)
        if last is None or now - last > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
            send_email_alert(ssid, bssid, disconnected=disconnected)
            _last_alert_time[alert_key] = now
        return  # don't also run check B for the same connection

    # --- Check B: connected to the OPEN twin of a duplicated name (any network) ---
    if _is_open_security(security):
        # Look at the last full scan for a secured version of this same SSID
        secured_twin = None
        for scan_ssid, scan_bssid, scan_security in _last_scan_results:
            if scan_ssid == ssid and scan_bssid != bssid and not _is_open_security(scan_security):
                secured_twin = (scan_bssid, scan_security)
                break

        if secured_twin:
            logging.warning(
                f"CONNECTED to OPEN network '{ssid}' ({bssid}) while a SECURED "
                f"version also exists at {secured_twin[0]} ({secured_twin[1]}) - disconnecting."
            )
            disconnected = False
            if AUTO_DISCONNECT:
                disconnected = disconnect_wifi()

            now = datetime.now()
            alert_key = ("OPEN_TWIN", ssid, bssid)
            last = _last_alert_time.get(alert_key)
            if last is None or now - last > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
                send_open_twin_alert(ssid, bssid, secured_twin, disconnected=disconnected)
                _last_alert_time[alert_key] = now


def check_networks(networks):
    """
    Looks for two things in every scan:
    1. Any of our watched SSIDs (home WiFi, etc.) broadcast from an unknown BSSID.
    2. ANY network name (not just watched ones) showing up from more than one
       BSSID with DIFFERENT security types - a strong sign of an evil twin
       even for networks we've never seen before, like at a cafe.
    """
    now = datetime.now()

    # --- Check 1: watched networks (home WiFi, etc.) ---
    for ssid, bssid, _security in networks:
        if ssid in WATCHED_NETWORKS and not _is_known_bssid(ssid, bssid):
            alert_key = (ssid, bssid)
            last = _last_alert_time.get(alert_key)
            if last is None or now - last > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
                logging.warning(f"Possible evil twin detected: SSID='{ssid}' BSSID={bssid}")
                send_email_alert(ssid, bssid)
                _last_alert_time[alert_key] = now
            else:
                logging.info(f"Already alerted recently for {ssid}/{bssid}, skipping (cooldown).")

    # --- Check 2: ANY duplicate SSID with mismatched security (e.g. cafe WiFi) ---
    by_ssid = {}
    for ssid, bssid, security in networks:
        by_ssid.setdefault(ssid, []).append((bssid, security))

    for ssid, entries in by_ssid.items():
        if len(entries) < 2:
            continue  # only one AP with this name, nothing to compare
        security_types = set(sec for _bssid, sec in entries)
        if len(security_types) > 1:
            # Same name, different security - suspicious, regardless of watchlist
            alert_key = ("DUPLICATE", ssid, tuple(sorted(security_types)))
            last = _last_alert_time.get(alert_key)
            if last is None or now - last > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
                logging.warning(f"Duplicate SSID with mismatched security: '{ssid}' -> {entries}")
                send_duplicate_ssid_alert(ssid, entries)
                _last_alert_time[alert_key] = now


def main():
    print("WiFi Guard started.")
    print(f"Watching {len(WATCHED_NETWORKS)} network(s):")
    for ssid, bssids in WATCHED_NETWORKS.items():
        print(f"  - '{ssid}'  known router(s): {bssids}")
    print(f"Full WiFi scan every {SCAN_INTERVAL_SECONDS}s, connection check every {CONNECTION_CHECK_SECONDS}s.")
    print(f"Auto-disconnect on evil twin: {'ON' if AUTO_DISCONNECT else 'OFF'}")
    print("Press Ctrl+C to stop.\n")

    if "AA:BB:CC:DD:EE:FF" in [b for bssids in WATCHED_NETWORKS.values() for b in bssids]:
        print("!! WARNING: You haven't edited the CONFIG section yet.")
        print("!! Open this file and fill in WATCHED_NETWORKS and email settings.\n")

    seconds_since_full_scan = SCAN_INTERVAL_SECONDS  # trigger a full scan right away

    try:
        while True:
            # Fast check: what are we CONNECTED to right now?
            check_current_connection()

            # Slower check: what networks are visible NEARBY (even if not connected)?
            if seconds_since_full_scan >= SCAN_INTERVAL_SECONDS:
                networks = scan_networks()
                logging.info(f"Scan found {len(networks)} networks.")
                global _last_scan_results
                _last_scan_results = networks  # cache for the open-twin connection check
                # DEBUG: show exactly what this scan saw for watched SSIDs
                for ssid in WATCHED_NETWORKS:
                    matches = [(b, s) for n, b, s in networks if n == ssid]
                    print(f"[SCAN] '{ssid}' -> {matches if matches else 'NOT SEEN this scan'}")
                check_networks(networks)
                seconds_since_full_scan = 0

            time.sleep(CONNECTION_CHECK_SECONDS)
            seconds_since_full_scan += CONNECTION_CHECK_SECONDS
    except KeyboardInterrupt:
        print("\nWiFi Guard stopped.")


if __name__ == "__main__":
    main()
