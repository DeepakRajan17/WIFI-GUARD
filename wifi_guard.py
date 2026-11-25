#!/usr/bin/env python3
"""
WiFi Guard - Evil Twin / Rogue AP Detector
--------------------------------------------
Watches nearby WiFi networks and alerts you by email if it ever sees
your home network's name (SSID) being broadcast from a DIFFERENT
router (a different BSSID / MAC address). That's the classic sign of
an "evil twin" attack, where someone clones your WiFi name to trick
your devices into connecting to them instead.

Works on Windows and Linux. No special hardware needed - uses your
normal WiFi adapter in its normal mode.

HOW TO SET IT UP
-----------------
1. Fill in the CONFIG section below with your real router's SSID,
   its BSSID (MAC address), and your email settings.
2. Run: python wifi_guard.py
3. Leave it running in a terminal. It checks every SCAN_INTERVAL
   seconds and emails you if it spots a clone.

HOW TO FIND YOUR ROUTER'S BSSID (its MAC address)
---------------------------------------------------
Windows:  netsh wlan show networks mode=bssid
Linux:    nmcli -f ssid,bssid dev wifi list

Look for your network's SSID in the list - the BSSID next to it
is what you put in KNOWN_BSSIDS below. If your router has multiple
bands (2.4GHz and 5GHz) or multiple access points (mesh system),
add ALL of their BSSIDs to the list, otherwise it will think your
own second AP is an attacker.
"""

import subprocess
import platform
import re
import time
import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta

# ============== CONFIG - FILL THIS IN ==============

HOME_SSID = "YourWiFiName"            # Your real WiFi network name
KNOWN_BSSIDS = [
    "AA:BB:CC:DD:EE:FF",               # Your real router's MAC address(es)
    # "11:22:33:44:55:66",             # add more lines if you have a mesh/dual-band setup
]

SCAN_INTERVAL_SECONDS = 30            # how often to scan
ALERT_COOLDOWN_MINUTES = 10           # don't re-email for the same clone more than once per this window

# Email (sender) settings - using Gmail as an example
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "youraccount@gmail.com"
SENDER_APP_PASSWORD = "your-16-char-app-password"   # NOT your normal password - see note below
RECEIVER_EMAIL = "youraccount@gmail.com"             # where you want alerts sent

# =====================================================

logging.basicConfig(
    filename="wifi_guard.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

_last_alert_time = {}  # bssid -> datetime, used for cooldown


def scan_networks():
    """Returns a list of (ssid, bssid) tuples currently visible."""
    system = platform.system()
    if system == "Windows":
        return _scan_windows()
    elif system == "Linux":
        return _scan_linux()
    else:
        raise RuntimeError(f"Unsupported OS: {system}. This script supports Windows and Linux.")


def _scan_windows():
    """Parses `netsh wlan show networks mode=bssid` output on Windows."""
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
    for line in output.splitlines():
        line = line.strip()
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
        bssid_match = re.match(r"BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
        elif bssid_match and current_ssid is not None:
            networks.append((current_ssid, bssid_match.group(1).upper()))
    return networks


def _scan_linux():
    """Parses `nmcli -f ssid,bssid dev wifi list` output on Linux (requires NetworkManager)."""
    try:
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
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
        if len(parts) >= 2:
            ssid = parts[0].replace("~", ":")
            bssid = parts[1].replace("~", ":").upper()
            if ssid:
                networks.append((ssid, bssid))
    return networks


def send_email_alert(fake_bssid):
    """Sends an email warning that a clone AP was detected."""
    subject = f"⚠ WiFi Guard Alert: Possible fake '{HOME_SSID}' network detected"
    body = (
        f"WiFi Guard detected a network broadcasting your WiFi name "
        f"('{HOME_SSID}') from an UNKNOWN router.\n\n"
        f"Suspicious BSSID: {fake_bssid}\n"
        f"Your known router(s): {', '.join(KNOWN_BSSIDS)}\n"
        f"Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"This could mean someone nearby is running an 'evil twin' attack, "
        f"trying to trick your devices into connecting to a fake copy of "
        f"your network. Do not connect to this network. Consider changing "
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
        logging.info(f"Alert email sent for BSSID {fake_bssid}")
        print(f"[ALERT SENT] Possible clone of '{HOME_SSID}' at {fake_bssid}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        print(f"[ERROR] Could not send alert email: {e}")


def check_networks(networks):
    """Looks for our SSID being broadcast from an unknown BSSID."""
    now = datetime.now()
    for ssid, bssid in networks:
        if ssid == HOME_SSID and bssid not in KNOWN_BSSIDS:
            last = _last_alert_time.get(bssid)
            if last is None or now - last > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
                logging.warning(f"Possible evil twin detected: SSID='{ssid}' BSSID={bssid}")
                send_email_alert(bssid)
                _last_alert_time[bssid] = now
            else:
                logging.info(f"Already alerted recently for {bssid}, skipping (cooldown).")


def main():
    print("WiFi Guard started.")
    print(f"Watching for clones of: '{HOME_SSID}'")
    print(f"Known good router(s): {KNOWN_BSSIDS}")
    print(f"Scanning every {SCAN_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.\n")

    if "YourWiFiName" == HOME_SSID or "AA:BB:CC:DD:EE:FF" in KNOWN_BSSIDS:
        print("!! WARNING: You haven't edited the CONFIG section yet.")
        print("!! Open this file and fill in HOME_SSID, KNOWN_BSSIDS, and email settings.\n")

    try:
        while True:
            networks = scan_networks()
            logging.info(f"Scan found {len(networks)} networks.")
            check_networks(networks)
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nWiFi Guard stopped.")


if __name__ == "__main__":
    main()
