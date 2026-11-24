# WiFi Guard — Evil Twin Detector

A small script that watches for someone cloning your home WiFi name and
emails you the moment it happens. Runs on **Windows or Linux**, no special
hardware needed.

## What it does
- Scans nearby WiFi networks every 30 seconds (adjustable)
- Checks what network your computer is **currently connected to** every
  5 seconds (fast check)
- Compares both against your registered networks (SSID + known BSSIDs)
- If a registered WiFi name shows up from a **different, unknown** router:
  - Sends you an email alert
  - **If you're actually connected to the fake one, it automatically
    disconnects you from it** (Windows only, can be turned off)
- **Also works at places you've never registered, like a cafe**: if it
  ever sees the SAME WiFi name broadcast by two different routers with
  DIFFERENT security types (e.g. one password-protected, one open), it
  emails you a warning - this needs no prior setup, since mismatched
  security on a duplicated name is suspicious anywhere
- Logs everything to `wifi_guard.log` so you have a history

## Why the cafe case is handled differently
For your home WiFi, the script knows the one true router's address in
advance, so it can say for certain "this other one is fake." At a cafe,
you've never saved their router's real address, so there's no "known
good" to compare against - no tool can know which of two identically
named networks is the real one just from the name alone. Instead, the
script watches for the next best signal: the same name appearing twice
with different security settings, which is how most real evil-twin
setups behave in public places. If you get this alert while at a cafe,
the safest move is to ask staff directly which network name and
password are correct before connecting.

## What it does NOT do
- It does not detect raw deauthentication packet floods — that needs a
  WiFi adapter in "monitor mode," which most built-in laptop WiFi cards
  (especially on Windows) don't support. This tool focuses on catching
  the **clone network itself**, which is the part that matters most for
  protecting you day to day.
- Auto-disconnect only works on Windows currently (uses `netsh`). On
  Linux it will still alert you, just won't auto-disconnect yet.
- It can't stop your computer from briefly auto-connecting to the fake
  network in the first place — Windows decides that instantly. What it
  does is catch it fast (within ~5 seconds) and kick you off right after.

## Turning auto-disconnect off
If you only want alerts without the automatic disconnect, open
`wifi_guard.py` and change:
```python
AUTO_DISCONNECT = False
```

## Protecting multiple networks
You can protect more than one network at once — your home WiFi, your
phone's hotspot, an office network, etc. Just add more entries to
`WATCHED_NETWORKS` in the config:
```python
WATCHED_NETWORKS = {
    "YourHomeWiFiName": [
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
    ],
    "YourPhoneHotspotName": [
        "AA:BB:CC:DD:EE:03",
    ],
    "AnotherNetworkName": [
        "11:22:33:44:55:66",
    ],
}
```
Each network name gets its own list of known-good MAC addresses. The
script checks ALL of them, every scan.

## Setup (5 minutes)

### Step 1 — Find a network's real BSSID (MAC address)
**Windows** (open Command Prompt):
```
netsh wlan show networks mode=bssid
```
**Linux**:
```
nmcli -f ssid,bssid dev wifi list
```
Find the network's name in the list and copy the BSSID next to it.
If a router has a mesh WiFi system or both 2.4GHz and 5GHz bands,
copy **all** of the BSSIDs for that one network name — you'll need
them all so it doesn't mistake your own second radio for an attacker.

**To find a phone's hotspot BSSID**: turn the hotspot on, then run the
same scan command from another device while standing near the phone.

### Step 2 — Get a Gmail "app password" (don't use your real password)
1. Go to your Google Account → Security → 2-Step Verification (turn it on if it's off)
2. Go to Security → App Passwords
3. Generate one for "Mail" — you'll get a 16-character code
4. Use that code in the script, not your normal Gmail password

(If you use a different email provider, look up its SMTP server and port —
most work the same way.)

### Step 3 — Edit the config
Open `wifi_guard.py` and fill in the `CONFIG` section near the top:
- `WATCHED_NETWORKS` — each network name you want protected, with its
  MAC address(es) from Step 1
- `SENDER_EMAIL` / `SENDER_APP_PASSWORD` — your Gmail + app password
- `RECEIVER_EMAIL` — where you want the alert sent (can be the same address)

### Step 4 — Install the one dependency (Linux only)
Linux needs NetworkManager's `nmcli` tool, which is installed by default
on most desktop Linux distros. Nothing extra to install on Windows —
it uses the built-in `netsh` command.

### Step 5 — Run it
```
python wifi_guard.py
```
Leave the terminal window open. You'll see it print each scan, and your
inbox will get an email the moment it spots a clone of your network.

## Running it in the background (optional)
- **Windows**: Use Task Scheduler to run `wifi_guard.py` at login.
- **Linux**: Add a `systemd` service, or run it inside `screen`/`tmux`
  so it keeps going after you close the terminal.

Ask me if you'd like help setting either of those up.
