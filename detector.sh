#!/usr/bin/env bash
# Network Intruder Detector
# Auto-detects local network CIDR and scans for new devices.
# Run with: sudo ./detector.sh

set -u
LOG_FILE="./intruders.log"
KNOWN_FILE="./known_devices.txt"
SLEEP_INTERVAL=30   # seconds between scans

# Ensure files exist
touch "$LOG_FILE"
touch "$KNOWN_FILE"

echo "[*] Starting Network Intruder Detector"
echo "[*] Log: $LOG_FILE"
echo "[*] Known devices file: $KNOWN_FILE"
echo ""

# Function to auto-detect local CIDR (works on typical systems)
detect_cidr() {
  # get outgoing interface used for internet
  dev=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
  if [ -z "$dev" ]; then
    # fallback
    dev=$(ip route | awk '/default/ {print $5; exit}')
  fi
  # get the ipv4 address with prefix (like 192.168.1.10/24)
  cidr=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1)
  if [ -z "$cidr" ]; then
    echo "ERROR: Could not detect network interface or CIDR. Please ensure you are connected to a network."
    exit 1
  fi
  echo "$cidr"
}

while true; do
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  CIDR=$(detect_cidr)
  echo "[$ts] Scanning network: $CIDR"

  # run nmap ping scan and capture result
  # Nmap may require sudo; caller should run script with sudo
  SCAN_OUTPUT=$(sudo nmap -sn "$CIDR" 2>/dev/null)

  # Parse results: we expect pairs of "Nmap scan report for <IP>" and "MAC Address: <MAC> (Vendor)"
  # For hosts without MAC printed (sometimes), we still record IP.
  CURRENT_LIST=$(echo "$SCAN_OUTPUT" | awk '
    /Nmap scan report for/ { ip = $NF }
    /MAC Address:/ { mac = $3; print ip " " mac; next }
    /Nmap scan report for/ && !/MAC Address:/ { next }
  ')

  # If parsing above yields nothing (older nmap formats), fallback to trying different parse:
  if [ -z "$CURRENT_LIST" ]; then
    # fallback: try extracting using another pattern
    CURRENT_LIST=$(echo "$SCAN_OUTPUT" | awk '
      /Nmap scan report for/ { ip = $NF }
      /MAC/ { for(i=1;i<=NF;i++) if($i=="MAC") { print ip " " $(i+2) } }
    ')
  fi

  # As extra fallback, if still empty, try to use arp after ping sweep
  if [ -z "$CURRENT_LIST" ]; then
    # quick ping sweep to populate ARP table
    sudo nmap -sn "$CIDR" >/dev/null 2>&1
    CURRENT_LIST=$(arp -n | awk '/^[0-9]/{print $1 " " $3}')
  fi

  # Iterate current devices and compare to known devices
  while read -r line; do
    [ -z "$line" ] && continue
    ip=$(echo "$line" | awk '{print $1}')
    mac=$(echo "$line" | awk '{print $2}')
    # if mac is empty, use IP as identifier
    id="$mac"
    if [ -z "$id" ]; then
      id="$ip"
    fi

    # if id not found in known file -> new device
    if ! grep -Fxq "$id" "$KNOWN_FILE" 2>/dev/null; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] NEW DEVICE: IP=$ip MAC=$mac" | tee -a "$LOG_FILE"
      echo "$id" >> "$KNOWN_FILE"
      # desktop notification (works if running in graphical session)
      if command -v notify-send >/dev/null 2>&1; then
        notify-send "⚠ Intruder Alert!" "New device detected: $ip $mac" -u critical
      fi
      # optional beep (commented out)
      # if command -v paplay >/dev/null 2>&1; then paplay /usr/share/sounds/freedesktop/stereo/complete.oga; fi
    fi
  done <<< "$CURRENT_LIST"

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scan complete. Sleeping $SLEEP_INTERVAL seconds."
  sleep "$SLEEP_INTERVAL"
done
