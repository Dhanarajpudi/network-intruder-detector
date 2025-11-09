#!/bin/bash

LOG_FILE="$HOME/network-intruder-detector/intruder_log.txt"
KNOWN_DEVICES="$HOME/network-intruder-detector/known_devices.txt"

# Create known devices file if missing
if [ ! -f "$KNOWN_DEVICES" ]; then
    arp -a | awk '{print $2}' | tr -d '()' > "$KNOWN_DEVICES"
fi

check_intruders() {
    current_devices=$(arp -a | awk '{print $2}' | tr -d '()')

    for device in $current_devices; do
        if ! grep -w "$device" "$KNOWN_DEVICES" > /dev/null; then
            echo "🚨 Intruder Detected: $device on $(date)" | tee -a "$LOG_FILE"
        fi
    done
}

while true; do
    check_intruders
    sleep 10
done
