#!/bin/sh
#
# Direct gateway device info (no REST API needed)
# Works from console/KVM without network
# Single-device mode: shows the ONE configured device
#

DEVICE_FILE="/etc/ipv4-ipv6-gateway/device.json"

if [ ! -f "$DEVICE_FILE" ]; then
    echo "No device configured"
    echo ""
    echo "Possible reasons:"
    echo "  - Gateway service not started yet"
    echo "  - No device connected to LAN"
    echo "  - Device not yet discovered"
    exit 1
fi

echo "================================"
echo "CONFIGURED DEVICE"
echo "================================"
echo ""

# Check if we have Python for pretty printing
if command -v python3 >/dev/null 2>&1; then
    # Pretty print with Python
    cat "$DEVICE_FILE" | python3 -m json.tool
else
    # Fallback to raw JSON
    cat "$DEVICE_FILE"
fi
