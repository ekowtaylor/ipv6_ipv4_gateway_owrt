#!/bin/sh
#
# Direct gateway devices list (no REST API needed)
# Works from console/KVM without network
#

DEVICES_FILE="/etc/ipv4-ipv6-gateway/devices.json"

if [ ! -f "$DEVICES_FILE" ]; then
    echo "No devices file found at $DEVICES_FILE"
    echo ""
    echo "Possible reasons:"
    echo "  - Gateway service not started yet"
    echo "  - No devices have been discovered"
    echo "  - Service hasn't written device store yet"
    exit 1
fi

# Check if we have Python for pretty printing
if command -v python3 >/dev/null 2>&1; then
    # Pretty print with Python
    cat "$DEVICES_FILE" | python3 -m json.tool
else
    # Fallback to raw JSON
    cat "$DEVICES_FILE"
fi
