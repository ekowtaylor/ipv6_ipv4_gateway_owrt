#!/bin/sh
# gateway-devices-direct.sh — Show device info (single device mode)
# Works even when API is down - reads state file directly

set -e

# State file (single device mode)
STATE_FILE="/etc/ipv4-ipv6-gateway/device.json"

echo "=========================================="
echo "DEVICE CONFIGURATION (Single Device Mode)"
echo "=========================================="
echo ""

if [ -f "$STATE_FILE" ]; then
    # Parse JSON and display (field names match Python Device dataclass)
    MAC=$(grep -o '"mac_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAN_IP=$(grep -o '"lan_ipv4": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    WAN_IPV4=$(grep -o '"wan_ipv4": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    WAN_IPV6=$(grep -o '"wan_ipv6": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    STATUS=$(grep -o '"status": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    DISCOVERED=$(grep -o '"discovered_at": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAST_UPDATED=$(grep -o '"last_updated": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)

    echo "Device Information:"
    echo "-------------------"
    echo "  MAC Address:    $MAC"
    echo "  Status:         $STATUS"
    echo ""

    echo "Network Addresses:"
    echo "-------------------"
    echo "  LAN IPv4:       $LAN_IP"

    if [ -n "$WAN_IPV4" ] && [ "$WAN_IPV4" != "null" ]; then
        echo "  WAN IPv4:       $WAN_IPV4"
    else
        echo "  WAN IPv4:       (none)"
    fi

    if [ -n "$WAN_IPV6" ] && [ "$WAN_IPV6" != "null" ]; then
        echo "  WAN IPv6:       $WAN_IPV6"
    else
        echo "  WAN IPv6:       (none)"
    fi

    echo ""
    echo "Timeline:"
    echo "-------------------"
    echo "  Discovered:     $DISCOVERED"
    echo "  Last Updated:   $LAST_UPDATED"

else
    echo "No device configured yet"
    echo ""
    echo "Waiting for device to connect to eth1..."
fi

echo ""
echo "=========================================="
