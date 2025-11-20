#!/bin/sh
# Simplified Gateway Device Info - Single Device Mode (Direct file read - no API)
# Displays current device configuration from JSON
# Perfect for console/KVM access or when network is unavailable

set -e

STATE_FILE="/etc/ipv4-ipv6-gateway/current_device.json"

echo "=========================================="
echo "DEVICE CONFIGURATION (Single Device Mode)"
echo "=========================================="
echo ""

if [ -f "$STATE_FILE" ]; then
    # Parse JSON and display
    MAC=$(grep -o '"mac_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAN_IP=$(grep -o '"ipv4_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    WAN_IPV4=$(grep -o '"ipv4_wan_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    WAN_IPV6=$(grep -o '"ipv6_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    STATUS=$(grep -o '"status": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    DISCOVERED=$(grep -o '"discovered_at": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAST_SEEN=$(grep -o '"last_seen": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)

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
    echo "  Last Seen:      $LAST_SEEN"

else
    echo "No device configured yet"
    echo ""
    echo "Waiting for device to connect to eth1..."
fi

echo ""
echo "=========================================="
