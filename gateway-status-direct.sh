#!/bin/sh
# Simplified Gateway Status - Single Device Mode (Direct file read - no API)
# Reads current device state from JSON without API server
# Perfect for console/KVM access or when network is unavailable

set -e

STATE_FILE="/etc/ipv4-ipv6-gateway/current_device.json"
LOG_FILE="/var/log/ipv4-ipv6-gateway.log"

echo "=========================================="
echo "GATEWAY STATUS (Single Device Mode)"
echo "=========================================="
echo

# Check if service is running
if ps | grep -v grep | grep "ipv4_ipv6_gateway.py" > /dev/null; then
    echo "Service: RUNNING"
else
    echo "Service: STOPPED"
fi

echo

# Check if device is configured
if [ -f "$STATE_FILE" ]; then
    echo "Device Configuration:"
    echo "--------------------"

    # Parse JSON manually (simple extraction)
    MAC=$(cat "$STATE_FILE" | grep '"mac_address"' | cut -d'"' -f4)
    LAN_IP=$(cat "$STATE_FILE" | grep '"lan_ipv4"' | cut -d'"' -f4)
    WAN_IPV4=$(cat "$STATE_FILE" | grep '"wan_ipv4"' | cut -d'"' -f4)
    WAN_IPV6=$(cat "$STATE_FILE" | grep '"wan_ipv6"' | cut -d'"' -f4)
    STATUS=$(cat "$STATE_FILE" | grep '"status"' | cut -d'"' -f4)
    UPDATED=$(cat "$STATE_FILE" | grep '"last_updated"' | cut -d'"' -f4)

    echo "MAC:         $MAC"
    echo "LAN IPv4:    ${LAN_IP:-N/A}"
    echo "WAN IPv4:    ${WAN_IPV4:-N/A}"
    echo "WAN IPv6:    ${WAN_IPV6:-N/A}"
    echo "Status:      $STATUS"
    echo "Last Update: $UPDATED"
    echo

    # Show access info
    if [ -n "$WAN_IPV4" ] && [ "$WAN_IPV4" != "null" ]; then
        echo "IPv4 Access (from WAN):"
        echo "  HTTP:   http://${WAN_IPV4}:8080"
        echo "  Telnet: telnet ${WAN_IPV4} 2323"
        echo "  SSH:    ssh -p 2222 user@${WAN_IPV4}"
        echo
    fi

    if [ -n "$WAN_IPV6" ] && [ "$WAN_IPV6" != "null" ]; then
        echo "IPv6 Access (from WAN):"
        echo "  HTTP:   http://[${WAN_IPV6}]:80"
        echo "  Telnet: telnet ${WAN_IPV6} 23"
        echo
    fi

else
    echo "No device configured yet"
    echo
fi

# Show recent log entries
if [ -f "$LOG_FILE" ]; then
    echo "Recent Log Entries (last 10 lines):"
    echo "------------------------------------"
    tail -10 "$LOG_FILE"
fi

echo
echo "=========================================="
