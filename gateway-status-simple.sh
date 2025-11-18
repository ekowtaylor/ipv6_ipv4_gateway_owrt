#!/bin/sh
# Simple Gateway Status - Direct JSON read (no API)
# For single-device mode

set -e

STATE_FILE="/etc/ipv4-ipv6-gateway/current_device.json"
LOG_FILE="/var/log/ipv4-ipv6-gateway.log"

echo "========================================="
echo " Simple Gateway Status"
echo "========================================="
echo ""

# Check if service is running
if pgrep -f "ipv4_ipv6_gateway_simple.py" > /dev/null; then
    echo "✓ Service Status: RUNNING"
    PID=$(pgrep -f "ipv4_ipv6_gateway_simple.py")
    echo "  PID: $PID"
else
    echo "✗ Service Status: NOT RUNNING"
fi

echo ""

# Check device state
if [ -f "$STATE_FILE" ]; then
    echo "Device Configuration:"
    echo "-------------------"
    
    # Parse JSON and display
    MAC=$(grep -o '"mac_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAN_IP=$(grep -o '"ipv4_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    WAN_IPV4=$(grep -o '"ipv4_wan_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    WAN_IPV6=$(grep -o '"ipv6_address": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4 | head -1)
    STATUS=$(grep -o '"status": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    DISCOVERED=$(grep -o '"discovered_at": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    LAST_SEEN=$(grep -o '"last_seen": "[^"]*"' "$STATE_FILE" | cut -d'"' -f4)
    
    echo "  MAC Address:    $MAC"
    echo "  Status:         $STATUS"
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
    
    echo "  Discovered:     $DISCOVERED"
    echo "  Last Seen:      $LAST_SEEN"
else
    echo "No device configured yet"
fi

echo ""
echo "Network Interfaces:"
echo "-------------------"

# eth0 (WAN)
echo "eth0 (WAN):"
ETH0_MAC=$(ip link show eth0 | grep -o 'link/ether [^ ]*' | awk '{print $2}')
echo "  MAC: $ETH0_MAC"

ETH0_IPV4=$(ip -4 addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
if [ -n "$ETH0_IPV4" ]; then
    echo "  IPv4: $ETH0_IPV4"
else
    echo "  IPv4: (none)"
fi

ETH0_IPV6=$(ip -6 addr show eth0 | grep 'scope global' | awk '{print $2}' | cut -d'/' -f1 | head -1)
if [ -n "$ETH0_IPV6" ]; then
    echo "  IPv6: $ETH0_IPV6"
else
    echo "  IPv6: (none)"
fi

echo ""

# eth1 (LAN)
echo "eth1 (LAN):"
ETH1_MAC=$(ip link show eth1 | grep -o 'link/ether [^ ]*' | awk '{print $2}')
ETH1_IPV4=$(ip -4 addr show eth1 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
echo "  MAC: $ETH1_MAC"
echo "  IPv4: $ETH1_IPV4"

echo ""
echo "Recent Log Entries:"
echo "-------------------"
if [ -f "$LOG_FILE" ]; then
    tail -10 "$LOG_FILE"
else
    echo "(No log file found)"
fi

echo ""
echo "========================================="
