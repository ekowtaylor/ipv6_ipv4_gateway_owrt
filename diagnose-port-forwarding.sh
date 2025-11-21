#!/bin/sh
#
# DIAGNOSE PORT FORWARDING - Why aren't forwards working?
# Check firewall and iptables configuration
#

echo "=========================================="
echo "PORT FORWARDING DIAGNOSTIC"
echo "=========================================="
echo ""

# Get device info
DEVICE_LAN_IP=""
DEVICE_WAN_IP=""
DEVICE_MAC=""

if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv4"' | cut -d'"' -f4)
    DEVICE_MAC=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"mac_address"' | cut -d'"' -f4)
fi

echo "Device Information:"
echo "------------------------------"
echo "Device MAC:     ${DEVICE_MAC:-NOT FOUND}"
echo "Device LAN IP:  ${DEVICE_LAN_IP:-NOT FOUND}"
echo "Device WAN IP:  ${DEVICE_WAN_IP:-NOT FOUND}"
echo ""

# Check if device is configured
if [ -z "$DEVICE_LAN_IP" ] || [ -z "$DEVICE_WAN_IP" ]; then
    echo "❌ ERROR: No device configured!"
    echo "   Port forwarding cannot work without a device"
    exit 1
fi

echo "1. Firewall INPUT Rules (traffic TO router):"
echo "------------------------------"
echo "These allow traffic to reach the router's WAN interface:"
uci show firewall | grep -E "(Allow-Device|Allow-Ping)" | grep "rule\[" | head -10
echo ""

echo "2. Firewall FORWARD Rules (traffic THROUGH router):"
echo "------------------------------"
echo "These allow traffic to be forwarded to the device:"
uci show firewall | grep "forwarding" || echo "  ⚠ No forwarding rules found!"
echo ""

echo "3. Firewall WAN Zone Configuration:"
echo "------------------------------"
uci show firewall | grep "@zone\[1\]" | grep -E "(name|input|forward)"
echo ""

WAN_FORWARD=$(uci get firewall.@zone[1].forward 2>/dev/null)
echo "WAN zone forward policy: ${WAN_FORWARD:-UNKNOWN}"
if [ "$WAN_FORWARD" = "REJECT" ]; then
    echo "  ⚠ WARNING: WAN forward is REJECT - this blocks forwarding!"
    echo "  Port forwards will NOT work with this setting"
fi
echo ""

echo "4. iptables NAT Rules (DNAT for port forwarding):"
echo "------------------------------"
iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "(8080|5000|2323|2222)" || echo "  ⚠ No DNAT rules found!"
echo ""

echo "5. iptables FORWARD Rules (allow forwarded traffic):"
echo "------------------------------"
iptables -L FORWARD -n -v --line-numbers | grep "$DEVICE_LAN_IP" || echo "  ⚠ No FORWARD rules for device!"
echo ""

echo "6. Test Port Listening on Device:"
echo "------------------------------"
echo "Checking if device has services listening..."

# Test common ports
for port in 80 5000 23 22; do
    if nc -z -w 2 "$DEVICE_LAN_IP" "$port" 2>/dev/null; then
        echo "  ✓ Port $port is OPEN on device"
    else
        echo "  ✗ Port $port is CLOSED on device"
    fi
done
echo ""

echo "=========================================="
echo "DIAGNOSIS SUMMARY"
echo "=========================================="
echo ""

# Determine the issue
HAS_DNAT=$(iptables -t nat -L PREROUTING -n | grep -c "8080\|5000\|2323")
HAS_FORWARD=$(iptables -L FORWARD -n | grep -c "$DEVICE_LAN_IP")
WAN_FORWARD=$(uci get firewall.@zone[1].forward 2>/dev/null)

echo "Issue Analysis:"
echo "------------------------------"

if [ "$HAS_DNAT" -eq 0 ]; then
    echo "❌ NO DNAT rules found!"
    echo "   Gateway service may not be running or device not configured"
    echo "   Fix: /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
fi

if [ "$HAS_FORWARD" -eq 0 ]; then
    echo "❌ NO FORWARD rules found for device!"
    echo "   iptables is not allowing forwarded traffic to device"
    echo "   This is created by the gateway service"
    echo ""
fi

if [ "$WAN_FORWARD" = "REJECT" ]; then
    echo "❌ WAN zone forward policy is REJECT!"
    echo "   This blocks all forwarding from WAN → LAN"
    echo ""
    echo "   SOLUTION 1: Add port forward rules to firewall"
    echo "   Run: sh fix-port-forwarding.sh"
    echo ""
    echo "   SOLUTION 2: Allow WAN→LAN forwarding (less secure)"
    echo "   Add this forwarding rule:"
    echo "     uci add firewall forwarding"
    echo "     uci set firewall.@forwarding[-1].src='wan'"
    echo "     uci set firewall.@forwarding[-1].dest='lan'"
    echo "     uci commit firewall"
    echo "     /etc/init.d/firewall restart"
fi

echo ""
echo "=========================================="
echo "QUICK FIX"
echo "=========================================="
echo ""
echo "To fix port forwarding immediately:"
echo "  sh fix-port-forwarding.sh"
echo ""
