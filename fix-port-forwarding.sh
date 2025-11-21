#!/bin/sh
#
# FIX PORT FORWARDING - Allow WAN→LAN forwarding for device access
# This fixes port forwarding by allowing traffic through the firewall
#

echo "=========================================="
echo "FIXING PORT FORWARDING"
echo "=========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run as root"
    exit 1
fi

echo "Current WAN firewall configuration:"
echo "------------------------------"
uci show firewall | grep "@zone\[1\]" | grep -E "(name|input|forward)"
echo ""

# Check if WAN→LAN forwarding exists
echo "Checking for existing WAN→LAN forwarding rule..."
if uci show firewall | grep -q "src='wan'" | grep -q "dest='lan'"; then
    echo "  WAN→LAN forwarding rule already exists"
else
    echo "  No WAN→LAN forwarding rule found - adding it now..."

    # Add forwarding rule from WAN to LAN
    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='wan'
    uci set firewall.@forwarding[-1].dest='lan'

    echo "  ✓ Added WAN→LAN forwarding rule"
fi

# Commit firewall changes
echo ""
echo "Committing firewall configuration..."
uci commit firewall
echo "  ✓ Configuration committed"

echo ""
echo "New firewall forwarding rules:"
echo "------------------------------"
uci show firewall | grep "forwarding"
echo ""

# Restart firewall
echo "Restarting firewall..."
/etc/init.d/firewall restart
sleep 2
echo "  ✓ Firewall restarted"

echo ""
echo "Restarting gateway service to recreate iptables rules..."
/etc/init.d/ipv4-ipv6-gateway restart
sleep 3
echo "  ✓ Gateway service restarted"

echo ""
echo "Waiting for device reconfiguration (30 seconds)..."
sleep 30

# Check device status
if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    DEVICE_WAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv4"' | cut -d'"' -f4)
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)

    echo ""
    echo "Device configuration:"
    echo "------------------------------"
    echo "Device LAN IP: ${DEVICE_LAN_IP:-NOT FOUND}"
    echo "Device WAN IP: ${DEVICE_WAN_IP:-NOT FOUND}"
    echo ""

    # Check iptables rules
    echo "Checking iptables NAT rules:"
    echo "------------------------------"
    iptables -t nat -L PREROUTING -n -v | grep -E "(8080|5000|2323|2222)" | head -5
    echo ""

    echo "Checking iptables FORWARD rules:"
    echo "------------------------------"
    iptables -L FORWARD -n -v | grep "$DEVICE_LAN_IP" | head -5
    echo ""
fi

echo "=========================================="
echo "PORT FORWARDING FIX COMPLETE"
echo "=========================================="
echo ""
echo "Firewall now allows:"
echo "  ✓ WAN → LAN forwarding (for port forwards)"
echo "  ✓ Traffic can flow from upstream to device"
echo ""
echo "Port forwards that should work:"
echo "  curl http://${DEVICE_WAN_IP:-<wan-ip>}:8080    → Device HTTP (port 80)"
echo "  curl http://${DEVICE_WAN_IP:-<wan-ip>}:5000    → Device HTTP (port 5000)"
echo "  telnet ${DEVICE_WAN_IP:-<wan-ip>} 2323         → Device Telnet (port 23)"
echo "  ssh -p 2222 user@${DEVICE_WAN_IP:-<wan-ip>}    → Device SSH (port 22)"
echo ""
echo "Test from upstream network:"
echo "  ping ${DEVICE_WAN_IP:-<wan-ip>}                ✓ Should work"
echo "  curl http://${DEVICE_WAN_IP:-<wan-ip>}:8080    ✓ Should work (if port 80 listening)"
echo "  curl http://${DEVICE_WAN_IP:-<wan-ip>}:5000    ✓ Should work (if port 5000 listening)"
echo ""
