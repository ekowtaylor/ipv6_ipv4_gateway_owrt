#!/bin/sh
#
# FIX FIREWALL NOW - Allow ping to WAN interface
# Run this immediately to fix the "can't ping router from upstream" issue
#

echo "=========================================="
echo "FIXING FIREWALL - ALLOW WAN INPUT"
echo "=========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run as root"
    exit 1
fi

echo "Current firewall configuration:"
echo "------------------------------"
uci show firewall | grep "zone\[1\]"
echo ""

# Fix WAN zone - change input from REJECT to ACCEPT
echo "Changing WAN zone input from REJECT to ACCEPT..."
uci set firewall.@zone[1].input='ACCEPT'
uci commit firewall

echo "✓ Firewall config updated"
echo ""

echo "New firewall configuration:"
echo "------------------------------"
uci show firewall | grep "zone\[1\]"
echo ""

# Restart firewall to apply changes
echo "Restarting firewall..."
/etc/init.d/firewall restart
sleep 2

echo "✓ Firewall restarted"
echo ""

# Test connectivity
echo "Testing WAN connectivity..."
echo "------------------------------"

# Get WAN IP
WAN_IP=$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')
if [ -n "$WAN_IP" ]; then
    echo "WAN IPv4: $WAN_IP"
    echo ""
    echo "You should now be able to:"
    echo "  - Ping router from upstream network: ping $WAN_IP"
    echo "  - SSH to router from upstream: ssh root@$WAN_IP"
else
    echo "⚠ No WAN IP detected - check network cable"
fi

echo ""
echo "Testing upstream connectivity..."
if ping -c 2 -W 2 192.168.8.1 >/dev/null 2>&1; then
    echo "✓ Can ping upstream router (192.168.8.1)"
else
    echo "✗ Cannot ping upstream router"
fi

echo ""
echo "=========================================="
echo "FIREWALL FIX COMPLETE"
echo "=========================================="
echo ""
echo "The WAN interface is now accessible!"
echo ""
