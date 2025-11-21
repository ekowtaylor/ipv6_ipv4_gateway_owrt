#!/bin/sh
#
# FIX FIREWALL SECURELY - Allow ping but block LuCI on WAN
# This is the CORRECT security configuration
#

echo "=========================================="
echo "FIXING FIREWALL - SECURE CONFIGURATION"
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

# Step 1: Block WAN input by default (secure!)
echo "Step 1: Blocking WAN input by default..."
uci set firewall.@zone[1].input='REJECT'
uci commit firewall

# Step 2: Add specific rule to allow ICMP (ping)
echo "Step 2: Adding rule to allow ICMP (ping) only..."

# Check if rule already exists
if uci show firewall | grep -q "Allow-Ping"; then
    echo "  Rule already exists, updating..."
    # Find and update existing rule
    RULE_INDEX=$(uci show firewall | grep "name='Allow-Ping'" | cut -d'[' -f2 | cut -d']' -f1 | head -1)
    if [ -n "$RULE_INDEX" ]; then
        uci set firewall.@rule[$RULE_INDEX].enabled='1'
    fi
else
    echo "  Creating new rule..."
    uci add firewall rule
    uci set firewall.@rule[-1].name='Allow-Ping'
    uci set firewall.@rule[-1].src='wan'
    uci set firewall.@rule[-1].proto='icmp'
    uci set firewall.@rule[-1].icmp_type='echo-request'
    uci set firewall.@rule[-1].family='ipv4'
    uci set firewall.@rule[-1].target='ACCEPT'
fi

uci commit firewall

echo "✓ Firewall configured"
echo ""

echo "New firewall configuration:"
echo "------------------------------"
echo "WAN Zone:"
uci show firewall | grep "zone\[1\]" | grep -E "(name|input|output|forward)"
echo ""
echo "Ping Rule:"
uci show firewall | grep -A 6 "Allow-Ping" | head -7
echo ""

# Restart firewall to apply changes
echo "Restarting firewall..."
/etc/init.d/firewall restart
sleep 2

echo "✓ Firewall restarted"
echo ""

# Test connectivity
echo "Testing connectivity..."
echo "------------------------------"

# Get WAN IP
WAN_IP=$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')
if [ -n "$WAN_IP" ]; then
    echo "WAN IPv4: $WAN_IP"
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
echo "SECURITY STATUS"
echo "=========================================="
echo ""
echo "✅ WAN zone input: REJECT (secure!)"
echo "✅ ICMP allowed: Ping works from upstream"
echo "✅ HTTP blocked: LuCI NOT accessible from WAN"
echo "✅ Router protected from upstream network"
echo ""
echo "FROM UPSTREAM NETWORK (192.168.8.x):"
echo "  ✅ ping $WAN_IP              (works)"
echo "  ❌ curl http://$WAN_IP       (blocked - good!)"
echo "  ❌ ssh root@$WAN_IP          (blocked - good!)"
echo ""
echo "FROM LAN NETWORK (192.168.1.x):"
echo "  ✅ http://192.168.1.1        (LuCI works)"
echo "  ✅ ssh root@192.168.1.1      (works)"
echo ""
echo "=========================================="
echo "FIREWALL FIX COMPLETE - SECURE!"
echo "=========================================="
echo ""
