#!/bin/sh
#
# Gateway Device Status (Direct - No API)
# Shows current device information by reading directly from system
#

echo "=========================================="
echo "Gateway Device Status (Direct)"
echo "=========================================="
echo ""

# 1. Device cache file
DEVICES_FILE="/etc/ipv4-ipv6-gateway/devices.json"

if [ -f "$DEVICES_FILE" ]; then
    echo "📄 Device Cache:"
    echo "────────────────────────────────────────"
    cat "$DEVICES_FILE" | grep -v '^{$\|^}$' | sed 's/^  //'
    echo ""
else
    echo "⚠️  No device cache file found"
    echo ""
fi

# 2. Live ARP table
echo "📡 Live ARP Table (eth1):"
echo "────────────────────────────────────────"
ip neigh show dev eth1 | grep -v FAILED | grep -v INCOMPLETE
echo ""

# 3. eth0 (WAN) status
echo "🌐 WAN Interface (eth0):"
echo "────────────────────────────────────────"
ETH0_MAC=$(ip link show eth0 | grep 'link/ether' | awk '{print $2}')
echo "MAC: $ETH0_MAC"
echo ""
echo "IPv6 addresses:"
ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80' | awk '{print "  " $2}'
echo ""
echo "IPv4 addresses:"
ip -4 addr show eth0 | grep 'inet' | awk '{print "  " $2}'
echo ""

# 4. Proxy processes
echo "🔀 Active Proxies:"
echo "────────────────────────────────────────"
SOCAT_COUNT=$(ps | grep -c '[s]ocat.*TCP6-LISTEN' || echo "0")
if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo "Found $SOCAT_COUNT socat proxies:"
    ps | grep '[s]ocat' | awk '{print "  " $0}'
else
    echo "No socat proxies running"
    if ps | grep -q '[h]aproxy'; then
        echo "Using HAProxy instead:"
        ps | grep '[h]aproxy'
    fi
fi
echo ""

# 5. Gateway service
echo "⚙️  Gateway Service:"
echo "────────────────────────────────────────"
if ps | grep -q '[p]ython.*gateway'; then
    echo "✅ Running"
    ps | grep '[p]ython.*gateway' | head -1
else
    echo "❌ NOT running"
fi
echo ""
