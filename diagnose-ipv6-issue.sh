#!/bin/sh
#
# Comprehensive IPv6 Acquisition Diagnostic
# Run this on OpenWrt gateway to identify IPv6 issues
#

echo "=========================================="
echo "IPv6 Acquisition Diagnostics"
echo "=========================================="
echo ""

# 1. Check gateway service
echo "1. Gateway Service Status"
echo "────────────────────────────────────────"
if ps | grep -q "[p]ython.*gateway"; then
    echo "✅ Gateway service is running"
    ps | grep "[p]ython.*gateway"
else
    echo "❌ Gateway service NOT running!"
    echo "   Start it with: /etc/init.d/ipv4-ipv6-gateway start"
    exit 1
fi
echo ""

# 2. Check device info
echo "2. Device Information"
echo "────────────────────────────────────────"
DEVICE_JSON=$(curl -s http://localhost:5050/devices 2>/dev/null || echo "{}")
MAC=$(echo "$DEVICE_JSON" | grep -o '"mac_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV4_LAN=$(echo "$DEVICE_JSON" | grep -o '"ipv4_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV4_WAN=$(echo "$DEVICE_JSON" | grep -o '"ipv4_wan_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV6=$(echo "$DEVICE_JSON" | grep -o '"ipv6_address":"[^"]*"' | head -1 | cut -d'"' -f4)
STATUS=$(echo "$DEVICE_JSON" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$MAC" ]; then
    echo "❌ No device detected"
    echo ""
    echo "Check ARP table:"
    ip neigh show dev eth1
    exit 1
fi

echo "Device MAC:        $MAC"
echo "Device LAN IPv4:   $IPV4_LAN"
echo "Device WAN IPv4:   $IPV4_WAN"
echo "Device IPv6:       ${IPV6:-NONE}"
echo "Status:            $STATUS"
echo ""

# 3. Check eth0 MAC
echo "3. WAN Interface (eth0) MAC Check"
echo "────────────────────────────────────────"
ETH0_MAC=$(ip link show eth0 | grep 'link/ether' | awk '{print $2}')
echo "eth0 current MAC:  $ETH0_MAC"
echo "Device MAC:        $MAC"

if [ "$ETH0_MAC" = "$MAC" ]; then
    echo "✅ eth0 MAC matches device MAC (correct!)"
else
    echo "❌ eth0 MAC does NOT match device MAC!"
    echo "   This is the problem - eth0 must use device's MAC"
    echo ""
    echo "   Fix with:"
    echo "   ip link set eth0 down"
    echo "   ip link set eth0 address $MAC"
    echo "   ip link set eth0 up"
fi
echo ""

# 4. Check IPv6 on eth0
echo "4. IPv6 Addresses on eth0"
echo "────────────────────────────────────────"
ETH0_IPV6=$(ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80' | awk '{print $2}')

if [ -z "$ETH0_IPV6" ]; then
    echo "❌ NO IPv6 addresses on eth0!"
    echo ""
    echo "   This is the problem - SLAAC/DHCPv6 failed"
    echo ""
    echo "   Possible causes:"
    echo "   1. Router doesn't support IPv6"
    echo "   2. Router Advertisement not sent to this MAC"
    echo "   3. DHCPv6 server not responding"
    echo "   4. IPv6 disabled in kernel"
else
    echo "✅ IPv6 addresses found on eth0:"
    echo "$ETH0_IPV6" | while read addr; do
        echo "   $addr"
    done

    # Check if device IPv6 is configured
    if [ -n "$IPV6" ] && echo "$ETH0_IPV6" | grep -q "${IPV6%/*}"; then
        echo "✅ Device IPv6 IS configured on eth0"
    elif [ -n "$IPV6" ]; then
        echo "⚠️  Device IPv6 $IPV6 NOT on eth0"
        echo "   Gateway thinks device has this IPv6 but it's not configured"
    fi
fi
echo ""

# 5. Check IPv6 settings
echo "5. IPv6 Kernel Settings"
echo "────────────────────────────────────────"
echo "IPv6 disabled:     $(sysctl -n net.ipv6.conf.eth0.disable_ipv6)"
echo "Accept RA:         $(sysctl -n net.ipv6.conf.eth0.accept_ra)"
echo "Autoconf:          $(sysctl -n net.ipv6.conf.eth0.autoconf)"
echo "Router solicit:    $(sysctl -n net.ipv6.conf.eth0.router_solicitations)"

DISABLED=$(sysctl -n net.ipv6.conf.eth0.disable_ipv6)
if [ "$DISABLED" = "1" ]; then
    echo "❌ IPv6 is DISABLED on eth0!"
    echo "   Enable with: sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
else
    echo "✅ IPv6 is enabled on eth0"
fi
echo ""

# 6. Test Router Advertisement
echo "6. Router Advertisement Test"
echo "────────────────────────────────────────"
echo "Sending Router Solicitation to ff02::2 (all-routers)..."
if ping6 -c 2 -I eth0 ff02::2 >/dev/null 2>&1; then
    echo "✅ Router responds to ping6"
else
    echo "⚠️  Router doesn't respond (may be normal)"
fi
echo ""

# 7. Check DHCPv6 client
echo "7. DHCPv6 Client Check"
echo "────────────────────────────────────────"
if command -v odhcp6c >/dev/null 2>&1; then
    echo "✅ odhcp6c is installed: $(which odhcp6c)"

    # Test DHCPv6
    echo ""
    echo "Testing DHCPv6 request (3 second timeout)..."
    timeout 3 odhcp6c -P 0 -t 3 eth0 2>&1 | head -10
else
    echo "❌ odhcp6c NOT installed!"
    echo "   Install with: opkg install odhcp6c"
fi
echo ""

# 8. Check gateway logs
echo "8. Recent Gateway Logs (IPv6-related)"
echo "────────────────────────────────────────"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    echo "Last 20 IPv6-related log entries:"
    tail -100 /var/log/ipv4-ipv6-gateway.log | grep -iE 'ipv6|slaac|dhcpv6|router.*advert' | tail -20
else
    echo "⚠️  Log file not found"
fi
echo ""

# 9. Check routing
echo "9. IPv6 Routing Table"
echo "────────────────────────────────────────"
ip -6 route show | head -10
echo ""

# 10. Network connectivity test
echo "10. IPv6 Connectivity Test"
echo "────────────────────────────────────────"
echo "Testing IPv6 connectivity to Google DNS..."
if ping6 -c 2 2001:4860:4860::8888 >/dev/null 2>&1; then
    echo "✅ IPv6 internet connectivity works!"
else
    echo "❌ No IPv6 internet connectivity"
    echo "   This suggests:"
    echo "   - Router doesn't provide IPv6"
    echo "   - ISP doesn't support IPv6"
    echo "   - Firewall blocking IPv6"
fi
echo ""

# Summary and recommendations
echo "=========================================="
echo "Summary & Recommendations"
echo "=========================================="
echo ""

if [ -z "$ETH0_IPV6" ]; then
    echo "🔴 CRITICAL ISSUE: No IPv6 on eth0"
    echo ""
    echo "Root Cause Analysis:"
    echo "1. Check if eth0 MAC = device MAC:"
    echo "   Current: $ETH0_MAC"
    echo "   Should:  $MAC"
    echo ""
    echo "2. Manual IPv6 acquisition test:"
    echo "   # Set device MAC"
    echo "   ip link set eth0 down"
    echo "   ip link set eth0 address $MAC"
    echo "   ip link set eth0 up"
    echo ""
    echo "   # Enable IPv6"
    echo "   sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
    echo "   sysctl -w net.ipv6.conf.eth0.accept_ra=2"
    echo "   sysctl -w net.ipv6.conf.eth0.autoconf=1"
    echo ""
    echo "   # Trigger Router Solicitation"
    echo "   ping6 -c 1 -I eth0 ff02::2"
    echo ""
    echo "   # Wait 15 seconds"
    echo "   sleep 15"
    echo ""
    echo "   # Check for IPv6"
    echo "   ip -6 addr show eth0 | grep -v fe80"
    echo ""
    echo "   # If still no IPv6, try DHCPv6"
    echo "   timeout 10 odhcp6c -P 0 -t 10 eth0"
    echo ""
elif [ -n "$IPV6" ] && ! echo "$ETH0_IPV6" | grep -q "${IPV6%/*}"; then
    echo "🟡 WARNING: IPv6 mismatch"
    echo ""
    echo "Gateway DB says:     $IPV6"
    echo "eth0 actually has:   $ETH0_IPV6"
    echo ""
    echo "Solutions:"
    echo "1. Re-add IPv6 to eth0:"
    echo "   ip -6 addr add $IPV6/64 dev eth0"
    echo ""
    echo "2. Or clear device cache and rediscover:"
    echo "   curl -X POST http://localhost:5050/admin/clear-cache"
    echo "   /etc/init.d/ipv4-ipv6-gateway restart"
else
    echo "✅ IPv6 acquisition appears to be working"
    echo ""
    echo "IPv6 addresses on eth0:"
    echo "$ETH0_IPV6" | while read addr; do
        echo "  - $addr"
    done
fi
echo ""
