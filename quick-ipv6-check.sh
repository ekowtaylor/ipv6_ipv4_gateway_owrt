#!/bin/sh
#
# Quick IPv6 Diagnostic (Direct - No API)
# Reads device info directly from system state and files
#

echo "=========================================="
echo "Quick IPv6 Diagnostics (Direct)"
echo "=========================================="
echo ""

# 1. Gateway service check
echo "1. Gateway Service"
echo "────────────────────────────────────────"
if ps | grep -q "[p]ython.*gateway"; then
    echo "✅ Running"
    ps | grep "[p]ython.*gateway" | head -1
else
    echo "❌ NOT running"
fi
echo ""

# 2. Device Info (Direct - NO API)
echo "2. Device Info (Direct from System)"
echo "────────────────────────────────────────"

# Try to read from devices.json file first
DEVICES_FILE="/etc/ipv4-ipv6-gateway/devices.json"
if [ -f "$DEVICES_FILE" ]; then
    echo "Reading from: $DEVICES_FILE"

    # Extract first device info using grep/awk (no python needed)
    MAC=$(grep -o '"[0-9a-f:]\{17\}"' "$DEVICES_FILE" | head -1 | tr -d '"')
    IPV4=$(grep -o '"ipv4_address": "[^"]*"' "$DEVICES_FILE" | head -1 | cut -d'"' -f4)
    IPV6=$(grep -o '"ipv6_address": "[^"]*"' "$DEVICES_FILE" | head -1 | cut -d'"' -f4)
    STATUS=$(grep -o '"status": "[^"]*"' "$DEVICES_FILE" | head -1 | cut -d'"' -f4)

    if [ -n "$MAC" ]; then
        echo "✅ Found device in cache:"
        echo "   MAC:    $MAC"
        echo "   IPv4:   ${IPV4:-none}"
        echo "   IPv6:   ${IPV6:-none}"
        echo "   Status: ${STATUS:-unknown}"
    else
        echo "⚠️  Device file exists but couldn't parse"
    fi
fi

# Always check ARP table (live data)
echo ""
echo "ARP Table (Live):"
ARP_MAC=$(ip neigh show dev eth1 | grep -v FAILED | grep -v INCOMPLETE | head -1 | awk '{print $5}')
ARP_IPV4=$(ip neigh show dev eth1 | grep -v FAILED | grep -v INCOMPLETE | head -1 | awk '{print $1}')

if [ -n "$ARP_MAC" ]; then
    echo "   MAC:  $ARP_MAC"
    echo "   IPv4: $ARP_IPV4"

    # Use ARP data if we didn't get it from file
    MAC=${MAC:-$ARP_MAC}
    IPV4=${IPV4:-$ARP_IPV4}
else
    echo "   ❌ No devices in ARP table"
fi

if [ -z "$MAC" ]; then
    echo ""
    echo "❌ No device found in cache or ARP!"
    exit 1
fi
echo ""

# 3. eth0 MAC check
echo "3. WAN Interface MAC"
echo "────────────────────────────────────────"
ETH0_MAC=$(ip link show eth0 | grep 'link/ether' | awk '{print $2}')
echo "eth0 MAC:   $ETH0_MAC"
echo "Device MAC: $MAC"

if [ "$ETH0_MAC" = "$MAC" ]; then
    echo "✅ MATCH"
else
    echo "❌ MISMATCH - This is the problem!"
fi
echo ""

# 4. IPv6 on eth0
echo "4. IPv6 on eth0"
echo "────────────────────────────────────────"
ETH0_IPV6=$(ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80')

if [ -z "$ETH0_IPV6" ]; then
    echo "❌ NO IPv6 on eth0!"
else
    echo "✅ IPv6 found:"
    echo "$ETH0_IPV6"
fi
echo ""

# 5. IPv6 settings
echo "5. IPv6 Settings"
echo "────────────────────────────────────────"
echo "disabled:  $(sysctl -n net.ipv6.conf.eth0.disable_ipv6)"
echo "accept_ra: $(sysctl -n net.ipv6.conf.eth0.accept_ra)"
echo "autoconf:  $(sysctl -n net.ipv6.conf.eth0.autoconf)"
echo ""

# 6. Recent logs
echo "6. Last 15 Log Lines"
echo "────────────────────────────────────────"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    tail -15 /var/log/ipv4-ipv6-gateway.log
else
    echo "⚠️  Log file not found"
fi
echo ""

# 7. Quick summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""

if [ "$ETH0_MAC" != "$MAC" ]; then
    echo "🔴 PROBLEM: eth0 MAC doesn't match device MAC"
    echo ""
    echo "Fix:"
    echo "  ip link set eth0 down"
    echo "  ip link set eth0 address $MAC"
    echo "  ip link set eth0 up"
    echo ""
elif [ -z "$ETH0_IPV6" ]; then
    echo "🔴 PROBLEM: No IPv6 on eth0"
    echo ""
    echo "Possible causes:"
    echo "  - Router not sending IPv6 to this MAC"
    echo "  - SLAAC/DHCPv6 failed"
    echo "  - IPv6 disabled"
    echo ""
    echo "Check logs for:"
    echo "  tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i ipv6"
else
    echo "✅ Looks OK"
    echo ""
    echo "IPv6 addresses on eth0:"
    echo "$ETH0_IPV6"
fi
echo ""
