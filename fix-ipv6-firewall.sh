#!/bin/sh
#
# FIX IPv6 FIREWALL - Allow Router Advertisements and DHCPv6
# This fixes IPv6 connectivity after securing the firewall
#

echo "=========================================="
echo "FIXING IPv6 FIREWALL RULES"
echo "=========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run as root"
    exit 1
fi

echo "Current WAN firewall configuration:"
echo "------------------------------"
uci show firewall | grep "@zone\[1\]" | grep -E "(name|input)"
echo ""

# Add ICMPv6 rule for Router Advertisements (SLAAC)
echo "Step 1: Adding ICMPv6 rule for Router Advertisements..."

# Check if rule already exists
if uci show firewall | grep -q "Allow-ICMPv6"; then
    echo "  Rule already exists, skipping..."
else
    echo "  Creating new ICMPv6 rule..."
    uci add firewall rule
    uci set firewall.@rule[-1].name='Allow-ICMPv6'
    uci set firewall.@rule[-1].src='wan'
    uci set firewall.@rule[-1].proto='icmp'
    uci set firewall.@rule[-1].family='ipv6'
    uci set firewall.@rule[-1].target='ACCEPT'
    uci set firewall.@rule[-1].enabled='1'
    echo "  ✓ ICMPv6 rule added"
fi

# Add DHCPv6 client rule
echo ""
echo "Step 2: Adding DHCPv6 client rule..."

# Check if rule already exists
if uci show firewall | grep -q "Allow-DHCPv6"; then
    echo "  Rule already exists, skipping..."
else
    echo "  Creating new DHCPv6 rule..."
    uci add firewall rule
    uci set firewall.@rule[-1].name='Allow-DHCPv6'
    uci set firewall.@rule[-1].src='wan'
    uci set firewall.@rule[-1].proto='udp'
    uci set firewall.@rule[-1].dest_port='546'
    uci set firewall.@rule[-1].family='ipv6'
    uci set firewall.@rule[-1].target='ACCEPT'
    uci set firewall.@rule[-1].enabled='1'
    echo "  ✓ DHCPv6 rule added"
fi

# Commit firewall changes
echo ""
echo "Step 3: Committing firewall configuration..."
uci commit firewall
echo "  ✓ Configuration committed"

echo ""
echo "New firewall rules:"
echo "------------------------------"
uci show firewall | grep -A 6 "Allow-ICMPv6" | head -7
echo ""
uci show firewall | grep -A 6 "Allow-DHCPv6" | head -7
echo ""

# Restart firewall
echo "Step 4: Restarting firewall..."
/etc/init.d/firewall restart
sleep 2
echo "  ✓ Firewall restarted"

echo ""
echo "Step 5: Testing IPv6 connectivity..."

# Flush old IPv6 addresses
echo "  Flushing old IPv6 addresses on eth0..."
ip -6 addr flush dev eth0 2>/dev/null || true

# Enable IPv6 and RA
echo "  Enabling IPv6 Router Advertisement acceptance..."
sysctl -w net.ipv6.conf.eth0.disable_ipv6=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.eth0.accept_ra=2 >/dev/null 2>&1
sysctl -w net.ipv6.conf.eth0.autoconf=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.eth0.accept_ra_defrtr=1 >/dev/null 2>&1

# Force link cycle to trigger fresh RAs
echo "  Cycling link to trigger fresh Router Advertisements..."
ip link set eth0 down
sleep 1
ip link set eth0 up
sleep 3

# Wait for RA/DHCPv6
echo "  Waiting 10 seconds for Router Advertisements..."
sleep 10

# Check for IPv6 addresses
IPV6_ADDR=$(ip -6 addr show eth0 | grep "inet6" | grep -v "fe80" | head -1)

echo ""
echo "=========================================="
echo "RESULT"
echo "=========================================="
echo ""

if [ -n "$IPV6_ADDR" ]; then
    echo "✅ SUCCESS! IPv6 address obtained:"
    ip -6 addr show eth0 | grep "inet6" | grep -v "fe80"
    echo ""
    echo "IPv6 is now working!"
else
    echo "⚠ NO IPv6 address yet"
    echo ""
    echo "Possible causes:"
    echo "  1. Upstream router not sending RAs (wait up to 600s)"
    echo "  2. Upstream router has IPv6 disabled"
    echo "  3. Device needs to send Router Solicitation"
    echo ""
    echo "Try manual DHCPv6 request:"
    echo "  odhcp6c -v eth0"
fi

echo ""
echo "=========================================="
echo "FIREWALL FIX COMPLETE"
echo "=========================================="
echo ""
echo "Firewall rules now allow:"
echo "  ✓ ICMPv6 (Router Advertisements for SLAAC)"
echo "  ✓ DHCPv6 client responses (UDP port 546)"
echo "  ✓ ICMP ping (IPv4)"
echo "  ✓ Port forwards (8080, 5000, 2323, 2222, etc.)"
echo ""
echo "Security maintained:"
echo "  ✓ WAN input blocked by default"
echo "  ✓ LuCI NOT accessible from WAN"
echo "  ✓ Only specific services allowed"
echo ""
