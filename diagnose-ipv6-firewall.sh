#!/bin/sh
#
# DIAGNOSE IPv6 FIREWALL BLOCKING
# Check if firewall is blocking Router Advertisements and DHCPv6
#

echo "=========================================="
echo "IPv6 FIREWALL DIAGNOSTIC"
echo "=========================================="
echo ""

# Check firewall WAN zone
echo "1. Firewall WAN Zone Configuration:"
echo "------------------------------"
uci show firewall | grep "@zone\[1\]" | grep -E "(name|input)"
echo ""

# Check for IPv6 allow rules
echo "2. IPv6 Allow Rules:"
echo "------------------------------"
echo "Looking for ICMPv6 and DHCPv6 rules..."
uci show firewall | grep -E "(Allow.*6|DHCPv6|Router.*Advert|ICMPv6)" || echo "  ⚠ NO IPv6 rules found!"
echo ""

# Check actual iptables
echo "3. ip6tables INPUT Chain:"
echo "------------------------------"
ip6tables -L INPUT -v -n | head -20
echo ""

# Test if we can see Router Advertisements
echo "4. Testing Router Advertisement Reception:"
echo "------------------------------"
echo "Listening for RAs on eth0 for 5 seconds..."
timeout 5 tcpdump -i eth0 -n icmp6 2>/dev/null | grep "router advertisement" &
TCPDUMP_PID=$!
sleep 6
kill $TCPDUMP_PID 2>/dev/null
echo ""

# Check IPv6 addresses on WAN
echo "5. Current IPv6 Addresses on WAN (eth0):"
echo "------------------------------"
ip -6 addr show eth0 | grep "inet6" | grep -v "fe80"
if [ $? -ne 0 ]; then
    echo "  ⚠ NO global IPv6 addresses found!"
else
    echo "  ✓ Global IPv6 address exists"
fi
echo ""

# Check IPv6 sysctl settings
echo "6. IPv6 System Settings:"
echo "------------------------------"
echo "IPv6 disabled: $(cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6)"
echo "Accept RA: $(cat /proc/sys/net/ipv6/conf/eth0/accept_ra)"
echo "Autoconf: $(cat /proc/sys/net/ipv6/conf/eth0/autoconf)"
echo ""

echo "=========================================="
echo "DIAGNOSIS COMPLETE"
echo "=========================================="
echo ""

# Determine the issue
WAN_INPUT=$(uci get firewall.@zone[1].input 2>/dev/null)
HAS_ICMPV6_RULE=$(uci show firewall | grep -c "ICMPv6\|ipv6-icmp")
HAS_DHCPV6_RULE=$(uci show firewall | grep -c "DHCPv6\|dhcpv6")

echo "ISSUE ANALYSIS:"
echo "------------------------------"

if [ "$WAN_INPUT" = "REJECT" ]; then
    echo "⚠ WAN input is REJECT (blocking by default)"

    if [ "$HAS_ICMPV6_RULE" -eq 0 ]; then
        echo "❌ NO ICMPv6 rule found - Router Advertisements BLOCKED!"
        echo "   This breaks SLAAC IPv6 address assignment"
    else
        echo "✓ ICMPv6 rule exists"
    fi

    if [ "$HAS_DHCPV6_RULE" -eq 0 ]; then
        echo "❌ NO DHCPv6 rule found - DHCPv6 responses BLOCKED!"
        echo "   This breaks DHCPv6 IPv6 address assignment"
    else
        echo "✓ DHCPv6 rule exists"
    fi
else
    echo "✓ WAN input is $WAN_INPUT (allowing traffic)"
fi

echo ""
echo "SOLUTION:"
echo "------------------------------"
if [ "$HAS_ICMPV6_RULE" -eq 0 ] || [ "$HAS_DHCPV6_RULE" -eq 0 ]; then
    echo "Run: sh fix-ipv6-firewall.sh"
    echo ""
    echo "This will add firewall rules to allow:"
    echo "  - ICMPv6 (Router Advertisements for SLAAC)"
    echo "  - DHCPv6 client responses (UDP 546)"
fi
echo ""
