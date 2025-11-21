#!/bin/bash
#
# Complete Gateway Diagnostics
# Run this on the router to diagnose IPv4 ping and IPv6 issues
#

echo "═══════════════════════════════════════════════════════════"
echo "Gateway Diagnostic Report"
echo "═══════════════════════════════════════════════════════════"
echo ""
date
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}1. Interface Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "eth0 (WAN) status:"
ip link show eth0
echo ""

echo "eth1 (LAN) status:"
ip link show eth1
echo ""

echo -e "${BLUE}2. MAC Addresses${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

ETH0_MAC=$(ip link show eth0 | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}')
ETH1_MAC=$(ip link show eth1 | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}')
ORIGINAL_MAC=$(cat /etc/ipv4-ipv6-gateway/original_wan_mac.txt 2>/dev/null)

echo "eth0 (WAN) MAC:     $ETH0_MAC"
echo "eth1 (LAN) MAC:     $ETH1_MAC"
echo "Original WAN MAC:   $ORIGINAL_MAC"
echo ""

if [ -f "/etc/ipv4-ipv6-gateway/device.json" ]; then
    DEVICE_MAC=$(grep -o '"mac_address": "[^"]*"' /etc/ipv4-ipv6-gateway/device.json | cut -d'"' -f4)
    echo "Device MAC (from state): $DEVICE_MAC"
    echo ""

    if [ "$ETH0_MAC" = "$DEVICE_MAC" ]; then
        echo -e "${GREEN}✓ WAN MAC correctly spoofed${NC}"
    else
        echo -e "${RED}✗ WAN MAC NOT spoofed correctly!${NC}"
        echo "  Expected: $DEVICE_MAC"
        echo "  Actual:   $ETH0_MAC"
    fi
else
    echo -e "${YELLOW}⚠ No device.json found${NC}"
fi
echo ""

echo -e "${BLUE}3. IPv4 Addresses${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "eth0 (WAN) IPv4:"
ip -4 addr show eth0 | grep inet || echo "  (none)"
echo ""

echo "eth1 (LAN) IPv4:"
ip -4 addr show eth1 | grep inet || echo "  (none)"
echo ""

WAN_IPV4=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
if [ -n "$WAN_IPV4" ]; then
    echo -e "${GREEN}✓ WAN has IPv4: $WAN_IPV4${NC}"
else
    echo -e "${RED}✗ WAN has NO IPv4!${NC}"
fi
echo ""

echo -e "${BLUE}4. IPv6 Addresses${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "eth0 (WAN) IPv6:"
ip -6 addr show eth0 | grep inet6 || echo "  (none)"
echo ""

echo "eth1 (LAN) IPv6:"
ip -6 addr show eth1 | grep inet6 || echo "  (none)"
echo ""

WAN_IPV6_COUNT=$(ip -6 addr show eth0 | grep -c 'inet6.*global')
if [ "$WAN_IPV6_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ WAN has $WAN_IPV6_COUNT global IPv6 address(es)${NC}"
else
    echo -e "${RED}✗ WAN has NO global IPv6 addresses!${NC}"
    echo "  (Only link-local fe80:: addresses don't count)"
fi
echo ""

echo -e "${BLUE}5. IPv6 Router Advertisements (SLAAC)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Listening for Router Advertisements (10 seconds)..."
timeout 10 tcpdump -i eth0 -n 'icmp6 and ip6[40] == 134' 2>/dev/null | head -5 &
TCPDUMP_PID=$!
sleep 11
echo ""

if kill -0 $TCPDUMP_PID 2>/dev/null; then
    kill $TCPDUMP_PID 2>/dev/null
    echo -e "${YELLOW}⚠ No Router Advertisements received${NC}"
    echo "  This means upstream network is NOT sending IPv6 RAs"
    echo "  SLAAC will not work without RAs"
else
    echo -e "${GREEN}✓ Router Advertisements received${NC}"
fi
echo ""

echo -e "${BLUE}6. DHCPv6 Server Detection${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Trying DHCPv6 solicit (5 seconds)..."
timeout 5 odhcp6c -v -s /bin/true eth0 2>&1 | head -10
echo ""

echo -e "${BLUE}7. Upstream Network Connectivity${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Default gateway:"
ip route | grep default
echo ""

echo "Ping upstream gateway (IPv4):"
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
if [ -n "$GATEWAY" ]; then
    ping -c 3 -W 2 $GATEWAY || echo "  Failed to ping gateway"
else
    echo "  No default gateway found"
fi
echo ""

echo "Ping Google DNS (IPv4):"
ping -c 3 -W 2 8.8.8.8 || echo "  Failed - no IPv4 internet"
echo ""

echo "Ping Google DNS (IPv6):"
ping6 -c 3 -W 2 2001:4860:4860::8888 || echo "  Failed - no IPv6 internet"
echo ""

echo -e "${BLUE}8. Device State${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if [ -f "/etc/ipv4-ipv6-gateway/device.json" ]; then
    echo "Device configuration:"
    cat /etc/ipv4-ipv6-gateway/device.json | python3 -m json.tool
else
    echo -e "${RED}✗ No device.json found${NC}"
fi
echo ""

echo -e "${BLUE}9. ARP Table (LAN Devices)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""
ip neigh show dev eth1
echo ""

echo -e "${BLUE}10. iptables NAT Rules (Port Forwarding)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "PREROUTING chain (DNAT rules):"
iptables -t nat -L PREROUTING -n -v --line-numbers
echo ""

echo "FORWARD chain:"
iptables -L FORWARD -n -v --line-numbers | head -20
echo ""

echo -e "${BLUE}11. ICMP Port Forwarding Test${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if [ -n "$WAN_IPV4" ] && [ -f "/etc/ipv4-ipv6-gateway/device.json" ]; then
    DEVICE_LAN_IP=$(grep -o '"lan_ipv4": "[^"]*"' /etc/ipv4-ipv6-gateway/device.json | cut -d'"' -f4)

    echo "Checking ICMP DNAT rule:"
    if iptables -t nat -C PREROUTING -p icmp -d $WAN_IPV4 -j DNAT --to-destination $DEVICE_LAN_IP 2>/dev/null; then
        echo -e "${GREEN}✓ ICMP DNAT rule exists: $WAN_IPV4 → $DEVICE_LAN_IP${NC}"
    else
        echo -e "${RED}✗ ICMP DNAT rule MISSING!${NC}"
        echo "  This is why ping doesn't work!"
    fi

    echo ""
    echo "Checking ICMP FORWARD rule:"
    if iptables -C FORWARD -p icmp -d $DEVICE_LAN_IP -j ACCEPT 2>/dev/null; then
        echo -e "${GREEN}✓ ICMP FORWARD rule exists${NC}"
    else
        echo -e "${RED}✗ ICMP FORWARD rule MISSING!${NC}"
    fi
else
    echo "Cannot test - no WAN IPv4 or device configured"
fi
echo ""

echo -e "${BLUE}12. Service Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if pgrep -f ipv4_ipv6_gateway.py > /dev/null; then
    echo -e "${GREEN}✓ Gateway service is RUNNING${NC}"
    echo ""
    echo "Process info:"
    ps w | grep ipv4_ipv6_gateway.py | grep -v grep
else
    echo -e "${RED}✗ Gateway service is NOT running!${NC}"
fi
echo ""

echo -e "${BLUE}13. Recent Logs (last 30 lines)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""
tail -30 /var/log/ipv4-ipv6-gateway.log 2>/dev/null || echo "No log file found"
echo ""

echo -e "${BLUE}14. Network Configuration (UCI)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "WAN interface config:"
uci show network.wan 2>/dev/null || echo "  Not configured"
echo ""

echo "WAN6 interface config:"
uci show network.wan6 2>/dev/null || echo "  Not configured"
echo ""

echo "LAN interface config:"
uci show network.lan 2>/dev/null || echo "  Not configured"
echo ""

echo -e "${BLUE}15. IP Forwarding Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

IPV4_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
IPV6_FORWARD=$(cat /proc/sys/net/ipv6/conf/all/forwarding)

if [ "$IPV4_FORWARD" = "1" ]; then
    echo -e "${GREEN}✓ IPv4 forwarding: ENABLED${NC}"
else
    echo -e "${RED}✗ IPv4 forwarding: DISABLED${NC}"
fi

if [ "$IPV6_FORWARD" = "1" ]; then
    echo -e "${GREEN}✓ IPv6 forwarding: ENABLED${NC}"
else
    echo -e "${RED}✗ IPv6 forwarding: DISABLED${NC}"
fi
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "Diagnostic Report Complete"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo -e "${YELLOW}SUMMARY OF ISSUES:${NC}"
echo ""

# Check for issues
ISSUES=0

if [ "$ETH0_MAC" != "$DEVICE_MAC" ] && [ -n "$DEVICE_MAC" ]; then
    echo -e "${RED}✗ WAN MAC not spoofed correctly${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ -z "$WAN_IPV4" ]; then
    echo -e "${RED}✗ No IPv4 on WAN interface${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ "$WAN_IPV6_COUNT" -eq 0 ]; then
    echo -e "${RED}✗ No IPv6 on WAN interface${NC}"
    echo "  Check if upstream network provides IPv6"
    ISSUES=$((ISSUES + 1))
fi

if [ "$IPV4_FORWARD" != "1" ]; then
    echo -e "${RED}✗ IPv4 forwarding disabled${NC}"
    ISSUES=$((ISSUES + 1))
fi

if ! pgrep -f ipv4_ipv6_gateway.py > /dev/null; then
    echo -e "${RED}✗ Gateway service not running${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ No obvious issues detected${NC}"
    echo ""
    echo "If ping still doesn't work, the issue may be:"
    echo "  - Firewall on the device blocking ICMP"
    echo "  - Upstream firewall blocking spoofed MAC"
    echo "  - Network policy blocking ICMP to WAN IP"
fi

echo ""
