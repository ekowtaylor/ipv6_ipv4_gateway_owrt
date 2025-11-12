#!/bin/bash
#
# Diagnostic script to troubleshoot ping issues
# Run this on the gateway to diagnose connectivity
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Gateway Ping Diagnostic${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# 1. Check interfaces are up
echo -e "${BLUE}1. Checking network interfaces...${NC}"
ip link show eth0 | head -1
ip link show eth1 | head -1
echo ""

# 2. Check IP addresses
echo -e "${BLUE}2. Checking IP addresses...${NC}"
echo -e "${YELLOW}eth0 (WAN):${NC}"
ip -4 addr show eth0 | grep inet || echo "  No IPv4"
ip -6 addr show eth0 | grep inet6 | grep -v fe80 || echo "  No IPv6 (except link-local)"
echo ""
echo -e "${YELLOW}eth1 (LAN):${NC}"
ip -4 addr show eth1 | grep inet || echo "  No IPv4"
ip -6 addr show eth1 | grep inet6 | grep -v fe80 || echo "  No IPv6 (except link-local)"
echo ""

# 3. Check iptables ICMP rules
echo -e "${BLUE}3. Checking iptables ICMP rules...${NC}"
echo -e "${YELLOW}INPUT chain (should allow ICMP):${NC}"
iptables -L INPUT -v -n | grep icmp || echo "  No ICMP rules in INPUT"
echo ""
echo -e "${YELLOW}FORWARD chain (should allow ICMP):${NC}"
iptables -L FORWARD -v -n | grep icmp || echo "  No ICMP rules in FORWARD"
echo ""

# 4. Check ip6tables ICMP rules
echo -e "${BLUE}4. Checking ip6tables ICMPv6 rules...${NC}"
echo -e "${YELLOW}INPUT chain (should allow ICMPv6):${NC}"
ip6tables -L INPUT -v -n | grep -i icmp || echo "  No ICMPv6 rules in INPUT"
echo ""
echo -e "${YELLOW}FORWARD chain (should allow ICMPv6):${NC}"
ip6tables -L FORWARD -v -n | grep -i icmp || echo "  No ICMPv6 rules in FORWARD"
echo ""

# 5. Test ping locally
echo -e "${BLUE}5. Testing local ping (gateway to itself)...${NC}"
echo -e "${YELLOW}Ping 127.0.0.1:${NC}"
ping -c 2 127.0.0.1 2>&1 | tail -2

echo -e "${YELLOW}Ping ::1:${NC}"
ping6 -c 2 ::1 2>&1 | tail -2
echo ""

# 6. Test ping eth1 (LAN)
echo -e "${BLUE}6. Testing ping to eth1 (LAN interface)...${NC}"
LAN_IP=$(ip -4 addr show eth1 | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
if [ -n "$LAN_IP" ]; then
    echo -e "${YELLOW}Ping $LAN_IP (eth1 IPv4):${NC}"
    ping -c 2 "$LAN_IP" 2>&1 | tail -2
else
    echo -e "${RED}  No IPv4 on eth1${NC}"
fi
echo ""

# 7. Check IP forwarding
echo -e "${BLUE}7. Checking IP forwarding settings...${NC}"
echo -e "${YELLOW}IPv4 forwarding:${NC} $(cat /proc/sys/net/ipv4/ip_forward)"
echo -e "${YELLOW}IPv6 forwarding:${NC} $(cat /proc/sys/net/ipv6/conf/all/forwarding)"
echo ""

# 8. Check routing
echo -e "${BLUE}8. Checking routing table...${NC}"
echo -e "${YELLOW}IPv4 routes:${NC}"
ip -4 route show | head -5
echo ""
echo -e "${YELLOW}IPv6 routes:${NC}"
ip -6 route show | head -5
echo ""

# 9. Recommendations
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Recommendations:${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check if ICMP is allowed
ICMP_INPUT=$(iptables -L INPUT -v -n | grep -i icmp | wc -l)
ICMPV6_INPUT=$(ip6tables -L INPUT -v -n | grep -i icmp | wc -l)

if [ "$ICMP_INPUT" -eq 0 ]; then
    echo -e "${RED}✗ No ICMP rules in iptables INPUT chain${NC}"
    echo -e "${YELLOW}  Fix: iptables -I INPUT -p icmp -j ACCEPT${NC}"
fi

if [ "$ICMPV6_INPUT" -eq 0 ]; then
    echo -e "${RED}✗ No ICMPv6 rules in ip6tables INPUT chain${NC}"
    echo -e "${YELLOW}  Fix: ip6tables -I INPUT -p ipv6-icmp -j ACCEPT${NC}"
fi

if [ "$ICMP_INPUT" -gt 0 ] && [ "$ICMPV6_INPUT" -gt 0 ]; then
    echo -e "${GREEN}✓ ICMP rules appear to be configured${NC}"
fi

echo ""
