#!/bin/bash
#
# DHCP Request Diagnostic Script
# Checks if gateway is properly requesting IPv4 and IPv6 addresses
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}DHCP Request Diagnostic${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check devices.json
echo -e "${BLUE}1. Checking devices.json...${NC}"
if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    echo -e "${GREEN}✓ devices.json exists${NC}"
    echo ""
    cat /etc/ipv4-ipv6-gateway/devices.json | python3 -m json.tool
    echo ""
else
    echo -e "${RED}✗ devices.json not found${NC}"
fi

# Check gateway logs for DHCP
echo -e "${BLUE}2. Checking gateway logs for DHCP requests...${NC}"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    echo -e "${YELLOW}Last 50 DHCPv4 log entries:${NC}"
    grep -i "dhcpv4" /var/log/ipv4-ipv6-gateway.log | tail -50
    echo ""

    echo -e "${YELLOW}Last 50 DHCPv6 log entries:${NC}"
    grep -i "dhcpv6" /var/log/ipv4-ipv6-gateway.log | tail -50
    echo ""

    echo -e "${YELLOW}DHCP failures/errors:${NC}"
    grep -iE "(dhcp.*fail|dhcp.*error|dhcp.*timeout)" /var/log/ipv4-ipv6-gateway.log | tail -20
    echo ""
else
    echo -e "${RED}✗ Gateway log not found${NC}"
fi

# Check eth0 addresses
echo -e "${BLUE}3. Checking eth0 addresses (WAN)...${NC}"
echo -e "${YELLOW}IPv4 addresses:${NC}"
ip -4 addr show eth0 | grep inet || echo "  (None)"
echo ""
echo -e "${YELLOW}IPv6 addresses:${NC}"
ip -6 addr show eth0 | grep inet6 || echo "  (None)"
echo ""

# Check eth1 addresses
echo -e "${BLUE}4. Checking eth1 addresses (LAN)...${NC}"
echo -e "${YELLOW}IPv4 addresses:${NC}"
ip -4 addr show eth1 | grep inet || echo "  (None)"
echo ""
echo -e "${YELLOW}IPv6 addresses:${NC}"
ip -6 addr show eth1 | grep inet6 || echo "  (None)"
echo ""

# Check ARP table (devices on LAN)
echo -e "${BLUE}5. Checking ARP table (devices on eth1/LAN)...${NC}"
arp -n | grep eth1
echo ""

# Check if DHCP client processes are running
echo -e "${BLUE}6. Checking for DHCP client processes...${NC}"
echo -e "${YELLOW}udhcpc (IPv4 DHCP client):${NC}"
ps | grep udhcpc | grep -v grep || echo "  (None running)"
echo ""
echo -e "${YELLOW}dhclient (Alternative IPv4/IPv6 DHCP client):${NC}"
ps | grep dhclient | grep -v grep || echo "  (None running)"
echo ""
echo -e "${YELLOW}odhcp6c (IPv6 DHCP client):${NC}"
ps | grep odhcp6c | grep -v grep || echo "  (None running)"
echo ""

# Check if gateway service is running
echo -e "${BLUE}7. Checking if gateway service is running...${NC}"
SERVICE_PID=$(ps | grep "ipv4_ipv6_gateway.py" | grep -v grep | awk '{print $1}' | head -1)
if [ -n "$SERVICE_PID" ]; then
    echo -e "${GREEN}✓ Gateway service is running (PID: $SERVICE_PID)${NC}"
else
    echo -e "${RED}✗ Gateway service NOT running${NC}"
    echo -e "${YELLOW}  Fix: /etc/init.d/ipv4-ipv6-gateway start${NC}"
fi
echo ""

# Check network connectivity
echo -e "${BLUE}8. Testing network connectivity...${NC}"
echo -e "${YELLOW}Ping Google DNS (IPv4 - 8.8.8.8):${NC}"
ping -c 2 -W 2 8.8.8.8 2>&1 | tail -2 || echo "  FAILED"
echo ""
echo -e "${YELLOW}Ping Google DNS (IPv6 - 2001:4860:4860::8888):${NC}"
ping6 -c 2 -W 2 2001:4860:4860::8888 2>&1 | tail -2 || echo "  FAILED"
echo ""

# Summary
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Summary & Recommendations${NC}"
echo -e "${YELLOW}========================================${NC}"

# Parse devices.json to check if device has IPv4 WAN
if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    HAS_IPV4_WAN=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; d=json.load(sys.stdin); print('yes' if any(v.get('ipv4_wan_address') for v in d.values()) else 'no')" 2>/dev/null)
    HAS_IPV6=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; d=json.load(sys.stdin); print('yes' if any(v.get('ipv6_address') for v in d.values()) else 'no')" 2>/dev/null)

    if [ "$HAS_IPV4_WAN" = "yes" ]; then
        echo -e "${GREEN}✓ Device has WAN IPv4 address${NC}"
    else
        echo -e "${RED}✗ Device has NO WAN IPv4 address${NC}"
        echo -e "${YELLOW}  Possible causes:${NC}"
        echo -e "${YELLOW}    1. Network doesn't provide IPv4 DHCP (IPv6-only network)${NC}"
        echo -e "${YELLOW}    2. DHCPv4 request failed/timed out${NC}"
        echo -e "${YELLOW}    3. Firewall blocking DHCP requests${NC}"
        echo -e "${YELLOW}  Check gateway logs above for DHCP errors${NC}"
    fi

    if [ "$HAS_IPV6" = "yes" ]; then
        echo -e "${GREEN}✓ Device has IPv6 address${NC}"
    else
        echo -e "${RED}✗ Device has NO IPv6 address${NC}"
    fi
fi

echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "${YELLOW}  1. Check if network provides IPv4 DHCP (ask network team)${NC}"
echo -e "${YELLOW}  2. Review gateway logs for DHCP timeout/failure messages${NC}"
echo -e "${YELLOW}  3. Try manual DHCP request: dhclient -v -d -1 eth0${NC}"
echo ""
