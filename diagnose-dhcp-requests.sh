#!/bin/sh
#
# DHCP Request Diagnostic Script
# Checks if gateway is properly requesting IPv4 and IPv6 addresses
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

printf "${YELLOW}========================================${NC}\n"
printf "${YELLOW}DHCP Request Diagnostic${NC}\n"
printf "${YELLOW}========================================${NC}\n"
printf "\n"

# Check devices.json
printf "${BLUE}1. Checking devices.json...${NC}\n"
if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    printf "${GREEN}✓ devices.json exists${NC}\n"
    printf "\n"
    cat /etc/ipv4-ipv6-gateway/devices.json | python3 -m json.tool
    printf "\n"
else
    printf "${RED}✗ devices.json not found${NC}\n"
fi

# Check gateway logs for DHCP
printf "${BLUE}2. Checking gateway logs for DHCP requests...${NC}\n"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    printf "${YELLOW}Last 50 DHCPv4 log entries:${NC}\n"
    grep -i "dhcpv4" /var/log/ipv4-ipv6-gateway.log | tail -50
    printf "\n"

    printf "${YELLOW}Last 50 DHCPv6 log entries:${NC}\n"
    grep -i "dhcpv6" /var/log/ipv4-ipv6-gateway.log | tail -50
    printf "\n"

    printf "${YELLOW}DHCP failures/errors:${NC}\n"
    grep -iE "(dhcp.*fail|dhcp.*error|dhcp.*timeout)" /var/log/ipv4-ipv6-gateway.log | tail -20
    printf "\n"
else
    printf "${RED}✗ Gateway log not found${NC}\n"
fi

# Check eth0 addresses
printf "${BLUE}3. Checking eth0 addresses (WAN)...${NC}\n"
printf "${YELLOW}IPv4 addresses:${NC}\n"
ip -4 addr show eth0 | grep inet || printf "  (None)\n"
printf "\n"
printf "${YELLOW}IPv6 addresses:${NC}\n"
ip -6 addr show eth0 | grep inet6 || printf "  (None)\n"
printf "\n"

# Check eth1 addresses
printf "${BLUE}4. Checking eth1 addresses (LAN)...${NC}\n"
printf "${YELLOW}IPv4 addresses:${NC}\n"
ip -4 addr show eth1 | grep inet || printf "  (None)\n"
printf "\n"
printf "${YELLOW}IPv6 addresses:${NC}\n"
ip -6 addr show eth1 | grep inet6 || printf "  (None)\n"
printf "\n"

# Check ARP table (devices on LAN)
printf "${BLUE}5. Checking ARP table (devices on eth1/LAN)...${NC}\n"
arp -n | grep eth1
printf "\n"

# Check if DHCP client processes are running
printf "${BLUE}6. Checking for DHCP client processes...${NC}\n"
printf "${YELLOW}udhcpc (IPv4 DHCP client):${NC}\n"
ps | grep udhcpc | grep -v grep || printf "  (None running)\n"
printf "\n"
printf "${YELLOW}dhclient (Alternative IPv4/IPv6 DHCP client):${NC}\n"
ps | grep dhclient | grep -v grep || printf "  (None running)\n"
printf "\n"
printf "${YELLOW}odhcp6c (IPv6 DHCP client):${NC}\n"
ps | grep odhcp6c | grep -v grep || printf "  (None running)\n"
printf "\n"

# Check if gateway service is running
printf "${BLUE}7. Checking if gateway service is running...${NC}\n"
SERVICE_PID=$(ps | grep "ipv4_ipv6_gateway.py" | grep -v grep | awk '{print $1}' | head -1)
if [ -n "$SERVICE_PID" ]; then
    printf "${GREEN}✓ Gateway service is running (PID: $SERVICE_PID)${NC}\n"
else
    printf "${RED}✗ Gateway service NOT running${NC}\n"
    printf "${YELLOW}  Fix: /etc/init.d/ipv4-ipv6-gateway start${NC}\n"
fi
printf "\n"

# Check network connectivity
printf "${BLUE}8. Testing network connectivity...${NC}\n"
printf "${YELLOW}Ping Google DNS (IPv4 - 8.8.8.8):${NC}\n"
ping -c 2 -W 2 8.8.8.8 2>&1 | tail -2 || printf "  FAILED\n"
printf "\n"
printf "${YELLOW}Ping Google DNS (IPv6 - 2001:4860:4860::8888):${NC}\n"
ping6 -c 2 -W 2 2001:4860:4860::8888 2>&1 | tail -2 || printf "  FAILED\n"
printf "\n"

# Summary
printf "${YELLOW}========================================${NC}\n"
printf "${YELLOW}Summary & Recommendations${NC}\n"
printf "${YELLOW}========================================${NC}\n"

# Parse devices.json to check if device has IPv4 WAN
if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    HAS_IPV4_WAN=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; d=json.load(sys.stdin); print('yes' if any(v.get('ipv4_wan_address') for v in d.values()) else 'no')" 2>/dev/null)
    HAS_IPV6=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; d=json.load(sys.stdin); print('yes' if any(v.get('ipv6_address') for v in d.values()) else 'no')" 2>/dev/null)

    if [ "$HAS_IPV4_WAN" = "yes" ]; then
        printf "${GREEN}✓ Device has WAN IPv4 address${NC}\n"
    else
        printf "${RED}✗ Device has NO WAN IPv4 address${NC}\n"
        printf "${YELLOW}  Possible causes:${NC}\n"
        printf "${YELLOW}    1. Network doesn't provide IPv4 DHCP (IPv6-only network)${NC}\n"
        printf "${YELLOW}    2. DHCPv4 request failed/timed out${NC}\n"
        printf "${YELLOW}    3. Firewall blocking DHCP requests${NC}\n"
        printf "${YELLOW}  Check gateway logs above for DHCP errors${NC}\n"
    fi

    if [ "$HAS_IPV6" = "yes" ]; then
        printf "${GREEN}✓ Device has IPv6 address${NC}\n"
    else
        printf "${RED}✗ Device has NO IPv6 address${NC}\n"
    fi
fi

printf "\n"
printf "${BLUE}Next steps:${NC}\n"
printf "${YELLOW}  1. Check if network provides IPv4 DHCP (ask network team)${NC}\n"
printf "${YELLOW}  2. Review gateway logs for DHCP timeout/failure messages${NC}\n"
printf "${YELLOW}  3. Try manual DHCP request: dhclient -v -d -1 eth0${NC}\n"
printf "\n"
