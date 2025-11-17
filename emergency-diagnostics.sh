#!/bin/bash
# Emergency Gateway Diagnostics - Quick Status Check
# Run this to see what's broken

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}========================================${NC}"
echo -e "${RED}EMERGENCY GATEWAY DIAGNOSTICS${NC}"
echo -e "${RED}========================================${NC}"
echo ""

# 1. Check if service is running
echo -e "${YELLOW}[1/8] Checking service status...${NC}"
if ps | grep -v grep | grep -q "ipv4_ipv6_gateway.py"; then
    PID=$(ps | grep "ipv4_ipv6_gateway.py" | grep -v grep | awk '{print $1}')
    echo -e "${GREEN}  ✓ Service is RUNNING (PID: $PID)${NC}"
else
    echo -e "${RED}  ✗ Service is NOT RUNNING${NC}"
    echo -e "${YELLOW}  Start it: /etc/init.d/ipv4-ipv6-gateway start${NC}"
fi
echo ""

# 2. Check recent logs for errors
echo -e "${YELLOW}[2/8] Checking logs for errors...${NC}"
if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    ERROR_COUNT=$(tail -100 /var/log/ipv4-ipv6-gateway.log | grep -i "error\|exception\|traceback\|failed" | wc -l)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo -e "${RED}  ✗ Found $ERROR_COUNT errors in last 100 lines${NC}"
        echo -e "${YELLOW}  Recent errors:${NC}"
        tail -100 /var/log/ipv4-ipv6-gateway.log | grep -i "error\|exception\|traceback\|failed" | tail -5
    else
        echo -e "${GREEN}  ✓ No errors in last 100 lines${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ Log file not found${NC}"
fi
echo ""

# 3. Check device discovery
echo -e "${YELLOW}[3/8] Checking device discovery...${NC}"
if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    DISCOVERY_COUNT=$(grep -i "discovered device\|new device" /var/log/ipv4-ipv6-gateway.log | wc -l)
    echo -e "${BLUE}  Total devices discovered: $DISCOVERY_COUNT${NC}"

    if [ "$DISCOVERY_COUNT" -eq 0 ]; then
        echo -e "${YELLOW}  ⚠ No devices discovered yet${NC}"
        echo -e "${BLUE}    Connect a device to eth1 to trigger discovery${NC}"
    else
        echo -e "${GREEN}  ✓ Devices have been discovered${NC}"
        echo -e "${BLUE}  Recent discovery:${NC}"
        grep -i "discovered device\|new device" /var/log/ipv4-ipv6-gateway.log | tail -3
    fi
else
    echo -e "${YELLOW}  ⚠ Cannot check (log file missing)${NC}"
fi
echo ""

# 4. Check WAN IPv6
echo -e "${YELLOW}[4/8] Checking WAN IPv6...${NC}"
WAN_IPV6=$(ip -6 addr show eth0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print $2}' | head -1)
if [ -n "$WAN_IPV6" ]; then
    echo -e "${GREEN}  ✓ eth0 has IPv6: $WAN_IPV6${NC}"
else
    echo -e "${RED}  ✗ eth0 has NO global IPv6${NC}"
    echo -e "${YELLOW}    This is CRITICAL - gateway cannot work without IPv6!${NC}"
fi
echo ""

# 5. Check MAC spoofing
echo -e "${YELLOW}[5/8] Checking MAC address on eth0...${NC}"
CURRENT_MAC=$(ip link show eth0 2>/dev/null | grep -o 'link/ether [^ ]*' | awk '{print $2}')
if [ -n "$CURRENT_MAC" ]; then
    echo -e "${BLUE}  Current eth0 MAC: $CURRENT_MAC${NC}"

    # Check if it matches any device on LAN
    if ip neigh show dev eth1 2>/dev/null | grep -qi "$CURRENT_MAC"; then
        echo -e "${GREEN}  ✓ MAC appears to be spoofed (matches LAN device)${NC}"
    else
        echo -e "${YELLOW}  ⚠ MAC may be gateway's original MAC${NC}"
    fi
fi
echo ""

# 6. Check port forwarding
echo -e "${YELLOW}[6/8] Checking port forwarding rules...${NC}"
IPTABLES_RULES=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c "tcp dpt:80\|tcp dpt:8080")
if [ "$IPTABLES_RULES" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $IPTABLES_RULES port forwarding rule(s)${NC}"
else
    echo -e "${YELLOW}  ⚠ No port forwarding rules found${NC}"
    echo -e "${BLUE}    These are created when devices are discovered${NC}"
fi
echo ""

# 7. Check proxy processes
echo -e "${YELLOW}[7/8] Checking proxy processes (socat/haproxy)...${NC}"
SOCAT_COUNT=$(ps | grep -v grep | grep -c "socat")
HAPROXY_COUNT=$(ps | grep -v grep | grep -c "haproxy")

if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $SOCAT_COUNT socat process(es)${NC}"
elif [ "$HAPROXY_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $HAPROXY_COUNT haproxy process(es)${NC}"
else
    echo -e "${YELLOW}  ⚠ No proxy processes running${NC}"
    echo -e "${BLUE}    These start when devices are discovered${NC}"
fi
echo ""

# 8. Check ARP monitoring
echo -e "${YELLOW}[8/8] Checking ARP table on eth1...${NC}"
ARP_COUNT=$(ip neigh show dev eth1 2>/dev/null | grep -v "FAILED" | wc -l)
if [ "$ARP_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $ARP_COUNT device(s) in ARP table${NC}"
    ip neigh show dev eth1 2>/dev/null | grep -v "FAILED" | while read line; do
        DEV_IP=$(echo "$line" | awk '{print $1}')
        DEV_MAC=$(echo "$line" | grep -oP 'lladdr \K[0-9a-f:]+')
        echo -e "${BLUE}    • $DEV_IP - $DEV_MAC${NC}"
    done
else
    echo -e "${YELLOW}  ⚠ No devices in ARP table${NC}"
    echo -e "${BLUE}    Connect a device to eth1 and wait for DHCP${NC}"
fi
echo ""

# Summary
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}DIAGNOSIS SUMMARY${NC}"
echo -e "${YELLOW}========================================${NC}"

ISSUES=0

if ! ps | grep -v grep | grep -q "ipv4_ipv6_gateway.py"; then
    echo -e "${RED}✗ Service not running${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ -z "$WAN_IPV6" ]; then
    echo -e "${RED}✗ No IPv6 on eth0 (CRITICAL!)${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ "$DISCOVERY_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ No devices discovered yet${NC}"
fi

if [ "$IPTABLES_RULES" -eq 0 ]; then
    echo -e "${YELLOW}⚠ No port forwarding rules${NC}"
fi

if [ "$SOCAT_COUNT" -eq 0 ] && [ "$HAPROXY_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ No proxy processes running${NC}"
fi

echo ""

if [ "$ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✓ Gateway appears to be operational${NC}"
    echo -e "${BLUE}If devices still can't connect, check the full logs:${NC}"
    echo -e "${BLUE}  tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
else
    echo -e "${RED}Found $ISSUES critical issue(s)!${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Check logs: tail -100 /var/log/ipv4-ipv6-gateway.log"
    echo -e "  2. Restart service: /etc/init.d/ipv4-ipv6-gateway restart"
    echo -e "  3. Check IPv6: diagnose-ipv6.sh"
fi

echo ""
echo -e "${BLUE}For detailed analysis, view the full log:${NC}"
echo -e "${BLUE}  tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
echo ""
