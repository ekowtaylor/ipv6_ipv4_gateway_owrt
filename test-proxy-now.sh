#!/bin/bash
#
# Quick Proxy Test Script - Run this on gateway after fix
# Tests IPv6→IPv4 proxy on STANDARD ports (80, 23, 5000)
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6→IPv4 Proxy Test (Standard Ports)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Check gateway service
echo -e "${YELLOW}[1] Checking gateway service...${NC}"
if ps | grep -q "python.*ipv4_ipv6_gateway\.py" | grep -v grep; then
    echo -e "${GREEN}✓ Gateway service is running${NC}"
else
    echo -e "${RED}✗ Gateway service is NOT running!${NC}"
    echo -e "${CYAN}  Start it with: /etc/init.d/ipv4-ipv6-gateway start${NC}"
    exit 1
fi
echo ""

# Step 2: Get device info
echo -e "${YELLOW}[2] Getting device information...${NC}"
DEVICE_MAC=""
DEVICE_IPV4=""
DEVICE_IPV6=""

if command -v curl >/dev/null 2>&1; then
    API_OUTPUT=$(curl -s http://localhost:5050/devices 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$API_OUTPUT" ]; then
        DEVICE_MAC=$(echo "$API_OUTPUT" | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.keys())[0] if data else '')" 2>/dev/null || echo "")
        DEVICE_IPV4=$(echo "$API_OUTPUT" | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.values())[0].get('ipv4_address', '') if data else '')" 2>/dev/null || echo "")
        DEVICE_IPV6=$(echo "$API_OUTPUT" | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.values())[0].get('ipv6_address', '') if data else '')" 2>/dev/null || echo "")
    fi
fi

# Fallback to devices.json if API doesn't work
if [ -z "$DEVICE_IPV4" ] && [ -f /etc/ipv4-ipv6-gateway/devices.json ]; then
    echo -e "${YELLOW}  API unavailable, reading from devices.json...${NC}"
    DEVICE_MAC=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.keys())[0] if data else '')" 2>/dev/null || echo "")
    DEVICE_IPV4=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.values())[0].get('ipv4_address', '') if data else '')" 2>/dev/null || echo "")
    DEVICE_IPV6=$(cat /etc/ipv4-ipv6-gateway/devices.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(list(data.values())[0].get('ipv6_address', '') if data else '')" 2>/dev/null || echo "")
fi

if [ -z "$DEVICE_IPV4" ] || [ -z "$DEVICE_IPV6" ]; then
    echo -e "${RED}✗ Could not get device information!${NC}"
    echo -e "${YELLOW}  Make sure a device is connected and discovered${NC}"
    exit 1
fi

echo -e "${CYAN}  MAC:  ${DEVICE_MAC}${NC}"
echo -e "${CYAN}  IPv4: ${DEVICE_IPV4}${NC}"
echo -e "${CYAN}  IPv6: ${DEVICE_IPV6}${NC}"
echo ""

# Step 3: Check socat processes
echo -e "${YELLOW}[3] Checking socat proxy processes...${NC}"
SOCAT_COUNT=$(ps w | grep socat | grep -v grep | wc -l)
echo -e "${CYAN}  Found ${SOCAT_COUNT} socat process(es)${NC}"
echo ""
echo -e "${BLUE}Active socat proxies:${NC}"
ps w | grep socat | grep -v grep | while read line; do
    echo -e "  ${CYAN}$line${NC}"
done
echo ""

# Step 4: Check specific ports
echo -e "${YELLOW}[4] Checking proxy ports...${NC}"
PORTS_CHECKED=0
PORTS_OK=0

for PORT in 80 23 5000; do
    PORTS_CHECKED=$((PORTS_CHECKED + 1))

    # Check if socat is listening on this port with device IPv6
    if ps w | grep socat | grep -q "TCP6-LISTEN:${PORT}.*${DEVICE_IPV6%%,*}"; then
        echo -e "${GREEN}✓ Port ${PORT}: Proxy active on IPv6${NC}"

        # Show the full command
        PROXY_CMD=$(ps w | grep socat | grep "TCP6-LISTEN:${PORT}" | grep "${DEVICE_IPV6%%,*}" | head -1)
        echo -e "${CYAN}  Command: $(echo "$PROXY_CMD" | awk '{for(i=5;i<=NF;i++)printf "%s ", $i; print ""}'
)${NC}"

        PORTS_OK=$((PORTS_OK + 1))
    else
        echo -e "${RED}✗ Port ${PORT}: NO proxy found!${NC}"
        echo -e "${YELLOW}  Expected: TCP6-LISTEN:${PORT},bind=${DEVICE_IPV6%%,*}...TCP4:${DEVICE_IPV4}:${PORT}${NC}"
    fi
    echo ""
done

# Step 5: Check IPv6 address on eth0
echo -e "${YELLOW}[5] Checking IPv6 address on eth0...${NC}"
if ip -6 addr show eth0 | grep -q "${DEVICE_IPV6%%,*}"; then
    echo -e "${GREEN}✓ Device IPv6 is configured on eth0${NC}"
else
    echo -e "${RED}✗ Device IPv6 NOT found on eth0!${NC}"
    echo -e "${YELLOW}  Current IPv6 addresses:${NC}"
    ip -6 addr show eth0 | grep "inet6" | grep -v "fe80::"
fi
echo ""

# Step 6: Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ $PORTS_OK -eq $PORTS_CHECKED ]; then
    echo -e "${GREEN}✓ All ${PORTS_CHECKED} ports are proxied correctly!${NC}"
    echo ""
    echo -e "${CYAN}Test from your devvm:${NC}"
    echo ""
    echo -e "${BLUE}# HTTP (port 80)${NC}"
    echo -e "  curl -6 -v http://[${DEVICE_IPV6%%,*}]"
    echo ""
    echo -e "${BLUE}# HTTP (port 5000)${NC}"
    echo -e "  curl -6 -v http://[${DEVICE_IPV6%%,*}]:5000"
    echo ""
    echo -e "${BLUE}# Telnet (port 23)${NC}"
    echo -e "  telnet ${DEVICE_IPV6%%,*} 23"
    echo ""
else
    echo -e "${RED}✗ Only ${PORTS_OK}/${PORTS_CHECKED} ports are working${NC}"
    echo ""
    echo -e "${CYAN}Troubleshooting:${NC}"
    echo ""
    echo -e "${YELLOW}1. Check gateway logs:${NC}"
    echo "   tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i socat"
    echo ""
    echo -e "${YELLOW}2. Restart gateway service:${NC}"
    echo "   /etc/init.d/ipv4-ipv6-gateway restart"
    echo "   sleep 5"
    echo "   $0  # Run this test again"
    echo ""
    echo -e "${YELLOW}3. Check socat errors:${NC}"
    echo "   tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i error"
    echo ""
fi

echo -e "${BLUE}========================================${NC}"
