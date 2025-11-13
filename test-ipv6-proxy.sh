#!/bin/bash
#
# IPv6 Proxy Test & Diagnostic Script
# Tests IPv6→IPv4 proxy connectivity and diagnoses issues
#

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv6→IPv4 Proxy Test & Diagnostic${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Target IPv6 address to test
TARGET_IPV6="dd56:fb82:64ad::7c79:7dff:fe45:3ad9"

if [ -n "$1" ]; then
    TARGET_IPV6="$1"
fi

echo -e "${BLUE}Testing IPv6: $TARGET_IPV6${NC}"
echo ""

# ============================================================
# Step 1: Check if IPv6 is assigned to eth0
# ============================================================
echo -e "${BLUE}=== Step 1: Check IPv6 on eth0 ===${NC}"
IPV6_ON_ETH0=$(ip -6 addr show eth0 | grep "$TARGET_IPV6")

if [ -n "$IPV6_ON_ETH0" ]; then
    echo -e "${GREEN}✓ IPv6 $TARGET_IPV6 is assigned to eth0${NC}"
    echo "$IPV6_ON_ETH0"
else
    echo -e "${RED}✗ IPv6 $TARGET_IPV6 NOT found on eth0!${NC}"
    echo ""
    echo "Current IPv6 addresses on eth0:"
    ip -6 addr show eth0 | grep "inet6" | grep -v "fe80"
    echo ""
    echo -e "${YELLOW}This is the problem! The proxy cannot bind to this IPv6.${NC}"
    echo ""
    echo "Possible causes:"
    echo "  1. DHCPv6/SLAAC didn't assign this address"
    echo "  2. Address was removed after assignment"
    echo "  3. Wrong IPv6 address (check gateway logs)"
    echo ""
    echo "Check gateway logs:"
    echo "  tail -50 /var/log/ipv4-ipv6-gateway.log | grep -E 'IPv6|WAN'"
    exit 1
fi
echo ""

# ============================================================
# Step 2: Check ICMPv6 Firewall Rules
# ============================================================
echo -e "${BLUE}=== Step 2: Check ICMPv6 Firewall Rules ===${NC}"
ICMPV6_RULES=$(ip6tables -L INPUT -n -v 2>/dev/null | grep -E "icmpv6|ICMPv6")

if [ -n "$ICMPV6_RULES" ]; then
    echo -e "${GREEN}✓ ICMPv6 rules exist:${NC}"
    echo "$ICMPV6_RULES" | head -5
else
    echo -e "${YELLOW}⚠ No ICMPv6 rules found (ping may fail)${NC}"
    echo "This is normal - IPv6 firewall may be fully open"
fi
echo ""

# ============================================================
# Step 3: Check Proxy NDP (Neighbor Discovery Proxy)
# ============================================================
echo -e "${BLUE}=== Step 3: Check Proxy NDP ===${NC}"
PROXY_NDP=$(ip -6 neigh show proxy | grep "$TARGET_IPV6")

if [ -n "$PROXY_NDP" ]; then
    echo -e "${GREEN}✓ Proxy NDP enabled for $TARGET_IPV6${NC}"
    echo "$PROXY_NDP"
else
    echo -e "${YELLOW}⚠ Proxy NDP NOT enabled for $TARGET_IPV6${NC}"
    echo ""
    echo "Proxy NDP allows the gateway to respond to Neighbor Discovery"
    echo "requests for this IPv6 address on behalf of the device."
    echo ""
    echo "Without it, other devices on the network can't discover this IPv6."
    echo ""
    echo -e "${YELLOW}Fix: Enable Proxy NDP${NC}"
    echo "  ip -6 neigh add proxy $TARGET_IPV6 dev eth0"
fi
echo ""

# ============================================================
# Step 4: Test Ping FROM Gateway
# ============================================================
echo -e "${BLUE}=== Step 4: Test Ping FROM Gateway (Local) ===${NC}"
echo "Pinging $TARGET_IPV6 from gateway itself..."

if ping6 -c 3 -W 2 "$TARGET_IPV6" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Gateway can ping $TARGET_IPV6 locally${NC}"
    ping6 -c 1 "$TARGET_IPV6" | head -2
else
    echo -e "${RED}✗ Gateway CANNOT ping $TARGET_IPV6 locally${NC}"
    echo ""
    echo "This is a critical issue. If the gateway can't ping this IPv6,"
    echo "then the proxy won't work either."
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check if device (192.168.1.x) is online"
    echo "  2. Check if device allows ICMPv6"
    echo "  3. Verify IPv6 is actually assigned to device"
fi
echo ""

# ============================================================
# Step 5: Check Socat/HAProxy Processes
# ============================================================
echo -e "${BLUE}=== Step 5: Check IPv6→IPv4 Proxy Processes ===${NC}"
SOCAT_PROCS=$(ps | grep "socat.*$TARGET_IPV6" | grep -v grep)
HAPROXY_PROCS=$(ps | grep haproxy | grep -v grep)

if [ -n "$SOCAT_PROCS" ]; then
    echo -e "${GREEN}✓ Socat proxies found:${NC}"
    echo "$SOCAT_PROCS"
elif [ -n "$HAPROXY_PROCS" ]; then
    echo -e "${GREEN}✓ HAProxy running:${NC}"
    echo "$HAPROXY_PROCS"
else
    echo -e "${RED}✗ No proxy processes found!${NC}"
    echo ""
    echo "This means IPv6→IPv4 proxy is NOT running."
    echo ""
    echo "Check gateway logs:"
    echo "  tail -50 /var/log/ipv4-ipv6-gateway.log | grep -E 'proxy|socat|haproxy'"
fi
echo ""

# ============================================================
# Step 6: Check Listening IPv6 Ports
# ============================================================
echo -e "${BLUE}=== Step 6: Check Listening IPv6 Ports ===${NC}"
echo "Ports listening on [$TARGET_IPV6]:"

if command -v netstat >/dev/null 2>&1; then
    LISTENING=$(netstat -ln | grep "\[$TARGET_IPV6\]" || netstat -ln | grep "$TARGET_IPV6")
    if [ -n "$LISTENING" ]; then
        echo -e "${GREEN}✓ Found listening ports:${NC}"
        echo "$LISTENING"
    else
        echo -e "${YELLOW}⚠ No ports listening on this IPv6 address${NC}"
    fi
elif command -v ss >/dev/null 2>&1; then
    LISTENING=$(ss -ln | grep "\[$TARGET_IPV6\]" || ss -ln | grep "$TARGET_IPV6")
    if [ -n "$LISTENING" ]; then
        echo -e "${GREEN}✓ Found listening ports:${NC}"
        echo "$LISTENING"
    else
        echo -e "${YELLOW}⚠ No ports listening on this IPv6 address${NC}"
    fi
else
    echo -e "${YELLOW}⚠ netstat/ss not available, can't check listening ports${NC}"
fi
echo ""

# ============================================================
# Step 7: Test HTTP Proxy (Port 80)
# ============================================================
echo -e "${BLUE}=== Step 7: Test HTTP Proxy (Port 80) ===${NC}"
echo "Testing: curl -v \"http://[$TARGET_IPV6]:80\" (5 second timeout)..."

if command -v curl >/dev/null 2>&1; then
    HTTP_RESULT=$(timeout 5 curl -v "http://[$TARGET_IPV6]:80" 2>&1 || true)

    if echo "$HTTP_RESULT" | grep -q "Connected to"; then
        echo -e "${GREEN}✓ HTTP proxy working! Connection successful${NC}"
        echo "$HTTP_RESULT" | grep -E "Connected to|HTTP"
    elif echo "$HTTP_RESULT" | grep -q "Connection refused"; then
        echo -e "${YELLOW}⚠ Connection refused (proxy not listening on port 80?)${NC}"
    elif echo "$HTTP_RESULT" | grep -q "No route to host"; then
        echo -e "${RED}✗ No route to host (routing/firewall issue)${NC}"
    elif echo "$HTTP_RESULT" | grep -q "timed out"; then
        echo -e "${RED}✗ Connection timed out${NC}"
    else
        echo -e "${YELLOW}⚠ Unexpected result:${NC}"
        echo "$HTTP_RESULT" | head -5
    fi
else
    echo -e "${YELLOW}⚠ curl not installed, skipping HTTP test${NC}"
fi
echo ""

# ============================================================
# Step 8: Test Telnet Proxy (Port 23)
# ============================================================
echo -e "${BLUE}=== Step 8: Test Telnet Proxy (Port 23) ===${NC}"
echo "Testing: nc -zv $TARGET_IPV6 23 (3 second timeout)..."

if command -v nc >/dev/null 2>&1; then
    TELNET_RESULT=$(timeout 3 nc -zv "$TARGET_IPV6" 23 2>&1 || true)

    if echo "$TELNET_RESULT" | grep -q "succeeded\|open"; then
        echo -e "${GREEN}✓ Telnet proxy working! Port 23 is open${NC}"
        echo "$TELNET_RESULT"
    elif echo "$TELNET_RESULT" | grep -q "refused"; then
        echo -e "${YELLOW}⚠ Connection refused (proxy not listening on port 23?)${NC}"
    else
        echo -e "${YELLOW}⚠ Port 23 test result:${NC}"
        echo "$TELNET_RESULT"
    fi
else
    echo -e "${YELLOW}⚠ nc (netcat) not installed, skipping telnet test${NC}"
fi
echo ""

# ============================================================
# Step 9: Gateway Device Info
# ============================================================
echo -e "${BLUE}=== Step 9: Check Gateway Device Info ===${NC}"
echo "Checking device configuration from gateway..."

if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    echo "Devices configured on gateway:"
    cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | grep -A 10 "$TARGET_IPV6" || \
    cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null
else
    echo -e "${YELLOW}⚠ devices.json not found${NC}"
    echo "Gateway may not have configured any devices yet"
fi
echo ""

# ============================================================
# Summary & Recommendations
# ============================================================
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Summary & Recommendations${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${YELLOW}Why Can't I Ping This IPv6?${NC}"
echo ""
echo "1. ${BLUE}Ping (ICMPv6) may be blocked by firewall${NC}"
echo "   - IPv6 firewall on gateway or device may drop ICMPv6"
echo "   - This is normal - focus on testing actual services (HTTP, Telnet)"
echo ""

echo "2. ${BLUE}Proxy NDP may not be enabled${NC}"
echo "   - Other devices can't discover this IPv6 without Proxy NDP"
echo "   - Enable: ip -6 neigh add proxy $TARGET_IPV6 dev eth0"
echo ""

echo -e "${YELLOW}How to Test IPv6→IPv4 Proxy:${NC}"
echo ""
echo "From another device on the network (192.168.8.x):"
echo ""
echo "  # Test HTTP (port 80)"
echo "  curl -v \"http://[$TARGET_IPV6]:80\""
echo ""
echo "  # Test Telnet (port 23)"
echo "  telnet $TARGET_IPV6 23"
echo ""
echo "  # Test with nc (netcat)"
echo "  nc -zv $TARGET_IPV6 80"
echo "  nc -zv $TARGET_IPV6 23"
echo ""

echo -e "${YELLOW}Quick Fixes:${NC}"
echo ""
echo "# Enable Proxy NDP"
echo "ip -6 neigh add proxy $TARGET_IPV6 dev eth0"
echo ""
echo "# Allow all ICMPv6 (for testing)"
echo "ip6tables -I INPUT -p icmpv6 -j ACCEPT"
echo "ip6tables -I FORWARD -p icmpv6 -j ACCEPT"
echo ""
echo "# Check gateway logs"
echo "tail -50 /var/log/ipv4-ipv6-gateway.log"
echo ""

echo -e "${GREEN}========================================${NC}"
