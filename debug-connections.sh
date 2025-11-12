#!/bin/sh
#
# Debug Connections - Comprehensive connection debugging
# Shows ALL gateway activity, not just socat
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6 Connection Debugger${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if socat processes are running
echo -e "${YELLOW}Checking socat processes...${NC}"
SOCAT_PROCS=$(ps | grep -E 'socat.*TCP6-LISTEN' | grep -v grep)
if [ -n "$SOCAT_PROCS" ]; then
    echo -e "${GREEN}✓ Socat processes running:${NC}"
    echo "$SOCAT_PROCS" | while read line; do
        echo -e "  ${GREEN}${line}${NC}"
    done
    echo ""
else
    echo -e "${RED}✗ No socat processes found!${NC}"
    echo -e "${YELLOW}This means IPv6→IPv4 proxies are NOT running.${NC}"
    echo ""
    echo -e "${YELLOW}Check why proxies didn't start:${NC}"
    echo "  tail -100 /var/log/ipv4-ipv6-gateway.log | grep -E 'proxy|socat|IPv6'"
    echo ""
fi

# Check listening IPv6 ports
echo -e "${YELLOW}Checking IPv6 listening ports...${NC}"
if command -v netstat >/dev/null 2>&1; then
    IPV6_LISTENERS=$(netstat -tlnp 2>/dev/null | grep -E '::.*LISTEN')
    if [ -n "$IPV6_LISTENERS" ]; then
        echo -e "${GREEN}✓ IPv6 listening sockets:${NC}"
        echo "$IPV6_LISTENERS"
    else
        echo -e "${RED}✗ No IPv6 listening sockets found!${NC}"
    fi
else
    echo -e "${YELLOW}netstat not available, trying ss...${NC}"
    IPV6_LISTENERS=$(ss -tlnp 2>/dev/null | grep -E '::.*LISTEN')
    if [ -n "$IPV6_LISTENERS" ]; then
        echo -e "${GREEN}✓ IPv6 listening sockets:${NC}"
        echo "$IPV6_LISTENERS"
    else
        echo -e "${RED}✗ No IPv6 listening sockets found!${NC}"
    fi
fi
echo ""

# Check IPv6 firewall rules
echo -e "${YELLOW}Checking IPv6 firewall (ip6tables)...${NC}"
if command -v ip6tables >/dev/null 2>&1; then
    INPUT_RULES=$(ip6tables -L INPUT -n -v 2>/dev/null | grep -E 'tcp|ACCEPT|REJECT|DROP' | head -10)
    if [ -n "$INPUT_RULES" ]; then
        echo -e "${CYAN}ip6tables INPUT rules (first 10):${NC}"
        echo "$INPUT_RULES"
    else
        echo -e "${YELLOW}No specific IPv6 firewall rules found${NC}"
    fi
else
    echo -e "${YELLOW}ip6tables not available${NC}"
fi
echo ""

# Show IPv6 addresses on eth0
echo -e "${YELLOW}IPv6 addresses on eth0:${NC}"
IPV6_ADDRS=$(ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80')
if [ -n "$IPV6_ADDRS" ]; then
    echo -e "${GREEN}${IPV6_ADDRS}${NC}"
else
    echo -e "${RED}✗ No global IPv6 addresses on eth0!${NC}"
fi
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Real-time Log Monitor${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Watching ALL gateway logs (Ctrl+C to stop)..."
echo ""

# Tail the log with NO filtering - show EVERYTHING
tail -f /var/log/ipv4-ipv6-gateway.log
