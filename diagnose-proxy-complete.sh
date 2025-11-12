#!/bin/bash
#
# Complete IPv6→IPv4 Proxy Diagnostic Script
# Identifies ALL potential issues preventing proxy from working
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

DEVICE_IPV6="${1:-2620:10d:c050:100:46b7:d0ff:fea6:6dfc}"
DEVICE_IPV4="${2:-192.168.1.128}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Complete IPv6→IPv4 Proxy Diagnostics${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${CYAN}Target Device:${NC}"
echo -e "  IPv6: ${DEVICE_IPV6}"
echo -e "  IPv4: ${DEVICE_IPV4}"
echo ""

ISSUES_FOUND=0

# ============================================
# 1. CHECK IF IPv6 ADDRESS EXISTS ON eth0
# ============================================
echo -e "${YELLOW}[1] Checking if IPv6 address is configured on eth0...${NC}"
if ip -6 addr show eth0 | grep -q "$DEVICE_IPV6"; then
    echo -e "${GREEN}✓ IPv6 address $DEVICE_IPV6 is present on eth0${NC}"
else
    echo -e "${RED}✗ IPv6 address $DEVICE_IPV6 NOT found on eth0${NC}"
    echo -e "${YELLOW}  Current IPv6 addresses on eth0:${NC}"
    ip -6 addr show eth0 | grep "inet6" | grep -v "fe80::"
    echo ""
    echo -e "${CYAN}  FIX: Add IPv6 address to eth0${NC}"
    echo -e "    ${BLUE}ip -6 addr add $DEVICE_IPV6/64 dev eth0${NC}"
    echo -e "    ${BLUE}ip -6 neigh add proxy $DEVICE_IPV6 dev eth0${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# ============================================
# 2. CHECK IF PORTS ARE ALREADY IN USE
# ============================================
echo -e "${YELLOW}[2] Checking if ports 80 and 23 are available on IPv6...${NC}"

# Check port 80
PORT_80_IN_USE=$(netstat -tlnp 2>/dev/null | grep -E ':80 ' || ss -tlnp 2>/dev/null | grep -E ':80 ')
if echo "$PORT_80_IN_USE" | grep -q "tcp6.*:80"; then
    echo -e "${RED}✗ Port 80 (IPv6) is already in use!${NC}"
    echo -e "${YELLOW}  Processes using port 80:${NC}"
    echo "$PORT_80_IN_USE" | grep ":80"
    echo ""
    echo -e "${CYAN}  This could be:${NC}"
    echo -e "    - LuCI web interface (OpenWrt)"
    echo -e "    - Another socat process"
    echo -e "    - uhttpd or nginx"
    echo -e "${CYAN}  FIX: Stop the conflicting service${NC}"
    echo -e "    ${BLUE}/etc/init.d/uhttpd stop${NC}  # If it's OpenWrt web UI"
    echo -e "    ${BLUE}killall socat${NC}             # If it's old socat process"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✓ Port 80 (IPv6) is available${NC}"
fi

# Check port 23
PORT_23_IN_USE=$(netstat -tlnp 2>/dev/null | grep -E ':23 ' || ss -tlnp 2>/dev/null | grep -E ':23 ')
if echo "$PORT_23_IN_USE" | grep -q "tcp6.*:23"; then
    echo -e "${RED}✗ Port 23 (IPv6) is already in use!${NC}"
    echo -e "${YELLOW}  Processes using port 23:${NC}"
    echo "$PORT_23_IN_USE" | grep ":23"
    echo ""
    echo -e "${CYAN}  FIX: Stop the conflicting service${NC}"
    echo -e "    ${BLUE}killall telnetd${NC}  # If it's telnet daemon"
    echo -e "    ${BLUE}killall socat${NC}    # If it's old socat process"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✓ Port 23 (IPv6) is available${NC}"
fi
echo ""

# ============================================
# 3. CHECK IF SOCAT PROCESSES ARE RUNNING
# ============================================
echo -e "${YELLOW}[3] Checking if socat proxy processes are running...${NC}"
SOCAT_PROCS=$(ps w | grep socat | grep -v grep)
if [ -n "$SOCAT_PROCS" ]; then
    echo -e "${GREEN}✓ Found socat processes:${NC}"
    echo "$SOCAT_PROCS" | while read line; do
        echo -e "  ${CYAN}$line${NC}"
    done

    # Check if they're binding to the correct IPv6
    if echo "$SOCAT_PROCS" | grep -q "$DEVICE_IPV6"; then
        echo -e "${GREEN}✓ socat is binding to correct IPv6: $DEVICE_IPV6${NC}"
    else
        echo -e "${RED}✗ socat is NOT binding to $DEVICE_IPV6${NC}"
        echo -e "${YELLOW}  socat might be binding to wrong address${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    echo -e "${RED}✗ NO socat processes running!${NC}"
    echo -e "${YELLOW}  This is the main problem - proxy is not started${NC}"
    echo ""
    echo -e "${CYAN}  FIX: Start socat manually${NC}"
    echo -e "    ${BLUE}# For HTTP (port 80)${NC}"
    echo -e "    ${BLUE}socat -d -d TCP6-LISTEN:80,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:80 &${NC}"
    echo -e "    ${BLUE}# For Telnet (port 23)${NC}"
    echo -e "    ${BLUE}socat -d -d TCP6-LISTEN:23,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:23 &${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# ============================================
# 4. CHECK SOCAT INSTALLATION
# ============================================
echo -e "${YELLOW}[4] Checking if socat is installed...${NC}"
if command -v socat >/dev/null 2>&1; then
    SOCAT_VERSION=$(socat -V 2>&1 | head -1)
    echo -e "${GREEN}✓ socat is installed: $SOCAT_VERSION${NC}"
else
    echo -e "${RED}✗ socat is NOT installed${NC}"
    echo -e "${CYAN}  FIX: Install socat${NC}"
    echo -e "    ${BLUE}opkg update${NC}"
    echo -e "    ${BLUE}opkg install socat${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# ============================================
# 5. CHECK IPv6 FIREWALL RULES
# ============================================
echo -e "${YELLOW}[5] Checking IPv6 firewall (ip6tables)...${NC}"

# Check INPUT chain
INPUT_POLICY=$(ip6tables -L INPUT -n 2>/dev/null | head -1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
if [ "$INPUT_POLICY" = "DROP" ] || [ "$INPUT_POLICY" = "REJECT" ]; then
    echo -e "${RED}✗ IPv6 INPUT policy is $INPUT_POLICY (blocking!)${NC}"
    echo -e "${CYAN}  FIX: Allow IPv6 input${NC}"
    echo -e "    ${BLUE}ip6tables -P INPUT ACCEPT${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✓ IPv6 INPUT policy: ${INPUT_POLICY:-ACCEPT}${NC}"
fi

# Check FORWARD chain
FORWARD_POLICY=$(ip6tables -L FORWARD -n 2>/dev/null | head -1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
if [ "$FORWARD_POLICY" = "DROP" ] || [ "$FORWARD_POLICY" = "REJECT" ]; then
    echo -e "${RED}✗ IPv6 FORWARD policy is $FORWARD_POLICY (blocking!)${NC}"
    echo -e "${CYAN}  FIX: Allow IPv6 forwarding${NC}"
    echo -e "    ${BLUE}ip6tables -P FORWARD ACCEPT${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✓ IPv6 FORWARD policy: ${FORWARD_POLICY:-ACCEPT}${NC}"
fi

# Check for specific blocking rules
BLOCKING_RULES=$(ip6tables -L INPUT -n --line-numbers 2>/dev/null | grep -E 'DROP|REJECT' | head -5)
if [ -n "$BLOCKING_RULES" ]; then
    echo -e "${YELLOW}⚠ Found potential blocking rules in INPUT chain:${NC}"
    echo "$BLOCKING_RULES" | while read line; do
        echo -e "  ${CYAN}$line${NC}"
    done
fi
echo ""

# ============================================
# 6. CHECK CONNECTIVITY TO DEVICE (IPv4)
# ============================================
echo -e "${YELLOW}[6] Checking connectivity to device via IPv4...${NC}"

# Ping test
if ping -c 2 -W 2 "$DEVICE_IPV4" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Can ping device at $DEVICE_IPV4${NC}"
else
    echo -e "${RED}✗ Cannot ping device at $DEVICE_IPV4${NC}"
    echo -e "${YELLOW}  Device might be offline or unreachable${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# HTTP test (port 80)
if timeout 3 nc -z "$DEVICE_IPV4" 80 2>/dev/null; then
    echo -e "${GREEN}✓ Device port 80 (HTTP) is reachable${NC}"
else
    echo -e "${RED}✗ Device port 80 (HTTP) is NOT reachable${NC}"
    echo -e "${YELLOW}  HTTP service might not be running on device${NC}"
fi

# Telnet test (port 23)
if timeout 3 nc -z "$DEVICE_IPV4" 23 2>/dev/null; then
    echo -e "${GREEN}✓ Device port 23 (Telnet) is reachable${NC}"
else
    echo -e "${RED}✗ Device port 23 (Telnet) is NOT reachable${NC}"
    echo -e "${YELLOW}  Telnet service might not be running on device${NC}"
fi
echo ""

# ============================================
# 7. CHECK GATEWAY LOGS FOR ERRORS
# ============================================
echo -e "${YELLOW}[7] Checking gateway logs for socat/proxy errors...${NC}"
if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    SOCAT_ERRORS=$(tail -100 /var/log/ipv4-ipv6-gateway.log | grep -iE "socat.*error|socat.*fail|bind.*fail|cannot bind")
    if [ -n "$SOCAT_ERRORS" ]; then
        echo -e "${RED}✗ Found socat errors in logs:${NC}"
        echo "$SOCAT_ERRORS" | tail -10 | while read line; do
            echo -e "  ${YELLOW}$line${NC}"
        done
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    else
        echo -e "${GREEN}✓ No obvious socat errors in recent logs${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Gateway log file not found${NC}"
fi
echo ""

# ============================================
# 8. CHECK PROXY NDP
# ============================================
echo -e "${YELLOW}[8] Checking Proxy NDP for IPv6...${NC}"
if ip -6 neigh show proxy | grep -q "$DEVICE_IPV6"; then
    echo -e "${GREEN}✓ Proxy NDP is configured for $DEVICE_IPV6${NC}"
else
    echo -e "${RED}✗ Proxy NDP is NOT configured for $DEVICE_IPV6${NC}"
    echo -e "${YELLOW}  Upstream routers won't know how to reach this IPv6${NC}"
    echo ""
    echo -e "${CYAN}  FIX: Enable Proxy NDP${NC}"
    echo -e "    ${BLUE}ip -6 neigh add proxy $DEVICE_IPV6 dev eth0${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# ============================================
# 9. CHECK IPv6 DAD (Duplicate Address Detection)
# ============================================
echo -e "${YELLOW}[9] Checking IPv6 DAD status...${NC}"
DAD_STATUS=$(ip -6 addr show eth0 | grep "$DEVICE_IPV6" | grep -o 'tentative\|dadfailed')
if [ -n "$DAD_STATUS" ]; then
    echo -e "${RED}✗ IPv6 address is in $DAD_STATUS state${NC}"
    echo -e "${YELLOW}  Address is not ready for use yet${NC}"
    echo -e "${CYAN}  FIX: Wait a few seconds for DAD to complete, or:${NC}"
    echo -e "    ${BLUE}# Disable DAD (risky!)${NC}"
    echo -e "    ${BLUE}sysctl -w net.ipv6.conf.eth0.accept_dad=0${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✓ IPv6 DAD completed (address is ready)${NC}"
fi
echo ""

# ============================================
# 10. CHECK UPSTREAM NETWORK FIREWALL
# ============================================
echo -e "${YELLOW}[10] Checking upstream network accessibility...${NC}"
echo -e "${CYAN}Testing if upstream allows connections to IPv6 ports...${NC}"

# Get gateway's own IPv6 address
GATEWAY_IPV6=$(ip -6 addr show eth0 | grep "inet6" | grep -v "fe80::" | head -1 | awk '{print $2}' | cut -d/ -f1)
if [ -n "$GATEWAY_IPV6" ]; then
    echo -e "${CYAN}Gateway IPv6: $GATEWAY_IPV6${NC}"
    echo -e "${YELLOW}⚠ Cannot test from gateway itself${NC}"
    echo -e "${YELLOW}  Test from your devvm:${NC}"
    echo -e "    ${BLUE}curl -6 -v --connect-timeout 5 http://[$DEVICE_IPV6]${NC}"
    echo -e "    ${BLUE}telnet $DEVICE_IPV6 23${NC}"
else
    echo -e "${YELLOW}⚠ Gateway has no global IPv6 address${NC}"
fi
echo ""

# ============================================
# SUMMARY AND RECOMMENDATIONS
# ============================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ No obvious issues found!${NC}"
    echo ""
    echo -e "${CYAN}If proxy still doesn't work:${NC}"
    echo -e "  1. Run packet capture to see if traffic arrives:"
    echo -e "     ${BLUE}./capture-traffic.sh${NC}"
    echo -e "  2. Test from your devvm:"
    echo -e "     ${BLUE}curl -6 -v http://[$DEVICE_IPV6]${NC}"
    echo -e "  3. Check if upstream firewall blocks these ports"
    echo -e "     (Your network might only allow specific IPv6 ports)"
else
    echo -e "${RED}Found $ISSUES_FOUND issue(s) that need fixing${NC}"
    echo ""
    echo -e "${CYAN}Quick fix script:${NC}"
    echo ""

    # Generate fix commands
    if ! ip -6 addr show eth0 | grep -q "$DEVICE_IPV6"; then
        echo -e "${BLUE}# Add IPv6 address to eth0${NC}"
        echo "ip -6 addr add $DEVICE_IPV6/64 dev eth0"
        echo "ip -6 neigh add proxy $DEVICE_IPV6 dev eth0"
        echo ""
    fi

    if [ -z "$SOCAT_PROCS" ]; then
        echo -e "${BLUE}# Start socat proxies (no source binding)${NC}"
        echo "socat -d -d TCP6-LISTEN:80,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:80 &"
        echo "socat -d -d TCP6-LISTEN:23,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:23 &"
        echo ""
    fi

    if [ "$INPUT_POLICY" = "DROP" ] || [ "$INPUT_POLICY" = "REJECT" ]; then
        echo -e "${BLUE}# Fix firewall${NC}"
        echo "ip6tables -P INPUT ACCEPT"
        echo "ip6tables -P FORWARD ACCEPT"
        echo ""
    fi

    echo -e "${CYAN}Copy-paste ready fix:${NC}"
    echo -e "${YELLOW}────────────────────────────────────────${NC}"
    cat << EOF
# Complete fix script (NO source binding - kernel chooses best route!)
ip -6 addr add $DEVICE_IPV6/64 dev eth0 2>/dev/null || true
ip -6 neigh add proxy $DEVICE_IPV6 dev eth0 2>/dev/null || true
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
killall socat 2>/dev/null || true
sleep 2
socat -d -d TCP6-LISTEN:80,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:80 &
socat -d -d TCP6-LISTEN:23,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:23 &
sleep 2
ps | grep socat | grep -v grep
EOF
    echo -e "${YELLOW}────────────────────────────────────────${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
