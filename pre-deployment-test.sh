#!/bin/sh
#
# Pre-Deployment Gateway Test
# Run this from the router console before connecting production devices
#

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

echo "========================================"
echo "Pre-Deployment Gateway Test"
echo "========================================"
echo ""

check() {
    if eval "$2"; then
        echo -e "${GREEN}✓${NC} $1"
        PASS=$((PASS + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $1"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Network Configuration Checks
echo "Network Configuration:"
check "eth1 has 192.168.1.1/24" "ip addr show eth1 | grep -q '192.168.1.1/24'"
check "eth1 interface is UP" "ip link show eth1 | grep -q 'state UP'"
check "eth0 interface exists" "ip link show eth0 >/dev/null 2>&1"
check "Routing table has 192.168.1.0/24" "ip route | grep -q '192.168.1.0/24'"
echo ""

# Service Checks
echo "Services:"
check "Gateway service is running" "ps | grep -q '[i]pv4_ipv6_gateway'"
check "DHCP server (dnsmasq) is running" "ps | grep -q '[d]nsmasq'"
echo ""

# API Checks (Optional in single-device mode)
echo "API Server (optional in single-device mode):"
if check "API listening on port 5050" "netstat -tuln 2>/dev/null | grep -q ':5050' || ss -tuln 2>/dev/null | grep -q ':5050'"; then
    check "API health endpoint responds" "curl -sf http://127.0.0.1:5050/health >/dev/null 2>&1"
    check "API status endpoint responds" "curl -sf http://127.0.0.1:5050/status >/dev/null 2>&1"
else
    echo -e "${YELLOW}  ℹ  API not running (this is OK in single-device mode)${NC}"
    echo -e "${YELLOW}  ℹ  Use gateway-status-direct for console access${NC}"
fi
echo ""

# Firewall & Forwarding
echo "Firewall & Forwarding:"
check "IPv4 forwarding enabled" "[ \$(sysctl -n net.ipv4.ip_forward 2>/dev/null) = '1' ]"
check "IPv6 forwarding enabled" "[ \$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null) = '1' ]"
echo ""

# UCI Configuration
echo "UCI Configuration:"
check "LAN interface configured" "uci show network.lan >/dev/null 2>&1"
check "WAN interface configured" "uci show network.wan >/dev/null 2>&1"
check "DHCP server configured" "uci show dhcp.lan >/dev/null 2>&1"
echo ""

# File Checks
echo "Files & Permissions:"
check "Service script exists" "[ -x /etc/init.d/ipv4-ipv6-gateway ]"
check "Python service exists" "[ -f /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py ]"
check "Helper scripts installed" "[ -x /usr/bin/gateway-status ] && [ -x /usr/bin/gateway-devices ]"
check "Log file exists" "[ -f /var/log/ipv4-ipv6-gateway.log ]"
echo ""

# Summary
echo "========================================"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL CHECKS PASSED!${NC} ($PASS/$((PASS + FAIL)))"
    echo "========================================"
    echo ""
    echo -e "${GREEN}Gateway is ready for deployment!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Connect eth0 to IPv6 network"
    echo "  2. Connect eth1 to IPv4 devices"
    echo "  3. Monitor logs: tail -f /var/log/ipv4-ipv6-gateway.log"
    echo "  4. Check devices: gateway-devices"
    echo ""
    exit 0
else
    echo -e "${RED}SOME CHECKS FAILED!${NC} ($PASS/$((PASS + FAIL)) passed)"
    echo "========================================"
    echo ""
    echo -e "${YELLOW}Fix issues before deploying to production${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  • Run full diagnostic: gateway-diagnose --fix-all"
    echo "  • Check logs: tail -30 /var/log/ipv4-ipv6-gateway.log"
    echo "  • Restart service: /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
    exit 1
fi
