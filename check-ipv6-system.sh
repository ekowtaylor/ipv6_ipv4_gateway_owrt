#!/bin/bash
#
# Check IPv6 System Status on OpenWrt Gateway
# Run this on the router to see if IPv6 is properly enabled
#

echo "═══════════════════════════════════════════════════════════"
echo "IPv6 System Status Check"
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

echo -e "${BLUE}1. Global IPv6 Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

IPV6_DISABLED_ALL=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)
IPV6_DISABLED_DEFAULT=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null)
IPV6_DISABLED_ETH0=$(cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6 2>/dev/null)

echo "Global IPv6 disable_ipv6 (all):      $IPV6_DISABLED_ALL (0=enabled, 1=disabled)"
echo "Global IPv6 disable_ipv6 (default):  $IPV6_DISABLED_DEFAULT"
echo "WAN (eth0) disable_ipv6:             $IPV6_DISABLED_ETH0"
echo ""

if [ "$IPV6_DISABLED_ALL" = "1" ]; then
    echo -e "${RED}✗ IPv6 is DISABLED globally!${NC}"
    echo "  Run: sysctl -w net.ipv6.conf.all.disable_ipv6=0"
else
    echo -e "${GREEN}✓ IPv6 is enabled globally${NC}"
fi

if [ "$IPV6_DISABLED_ETH0" = "1" ]; then
    echo -e "${RED}✗ IPv6 is DISABLED on eth0!${NC}"
    echo "  Run: sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
else
    echo -e "${GREEN}✓ IPv6 is enabled on eth0${NC}"
fi
echo ""

echo -e "${BLUE}2. IPv6 Forwarding Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

IPV6_FORWARD_ALL=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)
IPV6_FORWARD_ETH0=$(cat /proc/sys/net/ipv6/conf/eth0/forwarding 2>/dev/null)

echo "IPv6 forwarding (all):      $IPV6_FORWARD_ALL (0=off, 1=on)"
echo "IPv6 forwarding (eth0):     $IPV6_FORWARD_ETH0"
echo ""

if [ "$IPV6_FORWARD_ALL" = "1" ]; then
    echo -e "${GREEN}✓ IPv6 forwarding is enabled${NC}"
else
    echo -e "${RED}✗ IPv6 forwarding is DISABLED!${NC}"
fi
echo ""

echo -e "${BLUE}3. IPv6 Router Advertisement Settings (eth0)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

ACCEPT_RA=$(cat /proc/sys/net/ipv6/conf/eth0/accept_ra 2>/dev/null)
AUTOCONF=$(cat /proc/sys/net/ipv6/conf/eth0/autoconf 2>/dev/null)
ACCEPT_RA_DEFRTR=$(cat /proc/sys/net/ipv6/conf/eth0/accept_ra_defrtr 2>/dev/null)

echo "accept_ra:         $ACCEPT_RA (0=off, 1=on, 2=always)"
echo "autoconf:          $AUTOCONF (0=off, 1=on)"
echo "accept_ra_defrtr:  $ACCEPT_RA_DEFRTR (0=off, 1=on)"
echo ""

if [ "$ACCEPT_RA" = "2" ] || [ "$ACCEPT_RA" = "1" ]; then
    echo -e "${GREEN}✓ Router Advertisement acceptance is enabled${NC}"
else
    echo -e "${RED}✗ Router Advertisement acceptance is DISABLED!${NC}"
    echo "  Run: sysctl -w net.ipv6.conf.eth0.accept_ra=2"
fi

if [ "$AUTOCONF" = "1" ]; then
    echo -e "${GREEN}✓ SLAAC autoconfig is enabled${NC}"
else
    echo -e "${RED}✗ SLAAC autoconfig is DISABLED!${NC}"
fi
echo ""

echo -e "${BLUE}4. Kernel IPv6 Module Status${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if lsmod | grep -q ipv6; then
    echo -e "${GREEN}✓ IPv6 kernel module is loaded${NC}"
    lsmod | grep ipv6
else
    echo -e "${RED}✗ IPv6 kernel module NOT loaded!${NC}"
    echo "  Try: modprobe ipv6"
fi
echo ""

echo -e "${BLUE}5. UCI Network Configuration${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "WAN6 interface config:"
uci show network.wan6 2>/dev/null || echo -e "${YELLOW}  ⚠ wan6 interface not configured in UCI${NC}"
echo ""

echo "Global IPv6 ULA prefix:"
uci show network.globals.ula_prefix 2>/dev/null || echo "  (none)"
echo ""

echo -e "${BLUE}6. System-wide IPv6 Settings${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Contents of /etc/sysctl.conf (IPv6 related):"
grep -i ipv6 /etc/sysctl.conf 2>/dev/null || echo "  (no IPv6 settings found)"
echo ""

echo "Current sysctl IPv6 settings:"
sysctl -a 2>/dev/null | grep ipv6 | grep -E "disable_ipv6|accept_ra|autoconf|forwarding" | head -20
echo ""

echo -e "${BLUE}7. Test IPv6 Connectivity${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Ping Google IPv6 DNS (2001:4860:4860::8888):"
if ping6 -c 2 -W 2 2001:4860:4860::8888 2>/dev/null; then
    echo -e "${GREEN}✓ IPv6 internet connectivity works!${NC}"
else
    echo -e "${RED}✗ No IPv6 internet connectivity${NC}"
    echo "  This could mean:"
    echo "  - Upstream network has no IPv6"
    echo "  - IPv6 is disabled on the router"
    echo "  - Firewall is blocking IPv6"
fi
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "RECOMMENDED FIXES"
echo "═══════════════════════════════════════════════════════════"
echo ""

NEEDS_FIX=0

if [ "$IPV6_DISABLED_ALL" = "1" ]; then
    echo -e "${YELLOW}Fix 1: Enable IPv6 globally${NC}"
    echo "  sysctl -w net.ipv6.conf.all.disable_ipv6=0"
    echo "  sysctl -w net.ipv6.conf.default.disable_ipv6=0"
    echo ""
    NEEDS_FIX=1
fi

if [ "$IPV6_DISABLED_ETH0" = "1" ]; then
    echo -e "${YELLOW}Fix 2: Enable IPv6 on eth0${NC}"
    echo "  sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
    echo ""
    NEEDS_FIX=1
fi

if [ "$ACCEPT_RA" != "2" ] && [ "$ACCEPT_RA" != "1" ]; then
    echo -e "${YELLOW}Fix 3: Enable Router Advertisement acceptance${NC}"
    echo "  sysctl -w net.ipv6.conf.eth0.accept_ra=2"
    echo "  sysctl -w net.ipv6.conf.eth0.autoconf=1"
    echo ""
    NEEDS_FIX=1
fi

if ! lsmod | grep -q ipv6; then
    echo -e "${YELLOW}Fix 4: Load IPv6 kernel module${NC}"
    echo "  modprobe ipv6"
    echo ""
    NEEDS_FIX=1
fi

if [ $NEEDS_FIX -eq 0 ]; then
    echo -e "${GREEN}✓ No obvious IPv6 issues detected on the system${NC}"
    echo ""
    echo "If IPv6 still doesn't work, the issue is likely:"
    echo "  - Upstream network doesn't provide IPv6"
    echo "  - MAC spoofing breaks IPv6 registration"
    echo "  - Upstream router blocks unknown MACs from IPv6"
fi

echo ""
