#!/bin/bash
#
# UNIFIED IPv6 GATEWAY DIAGNOSTIC TOOL
# Consolidates all IPv6 diagnostic scripts into one comprehensive tool
#
# Usage: ./diagnose-ipv6.sh [--quick|--full|--fix]
#   --quick : Quick diagnostic (default)
#   --full  : Full comprehensive diagnostic with all tests
#   --fix   : Attempt automatic fixes for common issues
#

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Diagnostic mode
MODE="${1:---quick}"

echo "==============================================="
echo "UNIFIED IPv6 GATEWAY DIAGNOSTIC TOOL"
echo "Mode: $MODE"
echo "==============================================="
echo ""

# Issue counter
ISSUES=0
WARNINGS=0

#==============================================
# SECTION 1: Gateway Service Status
#==============================================
echo -e "${BLUE}=== 1. Gateway Service Status ===${NC}"
if ps | grep -q "[p]ython.*gateway"; then
    echo -e "${GREEN}✓ Gateway service is running${NC}"
    ps | grep "[p]ython.*gateway" | head -1
else
    echo -e "${RED}❌ Gateway service NOT running!${NC}"
    ISSUES=$((ISSUES + 1))
    echo "   Start it with: /etc/init.d/ipv4-ipv6-gateway start"
    if [ "$MODE" = "--fix" ]; then
        echo "   Attempting to start service..."
        /etc/init.d/ipv4-ipv6-gateway start
        sleep 3
    fi
fi
echo ""

#==============================================
# SECTION 2: Device Information
#==============================================
echo -e "${BLUE}=== 2. Device Information ===${NC}"
DEVICE_JSON=$(curl -s http://localhost:5050/devices 2>/dev/null || echo "{}")
MAC=$(echo "$DEVICE_JSON" | grep -o '"mac_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV4_LAN=$(echo "$DEVICE_JSON" | grep -o '"ipv4_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV4_WAN=$(echo "$DEVICE_JSON" | grep -o '"ipv4_wan_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV6=$(echo "$DEVICE_JSON" | grep -o '"ipv6_address":"[^"]*"' | head -1 | cut -d'"' -f4)
STATUS=$(echo "$DEVICE_JSON" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$MAC" ]; then
    echo -e "${YELLOW}⚠ No device detected${NC}"
    WARNINGS=$((WARNINGS + 1))
    echo ""
    echo "ARP table (eth1):"
    ip neigh show dev eth1 2>/dev/null || echo "  No entries"
else
    echo "Device MAC:        $MAC"
    echo "Device LAN IPv4:   ${IPV4_LAN:-NONE}"
    echo "Device WAN IPv4:   ${IPV4_WAN:-NONE}"
    echo "Device IPv6:       ${IPV6:-NONE}"
    echo "Status:            ${STATUS:-unknown}"

    if [ -z "$IPV6" ]; then
        echo -e "${YELLOW}⚠ Device has NO IPv6 address${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
fi
echo ""

#==============================================
# SECTION 3: WAN Interface (eth0) Status
#==============================================
echo -e "${BLUE}=== 3. WAN Interface (eth0) Status ===${NC}"

# Get eth0 details
ETH0_STATUS=$(ip link show eth0 2>/dev/null | grep -o "state [^ ]*" | awk '{print $2}')
ETH0_MAC=$(ip link show eth0 2>/dev/null | grep -o 'link/ether [^ ]*' | awk '{print $2}')

echo "Interface state:   ${ETH0_STATUS:-UNKNOWN}"
echo "Current MAC:       ${ETH0_MAC:-UNKNOWN}"
echo "Expected MAC:      ${MAC:-not set}"

if [ -n "$MAC" ] && [ "$ETH0_MAC" != "$MAC" ]; then
    echo -e "${RED}❌ eth0 MAC does NOT match device MAC!${NC}"
    ISSUES=$((ISSUES + 1))
    if [ "$MODE" = "--fix" ]; then
        echo "   Fixing MAC address..."
        ip link set eth0 down
        ip link set eth0 address "$MAC"
        ip link set eth0 up
        echo -e "${GREEN}✓ MAC address updated${NC}"
    else
        echo "   Fix with: ip link set eth0 address $MAC"
    fi
elif [ -n "$MAC" ]; then
    echo -e "${GREEN}✓ eth0 MAC matches device MAC${NC}"
fi
echo ""

#==============================================
# SECTION 4: IPv6 Addresses on eth0
#==============================================
echo -e "${BLUE}=== 4. IPv6 Addresses on eth0 ===${NC}"

# Link-local
LINK_LOCAL=$(ip -6 addr show eth0 2>/dev/null | grep "fe80" | awk '{print $2}')
if [ -z "$LINK_LOCAL" ]; then
    echo -e "${RED}❌ NO link-local IPv6 (fe80::) - CRITICAL!${NC}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}✓ Link-local:${NC} $LINK_LOCAL"
fi

# Global IPv6
ETH0_IPV6=$(ip -6 addr show eth0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print $2}')
if [ -z "$ETH0_IPV6" ]; then
    echo -e "${RED}❌ NO global IPv6 addresses on eth0!${NC}"
    ISSUES=$((ISSUES + 1))
    echo ""
    echo "This is the ROOT CAUSE - gateway cannot get IPv6 from router!"
    echo ""
    echo "Possible causes:"
    echo "1. IPv6 forwarding disabled Router Advertisements (accept_ra=0)"
    echo "2. Router doesn't support IPv6"
    echo "3. Router doesn't send RA to this MAC"
    echo "4. DHCPv6 server not responding"
else
    echo -e "${GREEN}✓ Global IPv6 addresses:${NC}"
    echo "$ETH0_IPV6" | while read addr; do
        echo "  $addr"
    done

    # Check if device IPv6 matches eth0
    if [ -n "$IPV6" ]; then
        MATCH_FOUND=false
        for ipv6_addr in $(echo "$IPV6" | tr ',' '\n'); do
            if echo "$ETH0_IPV6" | grep -q "${ipv6_addr%/*}"; then
                MATCH_FOUND=true
                break
            fi
        done

        if [ "$MATCH_FOUND" = true ]; then
            echo -e "${GREEN}✓ Device IPv6 IS configured on eth0${NC}"
        else
            echo -e "${YELLOW}⚠ Device IPv6 ($IPV6) NOT found on eth0${NC}"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
fi
echo ""

#==============================================
# SECTION 5: IPv6 Kernel Settings (CRITICAL!)
#==============================================
echo -e "${BLUE}=== 5. IPv6 Kernel Settings (CRITICAL!) ===${NC}"

DISABLED=$(sysctl -n net.ipv6.conf.eth0.disable_ipv6 2>/dev/null || echo "unknown")
ACCEPT_RA=$(sysctl -n net.ipv6.conf.eth0.accept_ra 2>/dev/null || echo "unknown")
AUTOCONF=$(sysctl -n net.ipv6.conf.eth0.autoconf 2>/dev/null || echo "unknown")
FORWARDING=$(sysctl -n net.ipv6.conf.eth0.forwarding 2>/dev/null || echo "unknown")

echo "IPv6 disabled:     $DISABLED (should be 0)"
echo "Accept RA:         $ACCEPT_RA (should be 2 with forwarding)"
echo "Autoconf:          $AUTOCONF (should be 1)"
echo "Forwarding:        $FORWARDING (1 if gateway mode)"

# Check settings
if [ "$DISABLED" = "1" ]; then
    echo -e "${RED}❌ IPv6 is DISABLED on eth0!${NC}"
    ISSUES=$((ISSUES + 1))
    if [ "$MODE" = "--fix" ]; then
        sysctl -w net.ipv6.conf.eth0.disable_ipv6=0
        echo -e "${GREEN}✓ IPv6 enabled${NC}"
    else
        echo "   Fix: sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
    fi
fi

if [ "$FORWARDING" = "1" ] && [ "$ACCEPT_RA" != "2" ]; then
    echo -e "${RED}❌ CRITICAL: Forwarding enabled but accept_ra != 2!${NC}"
    ISSUES=$((ISSUES + 1))
    echo ""
    echo "This is THE BUG! When forwarding=1, kernel sets accept_ra=0"
    echo "This BLOCKS Router Advertisements → No SLAAC → No IPv6!"
    echo ""
    if [ "$MODE" = "--fix" ]; then
        sysctl -w net.ipv6.conf.eth0.accept_ra=2
        sysctl -w net.ipv6.conf.all.accept_ra=2
        sysctl -w net.ipv6.conf.eth0.autoconf=1
        echo -e "${GREEN}✓ accept_ra set to 2 (accept RA with forwarding)${NC}"
    else
        echo "Fix with:"
        echo "  sysctl -w net.ipv6.conf.eth0.accept_ra=2"
        echo "  sysctl -w net.ipv6.conf.all.accept_ra=2"
        echo "  sysctl -w net.ipv6.conf.eth0.autoconf=1"
    fi
elif [ "$ACCEPT_RA" = "2" ]; then
    echo -e "${GREEN}✓ accept_ra=2 (correct for forwarding mode)${NC}"
fi

if [ "$AUTOCONF" != "1" ]; then
    echo -e "${YELLOW}⚠ Autoconf not enabled (SLAAC may not work)${NC}"
    WARNINGS=$((WARNINGS + 1))
    if [ "$MODE" = "--fix" ]; then
        sysctl -w net.ipv6.conf.eth0.autoconf=1
        echo -e "${GREEN}✓ Autoconf enabled${NC}"
    fi
fi
echo ""

#==============================================
# SECTION 6: Router Connectivity
#==============================================
echo -e "${BLUE}=== 6. Router Connectivity ===${NC}"

# Ping all-routers multicast
echo "Pinging all-routers multicast (ff02::2)..."
if ping6 -c 2 -W 2 -I eth0 ff02::2 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Router reachable via IPv6!${NC}"
else
    echo -e "${YELLOW}⚠ Router doesn't respond to ping6${NC}"
    WARNINGS=$((WARNINGS + 1))
    echo "  (This may be normal - some routers don't respond)"
fi
echo ""

#==============================================
# SECTION 7: Router's IPv6 Neighbor Table
#==============================================
echo -e "${BLUE}=== 7. Router's IPv6 Neighbor Table ===${NC}"
if [ -n "$MAC" ]; then
    echo "Checking if router knows about our MAC ($MAC)..."
    if ip -6 neigh show 2>/dev/null | grep -qi "$MAC"; then
        echo -e "${GREEN}✓ Router has neighbor entry for our MAC${NC}"
        ip -6 neigh show 2>/dev/null | grep -i "$MAC"
    else
        echo -e "${YELLOW}⚠ Router doesn't have neighbor entry for our MAC${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "Skipping (no device MAC available)"
fi
echo ""

if [ "$MODE" = "--full" ]; then
    echo "All IPv6 neighbors:"
    ip -6 neigh show 2>/dev/null || echo "  None"
    echo ""
fi

#==============================================
# SECTION 8: DHCPv6 Client Test
#==============================================
if [ "$MODE" = "--full" ]; then
    echo -e "${BLUE}=== 8. DHCPv6 Client Test ===${NC}"
    if command -v odhcp6c >/dev/null 2>&1; then
        echo -e "${GREEN}✓ odhcp6c installed: $(which odhcp6c)${NC}"
        echo ""
        echo "Testing DHCPv6 server (5 second timeout)..."
        timeout 5 odhcp6c -v -t 5 eth0 2>&1 | head -20 || echo "  DHCPv6 request timed out or failed"
    else
        echo -e "${YELLOW}⚠ odhcp6c NOT installed${NC}"
        WARNINGS=$((WARNINGS + 1))
        echo "  Install with: opkg install odhcp6c"
    fi
    echo ""
fi

#==============================================
# SECTION 9: Socat Proxies
#==============================================
echo -e "${BLUE}=== 9. Socat Proxy Status ===${NC}"
SOCAT_COUNT=$(ps | grep -c "[s]ocat" || echo "0")
if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ $SOCAT_COUNT socat proxy process(es) running${NC}"
    if [ "$MODE" = "--full" ]; then
        echo ""
        echo "Socat processes:"
        ps | grep "[s]ocat" | head -10
    fi
else
    echo -e "${YELLOW}⚠ NO socat proxies running${NC}"
    WARNINGS=$((WARNINGS + 1))
    echo "  Expected if no devices discovered yet"
fi
echo ""

#==============================================
# SECTION 10: IPv6 Routes
#==============================================
if [ "$MODE" = "--full" ]; then
    echo -e "${BLUE}=== 10. IPv6 Routing Table ===${NC}"
    ip -6 route show 2>/dev/null | head -10
    echo ""
fi

#==============================================
# SECTION 11: Gateway Logs (Recent IPv6 Activity)
#==============================================
echo -e "${BLUE}=== 11. Recent IPv6 Gateway Logs ===${NC}"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    echo "Last 15 IPv6-related log entries:"
    tail -100 /var/log/ipv4-ipv6-gateway.log 2>/dev/null | grep -iE 'ipv6|slaac|dhcpv6|router.*advert|accept_ra' | tail -15
else
    echo -e "${YELLOW}⚠ Log file not found${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

#==============================================
# SECTION 12: Internet IPv6 Connectivity Test
#==============================================
if [ "$MODE" = "--full" ]; then
    echo -e "${BLUE}=== 12. IPv6 Internet Connectivity Test ===${NC}"
    echo "Testing connectivity to Google DNS (2001:4860:4860::8888)..."
    if ping6 -c 2 -W 3 2001:4860:4860::8888 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ IPv6 internet connectivity works!${NC}"
    else
        echo -e "${YELLOW}⚠ No IPv6 internet connectivity${NC}"
        WARNINGS=$((WARNINGS + 1))
        echo "  Possible reasons:"
        echo "  - Router doesn't provide IPv6 to internet"
        echo "  - ISP doesn't support IPv6"
        echo "  - Firewall blocking IPv6"
    fi
    echo ""
fi

#==============================================
# SUMMARY AND RECOMMENDATIONS
#==============================================
echo "==============================================="
echo "DIAGNOSTIC SUMMARY"
echo "==============================================="
echo ""
echo -e "Issues found:   ${RED}$ISSUES${NC}"
echo -e "Warnings:       ${YELLOW}$WARNINGS${NC}"
echo ""

if [ $ISSUES -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ NO ISSUES FOUND! Gateway appears healthy!${NC}"
    echo ""
    echo "If IPv6 is still not working, check:"
    echo "1. Router's IPv6 configuration"
    echo "2. ISP IPv6 availability"
    echo "3. Firewall rules"
    exit 0
fi

#==============================================
# RECOMMENDED FIXES
#==============================================
echo "==============================================="
echo "RECOMMENDED FIXES"
echo "==============================================="
echo ""

if [ -z "$ETH0_IPV6" ]; then
    echo -e "${RED}🔴 CRITICAL: No IPv6 on eth0${NC}"
    echo ""
    echo "Root Cause: Gateway cannot get IPv6 from router via SLAAC/DHCPv6"
    echo ""
    echo "Most common cause: IPv6 forwarding conflict (accept_ra=0)"
    echo "Solution:"
    echo ""
    echo "  # Enable RA acceptance with forwarding"
    echo "  sysctl -w net.ipv6.conf.eth0.accept_ra=2"
    echo "  sysctl -w net.ipv6.conf.all.accept_ra=2"
    echo "  sysctl -w net.ipv6.conf.eth0.autoconf=1"
    echo "  sysctl -w net.ipv6.conf.eth0.disable_ipv6=0"
    echo ""
    echo "  # Ensure device MAC is set on eth0"
    if [ -n "$MAC" ]; then
        echo "  ip link set eth0 down"
        echo "  ip link set eth0 address $MAC"
        echo "  ip link set eth0 up"
    fi
    echo ""
    echo "  # Request Router Advertisement"
    echo "  ping6 -c 1 -I eth0 ff02::2"
    echo ""
    echo "  # Wait 10 seconds for SLAAC"
    echo "  sleep 10"
    echo ""
    echo "  # Verify IPv6 appeared"
    echo "  ip -6 addr show eth0 | grep inet6 | grep -v fe80"
    echo ""
    echo "If still no IPv6, try DHCPv6:"
    echo "  timeout 10 odhcp6c -v -t 10 eth0"
    echo ""
fi

if [ -n "$IPV6" ] && [ -n "$ETH0_IPV6" ] && ! echo "$ETH0_IPV6" | grep -q "${IPV6%/*}"; then
    echo -e "${YELLOW}🟡 WARNING: IPv6 Address Mismatch${NC}"
    echo ""
    echo "Gateway database: $IPV6"
    echo "eth0 actually has: $ETH0_IPV6"
    echo ""
    echo "Solutions:"
    echo "1. Restart gateway to re-sync:"
    echo "   /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
    echo "2. Or manually add IPv6:"
    echo "   ip -6 addr add $IPV6 dev eth0"
    echo ""
fi

if [ "$MODE" != "--fix" ]; then
    echo ""
    echo "==============================================="
    echo "TIP: Run with --fix to auto-fix common issues:"
    echo "  ./diagnose-ipv6.sh --fix"
    echo "==============================================="
fi

exit $ISSUES
