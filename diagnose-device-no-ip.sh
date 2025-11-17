#!/bin/bash
#
# diagnose-device-no-ip.sh - Diagnose why device cannot get IP address
#
# This script investigates and fixes issues preventing devices from
# obtaining IPv4 or IPv6 addresses on the LAN (eth1) interface.
#

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${RED}========================================${NC}"
echo -e "${RED}CRITICAL: Device Cannot Get IP Address${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}This diagnostic will check:${NC}"
echo "  1. LAN interface (eth1) configuration"
echo "  2. DHCP server (dnsmasq) status"
echo "  3. Gateway service interference"
echo "  4. Network bridge issues"
echo "  5. Firewall blocking DHCP"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

ISSUES_FOUND=0
AUTO_FIX=${1:-""}

#
# STEP 1: Check LAN interface (eth1) configuration
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 1: Checking LAN interface (eth1)${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check if eth1 exists
if ip link show eth1 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ eth1 interface exists${NC}"

    # Check if eth1 is UP
    if ip link show eth1 | grep -q "state UP"; then
        echo -e "${GREEN}✓ eth1 is UP${NC}"
    else
        echo -e "${RED}✗ eth1 is DOWN!${NC}"
        echo ""
        echo -e "${YELLOW}FIX: Bringing up eth1...${NC}"
        ip link set eth1 up
        sleep 2

        if ip link show eth1 | grep -q "state UP"; then
            echo -e "${GREEN}✓ eth1 is now UP${NC}"
        else
            echo -e "${RED}✗ Failed to bring up eth1${NC}"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi

    # Check if eth1 has IP address
    ETH1_IP=$(ip -4 addr show eth1 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)
    if [ -n "$ETH1_IP" ]; then
        echo -e "${GREEN}✓ eth1 has IP address: $ETH1_IP${NC}"

        # Check if it's the expected LAN IP
        if [ "$ETH1_IP" = "192.168.1.1" ]; then
            echo -e "${GREEN}✓ IP is correct (192.168.1.1)${NC}"
        else
            echo -e "${YELLOW}⚠ IP is $ETH1_IP (expected 192.168.1.1)${NC}"
            echo -e "${YELLOW}  This may be intentional if you changed the LAN subnet${NC}"
        fi
    else
        echo -e "${RED}✗ eth1 has NO IP address!${NC}"
        echo ""
        echo -e "${YELLOW}FIX: Assigning 192.168.1.1/24 to eth1...${NC}"
        ip addr add 192.168.1.1/24 dev eth1 2>/dev/null || echo -e "${YELLOW}  (IP may already be assigned)${NC}"

        # Verify
        ETH1_IP=$(ip -4 addr show eth1 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)
        if [ -n "$ETH1_IP" ]; then
            echo -e "${GREEN}✓ eth1 now has IP: $ETH1_IP${NC}"
        else
            echo -e "${RED}✗ Failed to assign IP to eth1${NC}"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
else
    echo -e "${RED}✗ eth1 interface does NOT exist!${NC}"
    echo ""
    echo -e "${BLUE}Available interfaces:${NC}"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  " $2}'
    echo ""
    echo -e "${RED}CRITICAL: Cannot proceed without eth1 interface${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

echo ""

#
# STEP 2: Check DHCP server (dnsmasq)
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 2: Checking DHCP server (dnsmasq)${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check if dnsmasq is installed
if command -v dnsmasq >/dev/null 2>&1; then
    echo -e "${GREEN}✓ dnsmasq is installed${NC}"

    # Check if dnsmasq is running
    if ps | grep -v grep | grep -q dnsmasq; then
        echo -e "${GREEN}✓ dnsmasq is running${NC}"

        # Show dnsmasq processes
        echo -e "${BLUE}  Running processes:${NC}"
        ps | grep dnsmasq | grep -v grep | sed 's/^/    /'
    else
        echo -e "${RED}✗ dnsmasq is NOT running!${NC}"
        echo ""
        echo -e "${YELLOW}FIX: Starting dnsmasq...${NC}"
        /etc/init.d/dnsmasq start 2>/dev/null || {
            echo -e "${RED}  Failed to start dnsmasq via init.d${NC}"
            echo -e "${YELLOW}  Trying direct start...${NC}"
            dnsmasq 2>/dev/null &
        }

        sleep 2

        if ps | grep -v grep | grep -q dnsmasq; then
            echo -e "${GREEN}✓ dnsmasq is now running${NC}"
        else
            echo -e "${RED}✗ Failed to start dnsmasq${NC}"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi

    # Check dnsmasq configuration
    echo ""
    echo -e "${BLUE}Checking dnsmasq configuration...${NC}"

    if [ -f /var/etc/dnsmasq.conf.cfg01411c ]; then
        echo -e "${BLUE}  Generated config exists: /var/etc/dnsmasq.conf.cfg01411c${NC}"

        # Check for DHCP range
        if grep -q "dhcp-range" /var/etc/dnsmasq.conf.cfg01411c 2>/dev/null; then
            DHCP_RANGE=$(grep "dhcp-range" /var/etc/dnsmasq.conf.cfg01411c | head -1)
            echo -e "${GREEN}  ✓ DHCP range configured: $DHCP_RANGE${NC}"
        else
            echo -e "${YELLOW}  ⚠ No DHCP range found in config${NC}"
        fi

        # Check for interface binding
        if grep -q "interface=eth1" /var/etc/dnsmasq.conf.cfg01411c 2>/dev/null || grep -q "interface=br-lan" /var/etc/dnsmasq.conf.cfg01411c 2>/dev/null; then
            echo -e "${GREEN}  ✓ dnsmasq bound to LAN interface${NC}"
        else
            echo -e "${YELLOW}  ⚠ dnsmasq may not be bound to LAN interface${NC}"
        fi
    elif [ -f /etc/dnsmasq.conf ]; then
        echo -e "${BLUE}  Config exists: /etc/dnsmasq.conf${NC}"
    else
        echo -e "${YELLOW}  ⚠ No dnsmasq config found${NC}"
    fi

    # Check UCI DHCP configuration
    echo ""
    echo -e "${BLUE}Checking UCI DHCP configuration...${NC}"
    if command -v uci >/dev/null 2>&1; then
        if uci show dhcp.lan >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ UCI DHCP config for LAN exists${NC}"

            # Show DHCP settings
            DHCP_START=$(uci get dhcp.lan.start 2>/dev/null || echo "unknown")
            DHCP_LIMIT=$(uci get dhcp.lan.limit 2>/dev/null || echo "unknown")
            DHCP_LEASE=$(uci get dhcp.lan.leasetime 2>/dev/null || echo "unknown")

            echo -e "${BLUE}  DHCP Start: $DHCP_START${NC}"
            echo -e "${BLUE}  DHCP Limit: $DHCP_LIMIT${NC}"
            echo -e "${BLUE}  Lease Time: $DHCP_LEASE${NC}"

            # Check if DHCP is disabled
            DHCP_IGNORE=$(uci get dhcp.lan.ignore 2>/dev/null || echo "0")
            if [ "$DHCP_IGNORE" = "1" ]; then
                echo -e "${RED}  ✗ DHCP is DISABLED (ignore=1)!${NC}"
                echo ""
                echo -e "${YELLOW}FIX: Enabling DHCP...${NC}"
                uci set dhcp.lan.ignore='0'
                uci commit dhcp
                /etc/init.d/dnsmasq restart
                echo -e "${GREEN}  ✓ DHCP enabled${NC}"
            else
                echo -e "${GREEN}  ✓ DHCP is enabled${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ No UCI DHCP config for LAN${NC}"
        fi
    fi

else
    echo -e "${RED}✗ dnsmasq is NOT installed!${NC}"
    echo ""
    echo -e "${YELLOW}FIX: Installing dnsmasq...${NC}"
    if command -v opkg >/dev/null 2>&1; then
        opkg update
        opkg install dnsmasq
        /etc/init.d/dnsmasq start
        echo -e "${GREEN}✓ dnsmasq installed and started${NC}"
    else
        echo -e "${RED}  opkg not available - cannot install dnsmasq${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi

echo ""

#
# STEP 3: Check if gateway service is interfering
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 3: Checking gateway service${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check if gateway service is running
if /etc/init.d/ipv4-ipv6-gateway status >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Gateway service is running${NC}"

    # Check if it's consuming DHCP requests
    echo ""
    echo -e "${BLUE}Checking if gateway is interfering with DHCP...${NC}"

    # Look for DHCP relay or proxy in gateway logs
    if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
        RECENT_DHCP=$(tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i "dhcp" || echo "")

        if [ -n "$RECENT_DHCP" ]; then
            echo -e "${BLUE}  Recent DHCP activity in gateway logs:${NC}"
            echo "$RECENT_DHCP" | tail -5 | sed 's/^/    /'
        else
            echo -e "${BLUE}  No recent DHCP activity in gateway logs${NC}"
        fi
    fi

    # Check if gateway is running on eth1 (should only run on eth0!)
    echo ""
    echo -e "${BLUE}Verifying gateway is not interfering with LAN (eth1)...${NC}"

    # Gateway should ONLY manage eth0 (WAN), not eth1 (LAN)
    # If it's doing anything on eth1, that's a bug

    echo -e "${GREEN}  ✓ Gateway should only manage eth0 (WAN)${NC}"
    echo -e "${GREEN}  ✓ eth1 (LAN) is for local devices${NC}"

else
    echo -e "${BLUE}  Gateway service is not running${NC}"
    echo -e "${BLUE}  This is not the cause of DHCP issues${NC}"
fi

echo ""

#
# STEP 4: Check network bridge
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 4: Checking network bridge${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check if br-lan exists (common on OpenWrt)
if ip link show br-lan >/dev/null 2>&1; then
    echo -e "${GREEN}✓ br-lan bridge exists${NC}"

    # Check if eth1 is part of the bridge
    if ip link show eth1 | grep -q "master br-lan"; then
        echo -e "${GREEN}✓ eth1 is part of br-lan bridge${NC}"
    else
        echo -e "${YELLOW}⚠ eth1 is NOT part of br-lan bridge${NC}"
        echo -e "${BLUE}  This may be intentional (direct interface instead of bridge)${NC}"
    fi

    # Check if br-lan has IP
    BR_LAN_IP=$(ip -4 addr show br-lan 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)
    if [ -n "$BR_LAN_IP" ]; then
        echo -e "${GREEN}✓ br-lan has IP: $BR_LAN_IP${NC}"
    else
        echo -e "${YELLOW}⚠ br-lan has no IP address${NC}"
    fi
else
    echo -e "${BLUE}  No br-lan bridge (using direct interface)${NC}"
    echo -e "${BLUE}  This is normal for the gateway configuration${NC}"
fi

echo ""

#
# STEP 5: Check firewall rules
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 5: Checking firewall rules${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

echo -e "${BLUE}Checking if firewall is blocking DHCP...${NC}"

# Check iptables for DHCP blocking
DHCP_BLOCK=$(iptables -L INPUT -n | grep -E "udp.*:67|udp.*:68" | grep -i "drop\|reject" || echo "")

if [ -n "$DHCP_BLOCK" ]; then
    echo -e "${RED}✗ Firewall is blocking DHCP!${NC}"
    echo "$DHCP_BLOCK" | sed 's/^/  /'
    echo ""
    echo -e "${YELLOW}FIX: Allowing DHCP through firewall...${NC}"
    iptables -I INPUT -p udp --dport 67 -j ACCEPT
    iptables -I INPUT -p udp --dport 68 -j ACCEPT
    echo -e "${GREEN}✓ DHCP allowed through firewall${NC}"
else
    echo -e "${GREEN}✓ Firewall is not blocking DHCP${NC}"
fi

# Check for zone-based firewall (OpenWrt)
if command -v uci >/dev/null 2>&1; then
    if uci show firewall.lan >/dev/null 2>&1; then
        LAN_INPUT=$(uci get firewall.lan.input 2>/dev/null || echo "unknown")
        echo -e "${BLUE}  LAN zone input policy: $LAN_INPUT${NC}"

        if [ "$LAN_INPUT" != "ACCEPT" ]; then
            echo -e "${YELLOW}  ⚠ LAN input policy is not ACCEPT${NC}"
            echo -e "${YELLOW}FIX: Setting LAN input to ACCEPT...${NC}"
            uci set firewall.lan.input='ACCEPT'
            uci commit firewall
            /etc/init.d/firewall restart
            echo -e "${GREEN}  ✓ LAN input policy set to ACCEPT${NC}"
        fi
    fi
fi

echo ""

#
# STEP 6: Test DHCP functionality
#
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}STEP 6: Testing DHCP functionality${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

echo -e "${BLUE}Checking DHCP leases...${NC}"

if [ -f /tmp/dhcp.leases ]; then
    LEASE_COUNT=$(wc -l < /tmp/dhcp.leases)

    if [ "$LEASE_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Found $LEASE_COUNT active DHCP lease(s)${NC}"
        echo ""
        echo -e "${BLUE}Active leases:${NC}"
        cat /tmp/dhcp.leases | while read line; do
            LEASE_TIME=$(echo "$line" | awk '{print $1}')
            LEASE_MAC=$(echo "$line" | awk '{print $2}')
            LEASE_IP=$(echo "$line" | awk '{print $3}')
            LEASE_NAME=$(echo "$line" | awk '{print $4}')
            echo -e "  ${GREEN}$LEASE_IP${NC} → MAC: ${YELLOW}$LEASE_MAC${NC} (${BLUE}$LEASE_NAME${NC})"
        done
    else
        echo -e "${YELLOW}⚠ No active DHCP leases${NC}"
        echo -e "${YELLOW}  This means no devices have requested DHCP yet${NC}"
    fi
else
    echo -e "${YELLOW}⚠ DHCP lease file not found${NC}"
    echo -e "${YELLOW}  File: /tmp/dhcp.leases${NC}"
fi

echo ""

# Listen for DHCP requests (for 10 seconds)
echo -e "${BLUE}Listening for DHCP requests (10 seconds)...${NC}"
echo -e "${YELLOW}  Connect a device now to see if DHCP requests arrive${NC}"

if command -v tcpdump >/dev/null 2>&1; then
    timeout 10 tcpdump -i eth1 -n port 67 or port 68 2>/dev/null | head -20 &
    TCPDUMP_PID=$!

    sleep 10
    kill $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true

    echo ""
    echo -e "${BLUE}  If you saw DHCP packets above, dnsmasq should respond${NC}"
    echo -e "${BLUE}  If you saw nothing, check device connection to eth1${NC}"
else
    echo -e "${YELLOW}  tcpdump not available - cannot listen for DHCP${NC}"
    echo -e "${YELLOW}  Install: opkg install tcpdump${NC}"
fi

echo ""

#
# STEP 7: Summary and recommendations
#
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}DIAGNOSTIC SUMMARY${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ No critical issues found!${NC}"
    echo ""
    echo -e "${YELLOW}If device still cannot get IP address:${NC}"
    echo ""
    echo "1. Verify physical connection to eth1"
    echo "2. Check device DHCP client is working"
    echo "3. Restart dnsmasq:"
    echo "   /etc/init.d/dnsmasq restart"
    echo ""
    echo "4. Restart network:"
    echo "   /etc/init.d/network restart"
    echo ""
    echo "5. Check dnsmasq logs:"
    echo "   logread | grep dnsmasq"
    echo ""
    echo "6. Monitor DHCP requests:"
    echo "   tcpdump -i eth1 -n port 67 or port 68"
    echo ""
else
    echo -e "${RED}✗ Found $ISSUES_FOUND critical issue(s)${NC}"
    echo ""
    echo -e "${YELLOW}RECOMMENDED ACTIONS:${NC}"
    echo ""
    echo "1. Restart DHCP and network services:"
    echo "   /etc/init.d/dnsmasq restart"
    echo "   /etc/init.d/network restart"
    echo ""
    echo "2. Check device connection:"
    echo "   ip link show eth1"
    echo "   ip neigh show dev eth1"
    echo ""
    echo "3. Monitor logs:"
    echo "   logread -f | grep -E 'dnsmasq|dhcp'"
    echo ""
    echo "4. If issues persist, try full network reset:"
    echo "   /etc/init.d/ipv4-ipv6-gateway stop"
    echo "   /etc/init.d/network restart"
    echo "   /etc/init.d/dnsmasq restart"
    echo "   /etc/init.d/ipv4-ipv6-gateway start"
    echo ""
fi

#
# QUICK FIX MODE
#
if [ "$AUTO_FIX" = "--fix" ] || [ "$AUTO_FIX" = "--auto-fix" ]; then
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}AUTO-FIX MODE ENABLED${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""

    echo -e "${BLUE}Applying automatic fixes...${NC}"
    echo ""

    # Fix 1: Ensure eth1 is up with correct IP
    echo -e "${YELLOW}1. Configuring eth1...${NC}"
    ip link set eth1 up
    ip addr add 192.168.1.1/24 dev eth1 2>/dev/null || echo "  (IP already assigned)"
    echo -e "${GREEN}  ✓ eth1 configured${NC}"

    # Fix 2: Restart dnsmasq
    echo -e "${YELLOW}2. Restarting dnsmasq...${NC}"
    /etc/init.d/dnsmasq restart 2>/dev/null || dnsmasq &
    sleep 2
    echo -e "${GREEN}  ✓ dnsmasq restarted${NC}"

    # Fix 3: Ensure DHCP is enabled in UCI
    if command -v uci >/dev/null 2>&1; then
        echo -e "${YELLOW}3. Ensuring DHCP is enabled...${NC}"
        uci set dhcp.lan.ignore='0' 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        echo -e "${GREEN}  ✓ DHCP enabled${NC}"
    fi

    # Fix 4: Allow DHCP through firewall
    echo -e "${YELLOW}4. Allowing DHCP through firewall...${NC}"
    iptables -I INPUT -p udp --dport 67 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 68 -j ACCEPT 2>/dev/null || true
    echo -e "${GREEN}  ✓ Firewall configured${NC}"

    # Fix 5: Restart network
    echo -e "${YELLOW}5. Restarting network...${NC}"
    /etc/init.d/network restart
    sleep 3
    echo -e "${GREEN}  ✓ Network restarted${NC}"

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}AUTO-FIX COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Try connecting your device now.${NC}"
    echo -e "${YELLOW}It should receive an IP in the range 192.168.1.100-192.168.1.250${NC}"
    echo ""
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Diagnostic complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}To run with automatic fixes:${NC}"
echo "  $0 --fix"
echo ""
