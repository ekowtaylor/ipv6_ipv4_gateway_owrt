#!/bin/bash
###############################################################################
# IPv6 Auto-Detection Diagnostic Script
# Tests whether network supports SLAAC, DHCPv6, or both
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

WAN_IF="eth0"
LAN_IF="eth1"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   IPv6 Auto-Detection Diagnostic${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Get original MAC for restoration
ORIGINAL_MAC=$(ip link show $WAN_IF | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
echo -e "${BLUE}Original $WAN_IF MAC:${NC} $ORIGINAL_MAC"
echo ""

# Function to restore MAC
restore_mac() {
    echo -e "${YELLOW}Restoring original MAC...${NC}"
    ip link set $WAN_IF down
    ip link set $WAN_IF address $ORIGINAL_MAC
    ip link set $WAN_IF up
    sleep 2
}

# Trap to ensure MAC is restored
trap restore_mac EXIT

# Get a test device MAC from LAN
echo -e "${BLUE}=== Step 1: Finding Test Device ===${NC}"
TEST_MAC=$(ip neigh show dev $LAN_IF | grep -v FAILED | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)

if [ -z "$TEST_MAC" ]; then
    echo -e "${RED}✗ No devices found on $LAN_IF${NC}"
    echo "Please ensure a device is connected to the LAN side"
    exit 1
fi

echo -e "${GREEN}✓ Found test device MAC:${NC} $TEST_MAC"
echo ""

# Check current IPv6 status
echo -e "${BLUE}=== Step 2: Check Current IPv6 Configuration ===${NC}"

echo "IPv6 addresses on $WAN_IF (before test):"
ip -6 addr show $WAN_IF | grep inet6 || echo "  None"
echo ""

echo "IPv6 sysctl settings:"
echo -n "  accept_ra: "
sysctl -n net.ipv6.conf.$WAN_IF.accept_ra
echo -n "  autoconf: "
sysctl -n net.ipv6.conf.$WAN_IF.autoconf
echo -n "  disable_ipv6: "
sysctl -n net.ipv6.conf.$WAN_IF.disable_ipv6
echo ""

# Test 1: SLAAC Detection
echo -e "${BLUE}=== Step 3: Testing SLAAC (Router Advertisement) ===${NC}"

# Flush existing addresses
echo "Flushing existing IPv6 addresses on $WAN_IF..."
ip -6 addr flush dev $WAN_IF scope global

# Spoof MAC
echo "Spoofing MAC to $TEST_MAC..."
ip link set $WAN_IF down
ip link set $WAN_IF address $TEST_MAC
ip link set $WAN_IF up
sleep 2

# Enable IPv6 and SLAAC
echo "Enabling IPv6 and SLAAC..."
sysctl -w net.ipv6.conf.$WAN_IF.disable_ipv6=0 > /dev/null
sysctl -w net.ipv6.conf.$WAN_IF.accept_ra=2 > /dev/null
sysctl -w net.ipv6.conf.$WAN_IF.autoconf=1 > /dev/null
sysctl -w net.ipv6.conf.$WAN_IF.router_solicitations=3 > /dev/null

# Flush IPv6 neighbor cache
echo "Flushing IPv6 neighbor cache..."
ip -6 neigh flush dev $WAN_IF

# Send Router Solicitation
echo "Sending Router Solicitation..."
ping6 -c 1 -W 1 -I $WAN_IF ff02::2 > /dev/null 2>&1 || true
sleep 1

# Wait for SLAAC
echo -e "${YELLOW}Waiting 15 seconds for SLAAC (Router Advertisement)...${NC}"
for i in {15..1}; do
    echo -ne "  $i seconds remaining...\r"
    sleep 1
done
echo ""

# Check for SLAAC addresses
SLAAC_ADDRS=$(ip -6 addr show $WAN_IF scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 || echo "")

if [ -n "$SLAAC_ADDRS" ]; then
    echo -e "${GREEN}✓ SLAAC SUCCESS! Network supports SLAAC${NC}"
    echo "SLAAC addresses obtained:"
    echo "$SLAAC_ADDRS" | while read addr; do
        echo -e "  ${GREEN}$addr${NC}"
    done
    SLAAC_WORKS=true
else
    echo -e "${RED}✗ SLAAC FAILED - No addresses obtained${NC}"
    echo "This could mean:"
    echo "  1. Network doesn't support SLAAC"
    echo "  2. No Router Advertisements sent"
    echo "  3. MAC $TEST_MAC not authorized on network"
    SLAAC_WORKS=false
fi
echo ""

# Test 2: Check for Router Advertisements
echo -e "${BLUE}=== Step 4: Checking for Router Advertisements ===${NC}"
echo "Listening for Router Advertisements (10 seconds)..."

# Check if tcpdump is available
if command -v tcpdump > /dev/null 2>&1; then
    RA_CAPTURED=$(timeout 10 tcpdump -i $WAN_IF -vvv icmp6 2>&1 | grep -i "router advertisement" || echo "")

    if [ -n "$RA_CAPTURED" ]; then
        echo -e "${GREEN}✓ Router Advertisements detected!${NC}"
        echo "$RA_CAPTURED"
    else
        echo -e "${RED}✗ No Router Advertisements detected${NC}"
        echo "Network may not support SLAAC or uses DHCPv6-only"
    fi
else
    echo -e "${YELLOW}⚠ tcpdump not available, skipping RA check${NC}"
fi
echo ""

# Test 3: DHCPv6 Detection
echo -e "${BLUE}=== Step 5: Testing DHCPv6 ===${NC}"

# Flush addresses again
echo "Flushing IPv6 addresses for DHCPv6 test..."
ip -6 addr flush dev $WAN_IF scope global

# Check if odhcp6c is available
if ! command -v odhcp6c > /dev/null 2>&1; then
    echo -e "${RED}✗ odhcp6c not found!${NC}"
    echo "Install with: opkg install odhcp6c"
    DHCPV6_WORKS=false
else
    echo "Running DHCPv6 request (15 second timeout)..."

    # Run DHCPv6 request
    if timeout 15 odhcp6c -P 0 -t 15 -v $WAN_IF > /tmp/dhcpv6_test.log 2>&1; then
        echo -e "${GREEN}✓ DHCPv6 SUCCESS! Network supports DHCPv6${NC}"

        # Check assigned addresses
        sleep 2
        DHCPV6_ADDRS=$(ip -6 addr show $WAN_IF scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 || echo "")

        if [ -n "$DHCPV6_ADDRS" ]; then
            echo "DHCPv6 addresses obtained:"
            echo "$DHCPV6_ADDRS" | while read addr; do
                echo -e "  ${GREEN}$addr${NC}"
            done
        else
            echo -e "${YELLOW}⚠ DHCPv6 succeeded but no addresses assigned${NC}"
            echo "Server may only provide DNS/NTP (info-only mode)"
        fi

        DHCPV6_WORKS=true
    else
        echo -e "${RED}✗ DHCPv6 FAILED - No response from server${NC}"
        echo "This could mean:"
        echo "  1. Network doesn't support DHCPv6"
        echo "  2. No DHCPv6 server available"
        echo "  3. MAC $TEST_MAC not authorized on network"

        # Show debug output
        if [ -f /tmp/dhcpv6_test.log ]; then
            echo ""
            echo "DHCPv6 debug output:"
            cat /tmp/dhcpv6_test.log | tail -20
        fi

        DHCPV6_WORKS=false
    fi
fi
echo ""

# Test 4: Check network authorization
echo -e "${BLUE}=== Step 6: Checking Network Authorization ===${NC}"

# Ping test with spoofed MAC
echo "Testing connectivity with spoofed MAC $TEST_MAC..."

# Try to ping gateway
GATEWAY=$(ip -6 route show dev $WAN_IF | grep default | awk '{print $3}' | head -1)

if [ -n "$GATEWAY" ]; then
    echo "Default IPv6 gateway: $GATEWAY"
    if ping6 -c 3 -W 2 $GATEWAY > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Can ping IPv6 gateway - MAC is authorized${NC}"
    else
        echo -e "${RED}✗ Cannot ping IPv6 gateway - MAC may not be authorized${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No IPv6 default gateway found${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   SUMMARY${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

echo "Test Device MAC: $TEST_MAC"
echo ""

if [ "$SLAAC_WORKS" = true ] && [ "$DHCPV6_WORKS" = true ]; then
    echo -e "${GREEN}✓ DUAL MODE: Network supports BOTH SLAAC and DHCPv6${NC}"
    echo ""
    echo "Recommended gateway configuration:"
    echo "  - Gateway will try SLAAC first (15 second wait)"
    echo "  - If SLAAC succeeds, will use SLAAC address"
    echo "  - Will also run DHCPv6 info-only for DNS/NTP"
    echo "  - If SLAAC fails, will fall back to DHCPv6"

elif [ "$SLAAC_WORKS" = true ]; then
    echo -e "${GREEN}✓ SLAAC-ONLY: Network supports SLAAC (Router Advertisements)${NC}"
    echo ""
    echo "Recommended gateway configuration:"
    echo "  - Gateway will obtain IPv6 via SLAAC"
    echo "  - No DHCPv6 server available"
    echo "  - Current 15-second SLAAC wait time is appropriate"

elif [ "$DHCPV6_WORKS" = true ]; then
    echo -e "${GREEN}✓ DHCPv6-ONLY: Network supports DHCPv6${NC}"
    echo ""
    echo "Recommended gateway configuration:"
    echo "  - Gateway will obtain IPv6 via DHCPv6"
    echo "  - No SLAAC/Router Advertisements available"
    echo "  - Could reduce SLAAC wait time from 15s to 5s"
    echo "  - Add configuration option: SLAAC_WAIT_TIME=5"

else
    echo -e "${RED}✗ PROBLEM: Network does NOT support IPv6 properly${NC}"
    echo ""
    echo "Possible issues:"
    echo "  1. ${RED}MAC $TEST_MAC not authorized on network firewall${NC}"
    echo "     → Register this MAC with your network administrator"
    echo ""
    echo "  2. ${RED}Network is IPv4-only (no IPv6 support)${NC}"
    echo "     → Check with network administrator"
    echo ""
    echo "  3. ${RED}IPv6 configuration issue on gateway${NC}"
    echo "     → Run: diagnose-ipv6-connectivity.sh"
    echo ""
    echo "  4. ${RED}Firewall blocking IPv6 on $WAN_IF${NC}"
    echo "     → Check firewall rules"
fi

echo ""
echo -e "${BLUE}============================================${NC}"
echo ""

# Show current addresses before restoration
echo "Final IPv6 addresses on $WAN_IF (before MAC restoration):"
ip -6 addr show $WAN_IF | grep inet6 || echo "  None"
echo ""

# MAC will be restored by trap
echo -e "${YELLOW}Restoring original MAC...${NC}"
