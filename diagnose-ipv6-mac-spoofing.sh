#!/bin/bash
#
# IPv6 MAC Spoofing Diagnostic
# Checks why gateway doesn't get IPv6 after MAC spoofing
#

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv6 MAC Spoofing Diagnostic${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

WAN_IF="eth0"

echo -e "${BLUE}=== Step 1: Check Current MAC on WAN ===${NC}"
CURRENT_MAC=$(ip link show $WAN_IF | grep link/ether | awk '{print $2}')
echo "WAN interface ($WAN_IF) MAC: $CURRENT_MAC"
echo ""

echo -e "${BLUE}=== Step 2: Check IPv6 Addresses on WAN ===${NC}"
echo "IPv6 addresses on $WAN_IF:"
ip -6 addr show $WAN_IF

IPV6_COUNT=$(ip -6 addr show $WAN_IF | grep -c "inet6")
GLOBAL_IPV6=$(ip -6 addr show $WAN_IF | grep "inet6" | grep -v "fe80" | awk '{print $2}' | head -1)

if [ $IPV6_COUNT -eq 0 ]; then
    echo -e "${RED}✗ No IPv6 addresses at all!${NC}"
elif [ -z "$GLOBAL_IPV6" ]; then
    echo -e "${YELLOW}⚠ Only link-local (fe80::) - no global IPv6${NC}"
    echo "  This is the problem - gateway has no global IPv6 address"
else
    echo -e "${GREEN}✓ Has global IPv6: $GLOBAL_IPV6${NC}"
fi
echo ""

echo -e "${BLUE}=== Step 3: Check IPv6 Neighbor Discovery ===${NC}"
echo "IPv6 neighbors on $WAN_IF:"
ip -6 neigh show dev $WAN_IF

ROUTER_COUNT=$(ip -6 neigh show dev $WAN_IF | grep -c "router")
if [ $ROUTER_COUNT -eq 0 ]; then
    echo -e "${RED}✗ No IPv6 router found in neighbor table${NC}"
    echo "  This means router advertisements (RA) are not being received"
else
    echo -e "${GREEN}✓ Found $ROUTER_COUNT IPv6 router(s)${NC}"
fi
echo ""

echo -e "${BLUE}=== Step 4: Check IPv6 Default Route ===${NC}"
DEFAULT_ROUTE=$(ip -6 route show default)

if [ -z "$DEFAULT_ROUTE" ]; then
    echo -e "${RED}✗ No IPv6 default route${NC}"
    echo "  Gateway cannot reach IPv6 internet"
else
    echo -e "${GREEN}✓ IPv6 default route exists:${NC}"
    echo "$DEFAULT_ROUTE"
fi
echo ""

echo -e "${BLUE}=== Step 5: Test Router Advertisement Reception ===${NC}"
echo "Sending Router Solicitation and listening for Router Advertisement..."
echo "This will take 5 seconds..."

if command -v rdisc6 >/dev/null 2>&1; then
    timeout 5 rdisc6 $WAN_IF 2>/dev/null || echo -e "${YELLOW}No RA received in 5s${NC}"
else
    echo -e "${YELLOW}⚠ rdisc6 not installed (package: ndisc6)${NC}"
    echo "Alternative: Listen with tcpdump for RAs..."

    if command -v tcpdump >/dev/null 2>&1; then
        echo "Listening for Router Advertisements (5 seconds)..."
        timeout 5 tcpdump -i $WAN_IF -vvv icmp6 2>/dev/null | grep -i "router advertisement" &
        TCPDUMP_PID=$!
        sleep 5
        kill $TCPDUMP_PID 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠ tcpdump not installed${NC}"
    fi
fi
echo ""

echo -e "${BLUE}=== Step 6: Check DHCPv6 Client Status ===${NC}"
echo "Looking for running DHCPv6 client (odhcp6c)..."
DHCPV6_PROC=$(ps | grep odhcp6c | grep -v grep)

if [ -n "$DHCPV6_PROC" ]; then
    echo -e "${GREEN}✓ DHCPv6 client running:${NC}"
    echo "$DHCPV6_PROC"
else
    echo -e "${YELLOW}⚠ No DHCPv6 client running${NC}"
fi
echo ""

echo -e "${BLUE}=== Step 7: Manually Test SLAAC ===${NC}"
echo "Testing SLAAC address generation from MAC..."

# Calculate expected SLAAC address
MAC_CLEAN=$(echo $CURRENT_MAC | tr -d ':')
if [ ${#MAC_CLEAN} -eq 12 ]; then
    # Convert MAC to modified EUI-64
    # This is complex, just show what we'd expect
    echo "Current MAC: $CURRENT_MAC"
    echo "Expected SLAAC pattern: Should contain MAC fragments"
    echo ""
    echo "Checking if any IPv6 address contains MAC fragments..."

    for FRAG in $(echo $CURRENT_MAC | sed 's/:/ /g'); do
        if ip -6 addr show $WAN_IF | grep -qi "$FRAG"; then
            echo -e "${GREEN}✓ Found MAC fragment '$FRAG' in IPv6 address (SLAAC likely working)${NC}"
        fi
    done
fi
echo ""

echo -e "${BLUE}=== Step 8: Test DHCPv6 Manually ===${NC}"
echo "Attempting DHCPv6 request (10 second timeout)..."

if command -v odhcp6c >/dev/null 2>&1; then
    timeout 10 odhcp6c -s /bin/true -t 10 -v $WAN_IF 2>&1 | head -10 || echo -e "${RED}DHCPv6 request failed${NC}"

    # Check if we got an address
    sleep 1
    NEW_IPV6=$(ip -6 addr show $WAN_IF | grep "inet6" | grep -v "fe80" | awk '{print $2}' | head -1)
    if [ -n "$NEW_IPV6" ]; then
        echo -e "${GREEN}✓ DHCPv6 worked! Got: $NEW_IPV6${NC}"
    else
        echo -e "${RED}✗ DHCPv6 didn't assign an address${NC}"
    fi
else
    echo -e "${RED}✗ odhcp6c not installed${NC}"
fi
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Diagnostic Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Analyze findings
if [ -z "$GLOBAL_IPV6" ]; then
    echo -e "${RED}PRIMARY ISSUE: No global IPv6 address${NC}"
    echo ""
    echo "Possible causes:"
    echo ""

    if [ $ROUTER_COUNT -eq 0 ]; then
        echo "1. ${RED}Router Advertisements not received${NC}"
        echo "   → Router may not trust the spoofed MAC for IPv6"
        echo "   → Try with original gateway MAC first to verify IPv6 works"
        echo ""
    fi

    echo "2. ${YELLOW}MAC spoofing breaks IPv6 neighbor discovery${NC}"
    echo "   → When MAC changes, old link-local conflicts with new"
    echo "   → Router's neighbor cache might be stale"
    echo ""

    echo "3. ${YELLOW}Not waiting long enough after MAC change${NC}"
    echo "   → IPv6 takes longer to establish than IPv4"
    echo "   → Current wait: 2s, may need 10-15s for IPv6"
    echo ""

    echo "4. ${YELLOW}Router has MAC-based filtering for IPv6${NC}"
    echo "   → Only whitelisted MACs can get IPv6"
    echo "   → Check router's IPv6 settings"
    echo ""

    echo -e "${YELLOW}Recommended Fixes:${NC}"
    echo ""
    echo "# Fix 1: Increase wait time after MAC spoofing"
    echo "# Edit ipv4_ipv6_gateway.py:"
    echo "#   wait_time = 0.5 if fast_mode else 15  # Increased from 2 to 15"
    echo ""
    echo "# Fix 2: Flush IPv6 neighbor cache after MAC change"
    echo "ip -6 neigh flush dev $WAN_IF"
    echo ""
    echo "# Fix 3: Send Router Solicitation manually"
    echo "echo 1 > /proc/sys/net/ipv6/conf/$WAN_IF/router_solicitations"
    echo ""
    echo "# Fix 4: Test with original MAC to verify IPv6 works"
    echo "# (Restore original MAC temporarily to test)"
    echo ""

else
    echo -e "${GREEN}✓ Gateway has global IPv6 address!${NC}"
    echo "IPv6 is working with current MAC."
    echo ""
    echo "If this wasn't expected, check:"
    echo "  1. Is this the device's MAC or gateway's original MAC?"
    echo "  2. Did IPv6 come from SLAAC or DHCPv6?"
fi

echo -e "${GREEN}========================================${NC}"
