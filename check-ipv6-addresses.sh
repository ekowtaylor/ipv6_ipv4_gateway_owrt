#!/bin/sh
#
# Check IPv6 Address Status - Diagnose why socat can't bind
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6 Address Diagnostic${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check IPv6 addresses on eth0
echo -e "${YELLOW}IPv6 addresses on eth0:${NC}"
ip -6 addr show eth0

echo ""
echo -e "${YELLOW}========================================${NC}"

# Extract device IPv6 from gateway logs
echo -e "${YELLOW}IPv6 addresses from gateway logs:${NC}"
tail -200 /var/log/ipv4-ipv6-gateway.log | grep -E "Successfully obtained IPv6|IPv6.*configured on eth0|Device.*WAN IPv6" | tail -10

echo ""
echo -e "${YELLOW}========================================${NC}"

# Check socat binding errors
echo -e "${YELLOW}Socat binding errors:${NC}"
tail -200 /var/log/ipv4-ipv6-gateway.log | grep -E "Address not available|bind.*failed" | tail -10

echo ""
echo -e "${YELLOW}========================================${NC}"

# Check what IPv6 addresses socat is trying to bind to
echo -e "${YELLOW}IPv6 addresses socat is trying to bind:${NC}"
ps | grep socat | grep -v grep

echo ""
echo -e "${YELLOW}========================================${NC}"

# Show what's needed
echo -e "${YELLOW}Analysis:${NC}"
echo ""
echo -e "${BLUE}1. Check if IPv6 from logs matches IPv6 on eth0${NC}"
echo -e "${BLUE}2. If mismatch: Gateway failed to add IPv6 to eth0${NC}"
echo -e "${BLUE}3. If match but socat fails: Check DAD (Duplicate Address Detection)${NC}"
echo ""

# Check DAD status
echo -e "${YELLOW}IPv6 DAD (Duplicate Address Detection) status:${NC}"
ip -6 addr show eth0 | grep -E "tentative|dadfailed"

if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ No DAD issues found${NC}"
else
    echo -e "${RED}✗ IPv6 addresses in tentative or DAD failed state!${NC}"
    echo -e "${YELLOW}  Addresses are not ready for binding${NC}"
fi

echo ""
echo -e "${YELLOW}========================================${NC}"

# Manual test: Try to add an IPv6 address manually
echo -e "${YELLOW}Manual test - add IPv6 address to eth0:${NC}"
TEST_IPV6=$(tail -100 /var/log/ipv4-ipv6-gateway.log | grep -o '2620:[0-9a-f:]*' | head -1)

if [ -n "$TEST_IPV6" ]; then
    echo -e "${BLUE}Attempting to add: $TEST_IPV6/64 to eth0${NC}"
    ip -6 addr add "$TEST_IPV6/64" dev eth0 2>&1
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✓ Successfully added IPv6 address${NC}"
        
        # Verify it's there
        sleep 1
        if ip -6 addr show eth0 | grep -q "$TEST_IPV6"; then
            echo -e "${GREEN}✓ Confirmed: IPv6 address is present on eth0${NC}"
            
            # Check if it's ready (not tentative)
            if ip -6 addr show eth0 | grep "$TEST_IPV6" | grep -q "tentative"; then
                echo -e "${YELLOW}⚠ IPv6 address is in tentative state (DAD in progress)${NC}"
                echo -e "${YELLOW}  Wait 3-5 seconds for DAD to complete before socat can bind${NC}"
            else
                echo -e "${GREEN}✓ IPv6 address is ready for binding!${NC}"
            fi
        else
            echo -e "${RED}✗ IPv6 address was added but disappeared from eth0!${NC}"
            echo -e "${YELLOW}  This suggests kernel is removing it (possible causes:${NC}"
            echo "  - Duplicate address detected on network"
            echo "  - Router advertisement conflict"
            echo "  - IPv6 forwarding or accept_ra settings"
        fi
    else
        echo -e "${RED}✗ Failed to add IPv6 address${NC}"
        echo -e "${YELLOW}  Check error above for details${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Could not find IPv6 address in gateway logs${NC}"
fi

echo ""
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Recommended actions:${NC}"
echo ""
echo "1. Check IPv6 settings:"
echo "   sysctl net.ipv6.conf.eth0.accept_ra"
echo "   sysctl net.ipv6.conf.eth0.forwarding"
echo ""
echo "2. If addresses disappear, check router advertisements:"
echo "   tcpdump -i eth0 -vv 'icmp6 and ip6[40] == 134'"
echo ""
echo "3. Restart gateway with verbose logging:"
echo "   /etc/init.d/ipv4-ipv6-gateway restart"
echo "   tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
