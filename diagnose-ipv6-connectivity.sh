#!/bin/sh
#
# IPv6 Connectivity Diagnostic Script
# Diagnoses why IPv6 address is unreachable
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

printf "${YELLOW}========================================${NC}\n"
printf "${YELLOW}IPv6 Connectivity Diagnostic${NC}\n"
printf "${YELLOW}========================================${NC}\n"
printf "\n"

# Get the target IPv6 from command line or use default
TARGET_IPV6="${1:-2620:10d:c050:100:46b7:d0ff:fea6:64fc}"

echo -e "${BLUE}Using IPv6 address: $TARGET_IPV6${NC}"
echo -e "${YELLOW}(Provide different address as argument: $0 <ipv6_address>)${NC}"
echo ""

echo -e "${BLUE}Target IPv6: $TARGET_IPV6${NC}"
echo ""

# 1. Check if IPv6 is configured on eth0
echo -e "${YELLOW}1. Checking if IPv6 is configured on eth0...${NC}"
ETH0_IPV6=$(ip -6 addr show eth0 | grep -v fe80 | grep inet6 | awk '{print $2}' | cut -d/ -f1)

if echo "$ETH0_IPV6" | grep -q "$TARGET_IPV6"; then
    echo -e "${GREEN}✓ IPv6 $TARGET_IPV6 IS configured on eth0${NC}"
else
    echo -e "${RED}✗ IPv6 $TARGET_IPV6 NOT found on eth0${NC}"
    echo -e "${YELLOW}  IPv6 addresses on eth0:${NC}"
    ip -6 addr show eth0 | grep inet6 | while read line; do
        echo -e "${YELLOW}    $line${NC}"
    done
    echo ""
    echo -e "${RED}FIX: The IPv6 address must be configured on eth0!${NC}"
    echo -e "${YELLOW}  Run: ip -6 addr add $TARGET_IPV6/64 dev eth0${NC}"
fi
echo ""

# 2. Check Proxy NDP
echo -e "${YELLOW}2. Checking Proxy NDP for $TARGET_IPV6...${NC}"
PROXY_NDP=$(ip -6 neigh show proxy | grep "$TARGET_IPV6")

if [ -n "$PROXY_NDP" ]; then
    echo -e "${GREEN}✓ Proxy NDP enabled for $TARGET_IPV6${NC}"
    echo -e "${BLUE}  $PROXY_NDP${NC}"
else
    echo -e "${RED}✗ Proxy NDP NOT enabled for $TARGET_IPV6${NC}"
    echo -e "${RED}FIX: Enable Proxy NDP${NC}"
    echo -e "${YELLOW}  Run: ip -6 neigh add proxy $TARGET_IPV6 dev eth0${NC}"
fi
echo ""

# 3. Check IPv6 routing
echo -e "${YELLOW}3. Checking IPv6 routes...${NC}"
echo -e "${BLUE}IPv6 routes on eth0:${NC}"
ip -6 route show dev eth0 | head -5
echo ""

# 4. Check IPv6 neighbor table
echo -e "${YELLOW}4. Checking IPv6 neighbor table...${NC}"
echo -e "${BLUE}IPv6 neighbors on eth0:${NC}"
ip -6 neigh show dev eth0 | head -10
echo ""

# 5. Test local ping
echo -e "${YELLOW}5. Testing local ping to $TARGET_IPV6...${NC}"
ping6 -c 2 -I eth0 "$TARGET_IPV6" 2>&1 | tail -3
echo ""

# 6. Check if interface responds to NDP
echo -e "${YELLOW}6. Checking if eth0 responds to Neighbor Solicitation...${NC}"
echo -e "${BLUE}This requires the address to be properly configured${NC}"
echo ""

# 7. Check IPv6 forwarding
echo -e "${YELLOW}7. Checking IPv6 forwarding settings...${NC}"
ALL_FORWARD=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
ETH0_FORWARD=$(cat /proc/sys/net/ipv6/conf/eth0/forwarding)
echo -e "${BLUE}  all.forwarding: $ALL_FORWARD${NC}"
echo -e "${BLUE}  eth0.forwarding: $ETH0_FORWARD${NC}"

if [ "$ALL_FORWARD" = "1" ]; then
    echo -e "${GREEN}✓ IPv6 forwarding enabled globally${NC}"
else
    echo -e "${YELLOW}⚠ IPv6 forwarding disabled globally${NC}"
fi
echo ""

# 8. Check accept_ra
echo -e "${YELLOW}8. Checking IPv6 accept_ra (Router Advertisement)...${NC}"
ACCEPT_RA=$(cat /proc/sys/net/ipv6/conf/eth0/accept_ra)
echo -e "${BLUE}  eth0.accept_ra: $ACCEPT_RA${NC}"

if [ "$ACCEPT_RA" -ge "1" ]; then
    echo -e "${GREEN}✓ Router Advertisement enabled on eth0${NC}"
else
    echo -e "${YELLOW}⚠ Router Advertisement disabled on eth0${NC}"
fi
echo ""

# 9. Check default IPv6 route
echo -e "${YELLOW}9. Checking default IPv6 route...${NC}"
DEFAULT_ROUTE=$(ip -6 route show default)
if [ -n "$DEFAULT_ROUTE" ]; then
    echo -e "${GREEN}✓ Default IPv6 route exists${NC}"
    echo -e "${BLUE}  $DEFAULT_ROUTE${NC}"
else
    echo -e "${RED}✗ No default IPv6 route${NC}"
fi
echo ""

# 10. Summary and recommendations
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Summary & Recommendations${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check if IPv6 is on eth0
if ! echo "$ETH0_IPV6" | grep -q "$TARGET_IPV6"; then
    echo -e "${RED}CRITICAL: IPv6 not configured on eth0${NC}"
    echo -e "${YELLOW}Fix:${NC}"
    echo -e "  1. Add IPv6 to eth0:"
    echo -e "     ${BLUE}ip -6 addr add $TARGET_IPV6/64 dev eth0${NC}"
    echo -e "  2. Enable Proxy NDP:"
    echo -e "     ${BLUE}ip -6 neigh add proxy $TARGET_IPV6 dev eth0${NC}"
    echo -e "  3. Restart gateway service:"
    echo -e "     ${BLUE}/etc/init.d/ipv4-ipv6-gateway restart${NC}"
fi

# Check Proxy NDP
if [ -z "$PROXY_NDP" ]; then
    echo -e "${RED}CRITICAL: Proxy NDP not enabled${NC}"
    echo -e "${YELLOW}Fix:${NC}"
    echo -e "  ${BLUE}ip -6 neigh add proxy $TARGET_IPV6 dev eth0${NC}"
fi

# Check if address is tentative (DAD in progress)
TENTATIVE=$(ip -6 addr show eth0 | grep "$TARGET_IPV6" | grep tentative)
if [ -n "$TENTATIVE" ]; then
    echo -e "${YELLOW}WARNING: IPv6 address is tentative (DAD in progress)${NC}"
    echo -e "${YELLOW}Wait a few seconds for Duplicate Address Detection to complete${NC}"
fi

echo ""
echo -e "${BLUE}To test from remote machine:${NC}"
echo -e "  ${YELLOW}ping6 $TARGET_IPV6${NC}"
echo ""
