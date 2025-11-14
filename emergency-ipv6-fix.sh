#!/bin/bash
#
# EMERGENCY IPv6 FIX - Run this on the gateway to get IPv6 on eth0 NOW!
#
# This script forces IPv6 allocation on eth0 by:
# 1. Checking current IPv6 kernel settings
# 2. Disabling OpenWrt netifd interference
# 3. Setting accept_ra=2 (CRITICAL for forwarding mode!)
# 4. Triggering Router Solicitation
# 5. Verifying IPv6 was obtained
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}EMERGENCY IPv6 FIX FOR eth0${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Step 1: Show current state
echo -e "${BLUE}Step 1: Current IPv6 State${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}Current IPv6 addresses on eth0:${NC}"
ip -6 addr show eth0 | grep inet6 || echo "  (none found)"
echo ""

echo -e "${YELLOW}Current IPv6 sysctl settings:${NC}"
echo "  disable_ipv6:  $(sysctl -n net.ipv6.conf.eth0.disable_ipv6 2>/dev/null || echo 'unknown')"
echo "  accept_ra:     $(sysctl -n net.ipv6.conf.eth0.accept_ra 2>/dev/null || echo 'unknown')"
echo "  autoconf:      $(sysctl -n net.ipv6.conf.eth0.autoconf 2>/dev/null || echo 'unknown')"
echo "  forwarding:    $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 'unknown')"
echo ""

# Step 2: Check if netifd is managing eth0
echo -e "${BLUE}Step 2: Check OpenWrt netifd${NC}"
echo "----------------------------------------"

if command -v uci >/dev/null 2>&1; then
    WAN_DEVICE=$(uci get network.wan.device 2>/dev/null || uci get network.wan.ifname 2>/dev/null || echo "")
    if [ "$WAN_DEVICE" = "eth0" ]; then
        echo -e "${YELLOW}⚠ WARNING: OpenWrt netifd IS managing eth0!${NC}"
        echo ""
        echo "This can interfere with IPv6 settings!"
        echo ""
        echo "Option 1: Configure IPv6 via UCI (recommended for OpenWrt):"
        echo "  uci set network.wan.accept_ra='2'"
        echo "  uci set network.wan.send_rs='1'"
        echo "  uci commit network"
        echo "  /etc/init.d/network restart"
        echo ""
        echo "Option 2: Disable netifd management of eth0 (manual control)"
        echo ""
        read -p "Apply Option 1 now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Configuring IPv6 via UCI...${NC}"
            uci set network.wan.accept_ra='2'
            uci set network.wan.send_rs='1'
            uci commit network
            echo -e "${GREEN}✓ UCI configured${NC}"
            echo ""
            echo -e "${BLUE}Restarting network...${NC}"
            /etc/init.d/network restart
            sleep 5
            echo -e "${GREEN}✓ Network restarted${NC}"
            echo ""
            echo "Proceeding with manual fix as well (belt and suspenders)..."
        fi
    else
        echo -e "${GREEN}✓ netifd not managing eth0 (device: ${WAN_DEVICE:-none})${NC}"
    fi
else
    echo -e "${BLUE}ℹ UCI not available (not OpenWrt?)${NC}"
fi
echo ""

# Step 3: Apply kernel settings
echo -e "${BLUE}Step 3: Apply IPv6 Kernel Settings${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}Applying critical IPv6 settings...${NC}"

# CRITICAL: Set accept_ra=2 FIRST before enabling anything else!
# This is THE FIX for the forwarding conflict!
sysctl -w net.ipv6.conf.eth0.accept_ra=2
sysctl -w net.ipv6.conf.all.accept_ra=2

# Enable autoconf (SLAAC)
sysctl -w net.ipv6.conf.eth0.autoconf=1

# Ensure IPv6 not disabled
sysctl -w net.ipv6.conf.eth0.disable_ipv6=0

echo -e "${GREEN}✓ Applied settings:${NC}"
echo "  accept_ra=2 (accept RA even with forwarding) ← THE CRITICAL FIX!"
echo "  autoconf=1 (enable SLAAC)"
echo "  disable_ipv6=0 (IPv6 enabled)"
echo ""

# Step 4: Verify forwarding state
echo -e "${BLUE}Step 4: Check Forwarding State${NC}"
echo "----------------------------------------"

FORWARDING=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "0")
echo "IPv6 forwarding: $FORWARDING"

if [ "$FORWARDING" = "1" ]; then
    echo -e "${GREEN}✓ Forwarding enabled (gateway mode)${NC}"
    echo -e "${YELLOW}  This is WHY accept_ra=2 is required!${NC}"
    echo "  (With forwarding=1 and accept_ra=1, RAs are ignored)"
else
    echo -e "${BLUE}ℹ Forwarding disabled (will be enabled when gateway starts)${NC}"
fi
echo ""

# Step 5: Trigger Router Solicitation
echo -e "${BLUE}Step 5: Request IPv6 from Router${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}Sending Router Solicitation to ff02::2 (all-routers)...${NC}"

if command -v ping6 >/dev/null 2>&1; then
    # Send multiple RS to increase chances
    for i in 1 2 3; do
        ping6 -c 1 -W 2 -I eth0 ff02::2 >/dev/null 2>&1 || true
        echo "  Attempt $i/3..."
        sleep 1
    done
    echo -e "${GREEN}✓ Router Solicitations sent${NC}"
else
    echo -e "${YELLOW}⚠ ping6 not available${NC}"
fi
echo ""

# Alternative: Try rdisc6 if available
if command -v rdisc6 >/dev/null 2>&1; then
    echo -e "${BLUE}Using rdisc6 to explicitly request Router Advertisement...${NC}"
    timeout 5 rdisc6 eth0 2>/dev/null || echo "  (rdisc6 timed out or no response)"
    echo ""
fi

# Step 6: Wait for SLAAC
echo -e "${BLUE}Step 6: Wait for SLAAC${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}Waiting 15 seconds for Router Advertisement and SLAAC...${NC}"
for i in {15..1}; do
    printf "\r  ${i} seconds remaining...  "
    sleep 1
done
echo ""
echo ""

# Step 7: Verify IPv6 obtained
echo -e "${BLUE}Step 7: Verify IPv6 Address${NC}"
echo "----------------------------------------"

ETH0_IPV6=$(ip -6 addr show eth0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print $2}')

if [ -n "$ETH0_IPV6" ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}SUCCESS! IPv6 ADDRESS OBTAINED!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "IPv6 addresses on eth0:"
    echo "$ETH0_IPV6" | while read addr; do
        echo -e "  ${GREEN}✓ $addr${NC}"
    done
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Restart gateway service to use this IPv6:"
    echo "   /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
    echo "2. Verify gateway picks up IPv6:"
    echo "   tail -f /var/log/ipv4-ipv6-gateway.log | grep IPv6"
    echo ""
    echo "3. Check device discovery:"
    echo "   curl http://localhost:5050/devices | python3 -m json.tool"
    echo ""
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}FAILED TO OBTAIN IPv6!${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Current IPv6 addresses on eth0:${NC}"
    ip -6 addr show eth0 | grep inet6 || echo "  (none)"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo ""
    echo "1. Check if router supports IPv6:"
    echo "   - Does router have IPv6 WAN address?"
    echo "   - Are other devices getting IPv6?"
    echo ""
    echo "2. Check router's IPv6 settings:"
    echo "   - Is SLAAC/RA enabled?"
    echo "   - Is DHCPv6 server running?"
    echo ""
    echo "3. Try DHCPv6 instead of SLAAC:"
    if command -v odhcp6c >/dev/null 2>&1; then
        echo "   odhcp6c -v -t 10 eth0"
    else
        echo "   (odhcp6c not installed - install with: opkg install odhcp6c)"
    fi
    echo ""
    echo "4. Check netifd isn't interfering:"
    echo "   logread | grep -i ipv6"
    echo ""
    echo "5. Verify kernel settings stuck:"
    echo "   sysctl -a | grep 'net.ipv6.conf.eth0'"
    echo ""
fi

# Step 8: Show final state
echo -e "${BLUE}Step 8: Final IPv6 State${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}Final sysctl settings:${NC}"
echo "  disable_ipv6:  $(sysctl -n net.ipv6.conf.eth0.disable_ipv6)"
echo "  accept_ra:     $(sysctl -n net.ipv6.conf.eth0.accept_ra)"
echo "  autoconf:      $(sysctl -n net.ipv6.conf.eth0.autoconf)"
echo "  forwarding:    $(sysctl -n net.ipv6.conf.all.forwarding)"
echo ""

echo -e "${YELLOW}All IPv6 addresses on eth0:${NC}"
ip -6 addr show eth0 | grep inet6 || echo "  (none)"
echo ""

echo -e "${YELLOW}IPv6 routes:${NC}"
ip -6 route show | head -5
echo ""

echo "========================================"
echo "Emergency IPv6 Fix Complete!"
echo "========================================"
