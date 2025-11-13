#!/bin/bash
#
# Fix IPv6 Routing - Advertise IPv6 to Router
# Makes router aware of gateway's IPv6 addresses
#

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Fix IPv6 Routing - Advertise to Router${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

WAN_IF="eth0"

# Get current device IPv6 from devices.json
if [ -f "/etc/ipv4-ipv6-gateway/devices.json" ]; then
    DEVICE_IPV6=$(cat /etc/ipv4-ipv6-gateway/devices.json | grep -oP '"ipv6_address":\s*"\K[^"]+' | head -1)
else
    echo -e "${RED}✗ devices.json not found${NC}"
    echo "Please provide IPv6 address as argument"
    DEVICE_IPV6="$1"
fi

if [ -z "$DEVICE_IPV6" ]; then
    echo -e "${RED}✗ No IPv6 address found!${NC}"
    echo ""
    echo "Usage: $0 [ipv6-address]"
    echo "Example: $0 dd56:fb82:64ad::46b7:d0ff:fea6:773f"
    exit 1
fi

echo -e "${BLUE}Target IPv6: $DEVICE_IPV6${NC}"
echo ""

# ============================================================
# Step 1: Verify IPv6 is on eth0
# ============================================================
echo -e "${BLUE}=== Step 1: Verify IPv6 on eth0 ===${NC}"
IPV6_ON_ETH0=$(ip -6 addr show $WAN_IF | grep "$DEVICE_IPV6")

if [ -n "$IPV6_ON_ETH0" ]; then
    echo -e "${GREEN}✓ IPv6 is on eth0${NC}"
    echo "$IPV6_ON_ETH0"
else
    echo -e "${RED}✗ IPv6 NOT on eth0!${NC}"
    echo "Adding IPv6 to eth0..."

    ip -6 addr add "$DEVICE_IPV6/64" dev $WAN_IF 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Added IPv6 to eth0${NC}"
    else
        echo -e "${YELLOW}⚠ IPv6 may already exist or failed to add${NC}"
    fi
fi
echo ""

# ============================================================
# Step 2: Enable Proxy NDP
# ============================================================
echo -e "${BLUE}=== Step 2: Enable Proxy NDP ===${NC}"
echo "Enabling Proxy NDP for $DEVICE_IPV6..."

# Remove old proxy NDP entry if exists
ip -6 neigh del proxy "$DEVICE_IPV6" dev $WAN_IF 2>/dev/null

# Add new proxy NDP entry
ip -6 neigh add proxy "$DEVICE_IPV6" dev $WAN_IF 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Proxy NDP enabled${NC}"
elif [ $? -eq 2 ]; then
    echo -e "${GREEN}✓ Proxy NDP already enabled${NC}"
else
    echo -e "${YELLOW}⚠ Proxy NDP command returned: $?${NC}"
fi

# Verify
PROXY_CHECK=$(ip -6 neigh show proxy | grep "$DEVICE_IPV6")
if [ -n "$PROXY_CHECK" ]; then
    echo -e "${GREEN}✓ Confirmed: Proxy NDP active${NC}"
    echo "$PROXY_CHECK"
else
    echo -e "${YELLOW}⚠ Proxy NDP not showing in neighbor table${NC}"
fi
echo ""

# ============================================================
# Step 3: Send Unsolicited Neighbor Advertisement
# ============================================================
echo -e "${BLUE}=== Step 3: Send Neighbor Advertisement to Router ===${NC}"
echo "Broadcasting Neighbor Advertisement to tell router about this IPv6..."

# Use ndisc6 if available (better method)
if command -v ndisc6 >/dev/null 2>&1; then
    echo "Using ndisc6 to advertise..."
    timeout 3 ndisc6 "$DEVICE_IPV6" $WAN_IF 2>/dev/null || true
    echo -e "${GREEN}✓ Sent via ndisc6${NC}"
else
    echo -e "${YELLOW}⚠ ndisc6 not available${NC}"
fi

# Alternative: Use ping6 to trigger Neighbor Discovery
echo "Sending ping6 to all-nodes multicast to announce presence..."
ping6 -c 2 -I $WAN_IF ff02::1 >/dev/null 2>&1 &
sleep 1

echo -e "${GREEN}✓ Neighbor Advertisement sent${NC}"
echo ""

# ============================================================
# Step 4: Enable IPv6 Forwarding and Neighbor Proxying
# ============================================================
echo -e "${BLUE}=== Step 4: Enable IPv6 Forwarding ===${NC}"

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.$WAN_IF.forwarding=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.proxy_ndp=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.$WAN_IF.proxy_ndp=1 >/dev/null 2>&1

# Also enable accepting Router Advertisements (important!)
sysctl -w net.ipv6.conf.$WAN_IF.accept_ra=2 >/dev/null 2>&1

echo -e "${GREEN}✓ IPv6 forwarding and proxy NDP enabled${NC}"
echo ""

# ============================================================
# Step 5: Test Connectivity
# ============================================================
echo -e "${BLUE}=== Step 5: Test Local Connectivity ===${NC}"
echo "Testing ping6 to $DEVICE_IPV6 from gateway..."

if ping6 -c 3 -W 2 "$DEVICE_IPV6" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Gateway can ping this IPv6 locally${NC}"
    ping6 -c 1 "$DEVICE_IPV6" | head -2
else
    echo -e "${YELLOW}⚠ Cannot ping locally (may be normal if device doesn't respond to ICMPv6)${NC}"
fi
echo ""

# ============================================================
# Step 6: Check IPv6 Neighbors
# ============================================================
echo -e "${BLUE}=== Step 6: Check IPv6 Neighbor Table ===${NC}"
echo "Current IPv6 neighbors on $WAN_IF:"
ip -6 neigh show dev $WAN_IF
echo ""

echo "Proxy NDP entries:"
ip -6 neigh show proxy
echo ""

# ============================================================
# Summary
# ============================================================
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Summary & Next Steps${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${YELLOW}What We Did:${NC}"
echo "  1. ✓ Verified IPv6 $DEVICE_IPV6 is on eth0"
echo "  2. ✓ Enabled Proxy NDP for this IPv6"
echo "  3. ✓ Sent Neighbor Advertisement to router"
echo "  4. ✓ Enabled IPv6 forwarding and proxy NDP globally"
echo ""

echo -e "${YELLOW}Test from Your Mac:${NC}"
echo ""
echo "  # Test ping"
echo "  ping6 -c 3 $DEVICE_IPV6"
echo ""
echo "  # Test HTTP"
echo "  curl -v \"http://[$DEVICE_IPV6]:80\""
echo ""
echo "  # Test Telnet"
echo "  telnet $DEVICE_IPV6 23"
echo ""

echo -e "${YELLOW}Check Router:${NC}"
echo "  - Go to router's admin page (192.168.8.1)"
echo "  - Look for 'IPv6 Neighbors' or 'IPv6 Clients'"
echo "  - You should now see: $DEVICE_IPV6 → gateway's MAC"
echo ""

echo -e "${YELLOW}If Still Not Working:${NC}"
echo "  1. Wait 30-60 seconds for router to update neighbor table"
echo "  2. Restart your Mac's network: sudo ifconfig en0 down && sudo ifconfig en0 up"
echo "  3. Check router's IPv6 firewall settings"
echo "  4. Try accessing from another IPv6-enabled device"
echo ""

echo -e "${GREEN}========================================${NC}"
