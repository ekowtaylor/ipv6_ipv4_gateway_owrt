#!/bin/bash
#
# Check MAC Spoofing Status
#

echo "═══════════════════════════════════════════════════════════"
echo "MAC Spoofing Status Check"
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

echo -e "${BLUE}1. Current MAC Addresses${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "eth0 (WAN) MAC address:"
ip link show eth0 | grep ether
CURRENT_WAN_MAC=$(ip link show eth0 | grep ether | awk '{print $2}')
echo "  Current: $CURRENT_WAN_MAC"
echo ""

echo "eth1 (LAN) MAC address:"
ip link show eth1 | grep ether
CURRENT_LAN_MAC=$(ip link show eth1 | grep ether | awk '{print $2}')
echo "  Current: $CURRENT_LAN_MAC"
echo ""

echo -e "${BLUE}2. Original MAC (from config)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if [ -f /etc/ipv4-ipv6-gateway/original_wan_mac.txt ]; then
    ORIGINAL_MAC=$(cat /etc/ipv4-ipv6-gateway/original_wan_mac.txt)
    echo "Original WAN MAC: $ORIGINAL_MAC"
else
    echo -e "${YELLOW}⚠ original_wan_mac.txt not found${NC}"
    ORIGINAL_MAC="unknown"
fi
echo ""

echo -e "${BLUE}3. Device State (device.json)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    echo "Device state file exists:"
    cat /etc/ipv4-ipv6-gateway/device.json | python3 -m json.tool 2>/dev/null || cat /etc/ipv4-ipv6-gateway/device.json

    DEVICE_MAC=$(cat /etc/ipv4-ipv6-gateway/device.json | grep mac_address | cut -d'"' -f4)
    echo ""
    echo "Device MAC from state: $DEVICE_MAC"
else
    echo -e "${YELLOW}⚠ device.json not found - no device configured${NC}"
    DEVICE_MAC="none"
fi
echo ""

echo -e "${BLUE}4. MAC Comparison${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Original WAN MAC:  $ORIGINAL_MAC"
echo "Current WAN MAC:   $CURRENT_WAN_MAC"
echo "Device MAC:        $DEVICE_MAC"
echo ""

if [ "$DEVICE_MAC" != "none" ]; then
    if [ "$CURRENT_WAN_MAC" = "$DEVICE_MAC" ]; then
        echo -e "${GREEN}✓ WAN MAC is spoofed correctly!${NC}"
    else
        echo -e "${RED}✗ WAN MAC is NOT spoofed!${NC}"
        echo "  Expected: $DEVICE_MAC"
        echo "  Actual:   $CURRENT_WAN_MAC"
    fi
fi
echo ""

echo -e "${BLUE}5. netifd (OpenWrt Network Manager) Check${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "UCI network.wan.macaddr setting:"
uci get network.wan.macaddr 2>/dev/null || echo "  (not set)"
echo ""

echo "UCI network.wan.device setting:"
uci get network.wan.device 2>/dev/null || echo "  (not set)"
echo ""

echo "netifd status for wan interface:"
ubus call network.interface.wan status 2>/dev/null | grep -E "up|device|mac" || echo "  (ubus not available)"
echo ""

echo -e "${BLUE}6. Recent Gateway Logs (MAC spoofing related)${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    echo "Last 20 lines related to MAC:"
    grep -i "mac\|spoof" /var/log/ipv4-ipv6-gateway.log | tail -20
else
    echo -e "${YELLOW}⚠ Gateway log not found${NC}"
fi
echo ""

echo -e "${BLUE}7. IPv6 Status on eth0${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "IPv6 addresses on eth0:"
ip -6 addr show eth0
echo ""

echo "IPv6 disabled status:"
cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6
echo "  (0=enabled, 1=disabled)"
echo ""

echo "accept_ra status:"
cat /proc/sys/net/ipv6/conf/eth0/accept_ra
echo "  (0=off, 1=on, 2=always)"
echo ""

echo -e "${BLUE}8. Process Check${NC}"
echo "───────────────────────────────────────────────────────────"
echo ""

echo "Gateway service running:"
if pgrep -f ipv4_ipv6_gateway.py >/dev/null; then
    echo -e "${GREEN}✓ Running${NC}"
    ps w | grep ipv4_ipv6_gateway.py | grep -v grep
else
    echo -e "${RED}✗ Not running${NC}"
fi
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "DIAGNOSIS"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ "$DEVICE_MAC" = "none" ]; then
    echo -e "${YELLOW}No device configured yet${NC}"
    echo "  - Wait for device to connect to eth1"
    echo "  - Check: tail -f /var/log/ipv4-ipv6-gateway.log"
elif [ "$CURRENT_WAN_MAC" != "$DEVICE_MAC" ]; then
    echo -e "${RED}MAC SPOOFING FAILED!${NC}"
    echo ""
    echo "Possible causes:"
    echo "  1. netifd (OpenWrt network manager) is resetting the MAC"
    echo "  2. UCI network.wan.macaddr is set to a different MAC"
    echo "  3. Another process is changing the MAC"
    echo ""
    echo "Recommended fixes:"
    echo ""
    echo "Fix 1: Disable netifd control of eth0"
    echo "  uci set network.wan.auto='0'"
    echo "  uci commit network"
    echo "  /etc/init.d/network reload"
    echo ""
    echo "Fix 2: Set MAC in UCI (let netifd manage it)"
    echo "  uci set network.wan.macaddr='$DEVICE_MAC'"
    echo "  uci commit network"
    echo "  /etc/init.d/network reload"
    echo ""
    echo "Fix 3: Check for other processes:"
    echo "  ps w | grep -E 'eth0|network'"
else
    echo -e "${GREEN}✓ MAC spoofing is working${NC}"
    echo ""
    if ! ip -6 addr show eth0 | grep -q "scope global"; then
        echo -e "${YELLOW}⚠ But no IPv6 global address${NC}"
        echo "  Check upstream network provides IPv6"
        echo "  Run: ping6 google.com (with original MAC)"
    fi
fi

echo ""
