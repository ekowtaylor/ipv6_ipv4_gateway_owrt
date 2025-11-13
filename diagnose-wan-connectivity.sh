#!/bin/bash
#
# WAN Connectivity Diagnostic Script
# Diagnoses why WAN IP cannot be pinged from WAN network
#

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}WAN Connectivity Diagnostic${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get WAN interface (eth0)
WAN_IF="eth0"

echo -e "${BLUE}=== Step 1: Check WAN Interface Status ===${NC}"
echo "Interface: $WAN_IF"
echo ""

# Check if interface exists and is up
if ip link show $WAN_IF >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Interface $WAN_IF exists${NC}"

    # Check if it's UP
    if ip link show $WAN_IF | grep -q "state UP"; then
        echo -e "${GREEN}✓ Interface $WAN_IF is UP${NC}"
    else
        echo -e "${RED}✗ Interface $WAN_IF is DOWN!${NC}"
        echo "Fix: ip link set $WAN_IF up"
    fi
else
    echo -e "${RED}✗ Interface $WAN_IF does not exist!${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}=== Step 2: Check IP Address on WAN ===${NC}"
WAN_IP=$(ip -4 addr show $WAN_IF | grep inet | awk '{print $2}' | cut -d/ -f1)

if [ -n "$WAN_IP" ]; then
    echo -e "${GREEN}✓ WAN IP assigned: $WAN_IP${NC}"
else
    echo -e "${RED}✗ No IP address assigned to $WAN_IF!${NC}"
    echo "Fix: Run DHCP client or assign static IP"
    exit 1
fi

# Get subnet mask
WAN_CIDR=$(ip -4 addr show $WAN_IF | grep inet | awk '{print $2}')
echo "   Full CIDR: $WAN_CIDR"

echo ""
echo -e "${BLUE}=== Step 3: Check Default Route ===${NC}"
DEFAULT_GW=$(ip route | grep default | grep $WAN_IF | awk '{print $3}')

if [ -n "$DEFAULT_GW" ]; then
    echo -e "${GREEN}✓ Default gateway: $DEFAULT_GW${NC}"
else
    echo -e "${YELLOW}⚠ No default gateway via $WAN_IF${NC}"
fi

echo ""
echo -e "${BLUE}=== Step 4: Test Ping from Gateway to WAN Network ===${NC}"

# Ping gateway
if [ -n "$DEFAULT_GW" ]; then
    echo "Pinging default gateway ($DEFAULT_GW)..."
    if ping -c 2 -W 2 $DEFAULT_GW >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Can ping gateway $DEFAULT_GW${NC}"
    else
        echo -e "${RED}✗ Cannot ping gateway $DEFAULT_GW${NC}"
        echo "   This indicates a Layer 2 (ARP/Ethernet) problem"
    fi
else
    echo -e "${YELLOW}⚠ Skipping (no default gateway)${NC}"
fi

# Ping the client trying to reach us (if provided)
CLIENT_IP="192.168.8.230"
echo ""
echo "Pinging client ($CLIENT_IP)..."
if ping -c 2 -W 2 $CLIENT_IP >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Can ping client $CLIENT_IP${NC}"
else
    echo -e "${RED}✗ Cannot ping client $CLIENT_IP${NC}"
    echo "   Check if client is reachable on WAN network"
fi

echo ""
echo -e "${BLUE}=== Step 5: Check ARP Table on WAN ===${NC}"
echo "ARP entries for $WAN_IF:"
ip neigh show dev $WAN_IF
echo ""

# Check if client is in ARP table
if ip neigh show dev $WAN_IF | grep -q "$CLIENT_IP"; then
    echo -e "${GREEN}✓ Client $CLIENT_IP is in ARP table${NC}"
    ARP_STATE=$(ip neigh show dev $WAN_IF | grep "$CLIENT_IP" | awk '{print $NF}')
    echo "   State: $ARP_STATE"
else
    echo -e "${YELLOW}⚠ Client $CLIENT_IP NOT in ARP table${NC}"
    echo "   Attempting to ping to add to ARP..."
    ping -c 1 -W 1 $CLIENT_IP >/dev/null 2>&1
    sleep 1
    if ip neigh show dev $WAN_IF | grep -q "$CLIENT_IP"; then
        echo -e "${GREEN}✓ Client added to ARP table${NC}"
    else
        echo -e "${RED}✗ Client still not in ARP table${NC}"
    fi
fi

echo ""
echo -e "${BLUE}=== Step 6: Check Firewall Rules (iptables) ===${NC}"

echo "INPUT chain (affects ping to gateway itself):"
iptables -L INPUT -n -v | grep -E "ICMP|icmp|$WAN_IF|all" | head -10

echo ""
echo "Checking if ICMP is allowed on INPUT:"
if iptables -L INPUT -n | grep -q "ACCEPT.*icmp"; then
    echo -e "${GREEN}✓ ICMP allowed in INPUT chain${NC}"
else
    echo -e "${RED}✗ ICMP may be blocked in INPUT chain${NC}"
    echo "   Add rule: iptables -I INPUT -p icmp -j ACCEPT"
fi

echo ""
echo -e "${BLUE}=== Step 7: Check Reverse Path Filter (rp_filter) ===${NC}"
# rp_filter can block packets if routing is asymmetric
RP_FILTER_ALL=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "N/A")
RP_FILTER_WAN=$(cat /proc/sys/net/ipv4/conf/$WAN_IF/rp_filter 2>/dev/null || echo "N/A")

echo "rp_filter (all): $RP_FILTER_ALL"
echo "rp_filter ($WAN_IF): $RP_FILTER_WAN"

if [ "$RP_FILTER_ALL" = "1" ] || [ "$RP_FILTER_WAN" = "1" ]; then
    echo -e "${YELLOW}⚠ Strict rp_filter enabled (may block responses)${NC}"
    echo "   Disable: sysctl -w net.ipv4.conf.all.rp_filter=0"
    echo "   Disable: sysctl -w net.ipv4.conf.$WAN_IF.rp_filter=0"
else
    echo -e "${GREEN}✓ rp_filter is permissive (0 or 2)${NC}"
fi

echo ""
echo -e "${BLUE}=== Step 8: Check ICMP Echo Settings ===${NC}"
ICMP_ECHO=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null || echo "N/A")
echo "icmp_echo_ignore_all: $ICMP_ECHO"

if [ "$ICMP_ECHO" = "1" ]; then
    echo -e "${RED}✗ ICMP echo is DISABLED (ignoring all pings)${NC}"
    echo "   Enable: sysctl -w net.ipv4.icmp_echo_ignore_all=0"
else
    echo -e "${GREEN}✓ ICMP echo is enabled${NC}"
fi

echo ""
echo -e "${BLUE}=== Step 9: Live Packet Capture Test ===${NC}"
echo "Starting tcpdump on $WAN_IF for ICMP packets..."
echo "Please ping $WAN_IP from client ($CLIENT_IP) now..."
echo "Capturing for 10 seconds..."
echo ""

timeout 10 tcpdump -i $WAN_IF -n icmp 2>/dev/null &
TCPDUMP_PID=$!

echo "Waiting for packets... (press Ctrl+C if you see packets)"
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo -e "${YELLOW}=== Diagnostic Complete ===${NC}"
echo ""
echo -e "${BLUE}Quick Fixes to Try:${NC}"
echo ""
echo "1. Allow ICMP in firewall:"
echo "   iptables -I INPUT -p icmp -j ACCEPT"
echo ""
echo "2. Disable strict reverse path filter:"
echo "   sysctl -w net.ipv4.conf.all.rp_filter=0"
echo "   sysctl -w net.ipv4.conf.$WAN_IF.rp_filter=0"
echo ""
echo "3. Enable ICMP echo:"
echo "   sysctl -w net.ipv4.icmp_echo_ignore_all=0"
echo ""
echo "4. Check if tcpdump showed incoming ICMP requests:"
echo "   - If YES → Gateway receives ping but doesn't respond (firewall issue)"
echo "   - If NO → Ping not reaching gateway (network/routing issue)"
echo ""
