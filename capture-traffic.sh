#!/bin/sh
#
# Capture IPv6 Traffic - See if TCP packets are arriving at gateway
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6 Traffic Capture${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Get the device's IPv6 address from gateway logs
IPV6_ADDR=$(tail -100 /var/log/ipv4-ipv6-gateway.log | grep -o '2620:[0-9a-f:]*' | head -1)

if [ -z "$IPV6_ADDR" ]; then
    echo -e "${YELLOW}Could not find IPv6 address in logs${NC}"
    echo -e "${YELLOW}Please enter the device IPv6 address:${NC}"
    read IPV6_ADDR
fi

echo -e "${GREEN}Monitoring IPv6 address: ${IPV6_ADDR}${NC}"
echo ""

# Check if tcpdump is available
if ! command -v tcpdump >/dev/null 2>&1; then
    echo -e "${RED}Error: tcpdump is not installed${NC}"
    echo -e "${YELLOW}Install with: opkg install tcpdump${NC}"
    exit 1
fi

echo -e "${YELLOW}Starting packet capture on eth0...${NC}"
echo "This will show if TCP packets are arriving at the gateway."
echo "Try your curl/telnet command now from devvm."
echo ""
echo -e "${BLUE}Press Ctrl+C to stop${NC}"
echo ""

# Capture IPv6 traffic to/from the device's IPv6 address
# -n: Don't resolve hostnames
# -v: Verbose
# -i eth0: Interface
# ip6: IPv6 only
tcpdump -n -v -i eth0 "ip6 and host $IPV6_ADDR"
