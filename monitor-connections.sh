#!/bin/sh
#
# Connection Monitor - Real-time monitoring of incoming IPv6 connections
# Shows every connection attempt to the gateway
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6 Connection Monitor${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Monitoring incoming IPv6 connections..."
echo "Press Ctrl+C to stop"
echo ""

# Tail the gateway log and filter for socat connection messages
tail -f /var/log/ipv4-ipv6-gateway.log | grep --line-buffered -E "listening on|accepting|connect|N accepted|E " | while read line; do
    timestamp=$(echo "$line" | awk '{print $1, $2}')

    # Highlight different message types
    if echo "$line" | grep -q "listening on"; then
        echo -e "${GREEN}[$timestamp]${NC} ${line#*- }"
    elif echo "$line" | grep -q "N accepted"; then
        echo -e "${YELLOW}[$timestamp]${NC} ${line#*- }"
    elif echo "$line" | grep -q "E "; then
        echo -e "${RED}[$timestamp]${NC} ${line#*- }"
    else
        echo -e "${BLUE}[$timestamp]${NC} ${line#*- }"
    fi
done
