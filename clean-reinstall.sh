#!/bin/bash
#
# Clean Reinstall Script - Uninstall + Fresh Install
# This script completely removes the old gateway and installs a fresh copy
#
# Usage:
#   ./clean-reinstall.sh              # Interactive (recommended)
#   ./clean-reinstall.sh --auto       # Fully automatic
#

set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

AUTO_MODE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --auto)
            AUTO_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--auto]"
            echo ""
            echo "This script performs a clean reinstall of the IPv4↔IPv6 Gateway:"
            echo "  1. Stops the service"
            echo "  2. Backs up configuration"
            echo "  3. Uninstalls completely (removes all files and rules)"
            echo "  4. Installs fresh from current directory"
            echo "  5. Starts the service"
            echo ""
            echo "Options:"
            echo "  --auto    Fully automatic (no prompts)"
            echo "  --help    Show this help"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Clean Reinstall - IPv4↔IPv6 Gateway${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "install.sh" ] || [ ! -f "uninstall.sh" ]; then
    echo -e "${RED}Error: install.sh or uninstall.sh not found${NC}"
    echo -e "${YELLOW}Make sure you're in the project directory${NC}"
    exit 1
fi

# Confirm with user
if [ "$AUTO_MODE" = false ]; then
    echo -e "${YELLOW}This will:${NC}"
    echo "  1. Stop the gateway service"
    echo "  2. Backup all configs to /root/ipv4-ipv6-gateway_backup_*"
    echo "  3. Completely uninstall (remove files, flush iptables rules)"
    echo "  4. Fresh install from current directory"
    echo "  5. Start the service"
    echo ""
    echo -e "${RED}⚠ WARNING: This will disconnect any active device!${NC}"
    echo ""
    read -p "Continue? (yes/no): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 1: Uninstalling Old Gateway${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Run uninstall script
if [ -f "uninstall.sh" ]; then
    bash uninstall.sh
    echo ""
    echo -e "${GREEN}✓ Uninstall completed${NC}"
else
    echo -e "${RED}✗ uninstall.sh not found!${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 2: Cleaning up any remaining state${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Extra cleanup (belt and suspenders)
echo -e "${YELLOW}Flushing any remaining iptables rules...${NC}"

# Kill any stray processes
pkill -f ipv4_ipv6_gateway.py 2>/dev/null || true
pkill -f socat.*TCP6-LISTEN 2>/dev/null || true

# Flush remaining NAT rules for gateway ports
for PORT in 8080 2323 8443 2222 5900 3389; do
    COUNT=0
    while iptables -t nat -D PREROUTING -p tcp --dport $PORT -j DNAT 2>/dev/null; do
        COUNT=$((COUNT + 1))
    done
    [ $COUNT -gt 0 ] && echo "  Removed $COUNT extra rule(s) for port $PORT"
done

# Flush remaining FORWARD rules
COUNT=0
while iptables -D FORWARD -d 192.168.1.0/24 -j ACCEPT 2>/dev/null; do
    COUNT=$((COUNT + 1))
done
[ $COUNT -gt 0 ] && echo "  Removed $COUNT extra FORWARD rule(s)"

echo -e "${GREEN}✓ Extra cleanup completed${NC}"
echo ""

# Small delay to ensure everything is cleaned up
sleep 2

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 3: Installing Fresh Gateway${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Run install script
if [ -f "install.sh" ]; then
    # Install with auto-start
    bash install.sh --auto-start
    echo ""
    echo -e "${GREEN}✓ Fresh install completed${NC}"
else
    echo -e "${RED}✗ install.sh not found!${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 4: Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Wait for service to start
echo -e "${YELLOW}Waiting 5 seconds for service to initialize...${NC}"
sleep 5

# Check service status
echo -e "${BLUE}Checking service status...${NC}"
if /etc/init.d/ipv4-ipv6-gateway status >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Service is running${NC}"
else
    echo -e "${RED}✗ Service may not be running${NC}"
    echo -e "${YELLOW}  Check logs: tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
fi

# Check for clean iptables rules
echo ""
echo -e "${BLUE}Checking iptables rules...${NC}"
RULE_COUNT=$(iptables -t nat -L PREROUTING -n | grep -E "8080|2323|2222" | wc -l)
if [ "$RULE_COUNT" -eq 3 ]; then
    echo -e "${GREEN}✓ Exactly 3 port forwarding rules (clean!)${NC}"
elif [ "$RULE_COUNT" -gt 3 ]; then
    echo -e "${YELLOW}⚠ Warning: Found $RULE_COUNT rules (expected 3)${NC}"
    echo -e "${YELLOW}  There may be duplicates${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Found $RULE_COUNT rules (expected 3)${NC}"
    echo -e "${YELLOW}  Rules may not be set up yet (device not connected?)${NC}"
fi

# Check for IPv6 NAT support
echo ""
echo -e "${BLUE}Checking IPv6 NAT support...${NC}"
if ip6tables -t nat -L >/dev/null 2>&1; then
    echo -e "${GREEN}✓ IPv6 NAT is available${NC}"
else
    echo -e "${RED}✗ IPv6 NAT is NOT available${NC}"
    echo -e "${YELLOW}  IPv6 proxy will not work properly${NC}"
    echo -e "${YELLOW}  Run: opkg install kmod-ipt-nat6 kmod-nf-nat6${NC}"
fi

# Show recent logs
echo ""
echo -e "${BLUE}Recent gateway logs (last 20 lines):${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
tail -20 /var/log/ipv4-ipv6-gateway.log 2>/dev/null || echo "(No logs yet)"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Clean Reinstall Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Connect a device to eth1 (LAN port)"
echo "  2. Watch logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo "  3. Check device state: cat /etc/ipv4-ipv6-gateway/device.json"
echo "  4. Debug if needed: debug-port-forwarding.sh"
echo ""

echo -e "${YELLOW}Useful Commands:${NC}"
echo "  gateway-status              # Check status"
echo "  gateway-devices             # List devices"
echo "  debug-port-forwarding.sh    # Debug IPv4 port forwarding"
echo "  debug-connections.sh        # Debug IPv6 connections"
echo ""

echo -e "${GREEN}Done! 🎉${NC}"
echo ""
