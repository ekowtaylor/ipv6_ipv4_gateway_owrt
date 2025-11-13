#!/bin/bash
#
# Quick Deploy Script - Deploy from your computer to the router
#
# Usage from your computer:
#   ./quick-deploy.sh                    # Safe mode (manual start)
#   ./quick-deploy.sh --auto-start       # Auto-start service
#   ./quick-deploy.sh --full-auto        # Full automation
#

set -e

# Configuration
ROUTER_IP="${ROUTER_IP:-192.168.1.1}"
ROUTER_USER="${ROUTER_USER:-root}"
INSTALL_MODE="${1:---auto-start}"  # Default to auto-start mode

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv4↔IPv6 Gateway Quick Deploy${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}Target: $ROUTER_USER@$ROUTER_IP${NC}"
echo -e "${BLUE}Mode: $INSTALL_MODE${NC}\n"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check required files exist
echo -e "${YELLOW}Checking files...${NC}"
REQUIRED_FILES=(
    "install.sh"
    "ipv4_ipv6_gateway.py"
    "gateway_config.py"
    "gateway_api_server.py"
    "diagnose-and-fix.sh"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        echo -e "${RED}Error: $file not found in $SCRIPT_DIR${NC}"
        exit 1
    fi
    echo "  ✓ $file"
done
echo ""

# Note: Configuration check
echo -e "${YELLOW}Configuration notes...${NC}"
echo -e "  ${BLUE}ℹ Single-Device Mode: API is optional${NC}"
echo -e "  ${BLUE}ℹ Use gateway-status-direct for console access${NC}"
echo ""

# Copy files to router
echo -e "${YELLOW}Copying files to router...${NC}"
scp "$SCRIPT_DIR"/*.py "$SCRIPT_DIR"/*.sh "$ROUTER_USER@$ROUTER_IP:/tmp/" || {
    echo -e "${RED}Failed to copy files. Is SSH working?${NC}"
    echo "Try: ssh $ROUTER_USER@$ROUTER_IP"
    exit 1
}
echo -e "${GREEN}✓ Files copied${NC}\n"

# Run installer on router
echo -e "${YELLOW}Running installer on router...${NC}"
ssh "$ROUTER_USER@$ROUTER_IP" "cd /tmp && bash install.sh $INSTALL_MODE" || {
    echo -e "${RED}Installation failed. Check output above.${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Test if service is responding
echo -e "${YELLOW}Testing service...${NC}"
if ssh "$ROUTER_USER@$ROUTER_IP" "gateway-status >/dev/null 2>&1"; then
    echo -e "${GREEN}✓ Service is responding!${NC}\n"

    echo -e "${YELLOW}Service Status:${NC}"
    ssh "$ROUTER_USER@$ROUTER_IP" "gateway-status" || true
else
    echo -e "${YELLOW}⚠ Service may still be starting or needs manual start${NC}"
    echo -e "${YELLOW}  SSH to router and check: tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
fi

echo ""
echo -e "${BLUE}Quick Commands:${NC}"
echo "  ssh $ROUTER_USER@$ROUTER_IP                    # SSH to router"
echo "  ssh $ROUTER_USER@$ROUTER_IP gateway-status     # Check status"
echo "  ssh $ROUTER_USER@$ROUTER_IP gateway-devices    # List devices"
echo ""
echo -e "${YELLOW}IMPORTANT - Network Configuration:${NC}"
echo "The gateway service is installed but network configuration"
echo "needs to be applied to configure eth1 (192.168.1.1) and eth0 (DHCPv6)."
echo ""
echo "Run diagnostic and apply fixes from router:"
echo "  ssh $ROUTER_USER@$ROUTER_IP"
echo "  /tmp/diagnose-and-fix.sh               # Run diagnostic"
echo "  /tmp/diagnose-and-fix.sh --fix-all     # Apply all fixes"
echo ""
echo -e "${GREEN}Deployment successful!${NC}"
