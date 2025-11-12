#!/bin/sh
#
# Free IPv6 Ports for Gateway Proxying
#
# This script configures OpenWrt services (LuCI web interface and SSH)
# to ONLY listen on IPv4, freeing up IPv6 ports 80, 443, and 22 for
# the gateway's socat proxies.
#
# After running this script:
# - LuCI web interface: accessible on http://192.168.1.1 (IPv4 only)
# - SSH: accessible on 192.168.1.1 (IPv4 only)
# - Gateway socat proxies: can bind to IPv6 ports 80, 443, 22
#
# Run as: sh free-ipv6-ports.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Free IPv6 Ports for Gateway Proxying${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if UCI is available (OpenWrt)
if ! command -v uci >/dev/null 2>&1; then
    echo -e "${RED}UCI not found - this script is for OpenWrt only${NC}"
    exit 1
fi

echo -e "${YELLOW}This script will configure OpenWrt services to free IPv6 ports.${NC}"
echo ""
echo -e "${YELLOW}Changes:${NC}"
echo "  1. LuCI (uhttpd) - Listen on IPv4 ONLY (192.168.1.1:80, :443)"
echo "  2. SSH (dropbear) - Listen on LAN/IPv4 ONLY"
echo "  3. Gateway proxies - Can now bind to IPv6 ports 80, 443, 22"
echo ""
echo -e "${YELLOW}Access after changes:${NC}"
echo "  - LuCI web UI: http://192.168.1.1 (IPv4)"
echo "  - SSH: ssh root@192.168.1.1 (IPv4)"
echo "  - Gateway IPv6 proxies: Will work on ports 80, 443, 22"
echo ""
echo -e "${RED}⚠ WARNING: This will restart web interface and SSH!${NC}"
echo -e "${YELLOW}Continuing in 5 seconds... (Ctrl+C to cancel)${NC}"
sleep 5

# Step 1: Configure uhttpd (LuCI web interface) to IPv4 only
echo ""
echo -e "${YELLOW}Step 1: Configuring LuCI web interface (uhttpd)...${NC}"

# Stop uhttpd
echo -e "${BLUE}- Stopping uhttpd...${NC}"
/etc/init.d/uhttpd stop 2>/dev/null || true

# Backup current uhttpd config
if [ -f /etc/config/uhttpd ]; then
    cp /etc/config/uhttpd /etc/config/uhttpd.backup.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}✓ Backed up uhttpd config${NC}"
fi

# Configure to listen on IPv4 only
echo -e "${BLUE}- Configuring IPv4-only listening...${NC}"

# Set explicit IPv4 addresses for HTTP and HTTPS
uci set uhttpd.main.listen_http='192.168.1.1:80'
uci set uhttpd.main.listen_https='192.168.1.1:443'

# Delete IPv6 listeners
uci delete uhttpd.main.listen_http6 2>/dev/null || true
uci delete uhttpd.main.listen_https6 2>/dev/null || true

# Commit changes
uci commit uhttpd

echo -e "${GREEN}✓ uhttpd configured to listen on IPv4 only${NC}"

# Restart uhttpd
echo -e "${BLUE}- Restarting uhttpd...${NC}"
/etc/init.d/uhttpd start

echo -e "${GREEN}✓ LuCI web interface restarted (IPv4 only)${NC}"
echo -e "${GREEN}  Access at: http://192.168.1.1${NC}"

# Step 2: Configure dropbear (SSH) to LAN/IPv4 only
echo ""
echo -e "${YELLOW}Step 2: Configuring SSH server (dropbear)...${NC}"

# Backup current dropbear config
if [ -f /etc/config/dropbear ]; then
    cp /etc/config/dropbear /etc/config/dropbear.backup.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}✓ Backed up dropbear config${NC}"
fi

# Configure to listen on LAN interface only (which is IPv4)
echo -e "${BLUE}- Configuring LAN-only listening...${NC}"

# Set Interface to 'lan' (restricts to LAN subnet, typically IPv4)
uci set dropbear.@dropbear[0].Interface='lan'

# Also explicitly set to not listen on IPv6
uci set dropbear.@dropbear[0].GatewayPorts='off'

# Commit changes
uci commit dropbear

echo -e "${GREEN}✓ dropbear configured to listen on LAN/IPv4 only${NC}"

# Restart dropbear
echo -e "${BLUE}- Restarting dropbear...${NC}"
/etc/init.d/dropbear restart

echo -e "${GREEN}✓ SSH server restarted (IPv4 only)${NC}"
echo -e "${GREEN}  Access at: ssh root@192.168.1.1${NC}"

# Step 3: Verify ports are freed
echo ""
echo -e "${YELLOW}Step 3: Verifying IPv6 ports are free...${NC}"

# Check what's listening on port 80
PORT_80_USERS=$(netstat -tlnp 2>/dev/null | grep ":80 " | grep -v "192.168.1.1:80" || true)
PORT_443_USERS=$(netstat -tlnp 2>/dev/null | grep ":443 " | grep -v "192.168.1.1:443" || true)
PORT_22_USERS=$(netstat -tlnp 2>/dev/null | grep ":22 " | grep -v grep || true)

if [ -n "$PORT_80_USERS" ]; then
    echo -e "${YELLOW}⚠ Port 80 still in use:${NC}"
    echo "$PORT_80_USERS"
else
    echo -e "${GREEN}✓ Port 80 free on IPv6${NC}"
fi

if [ -n "$PORT_443_USERS" ]; then
    echo -e "${YELLOW}⚠ Port 443 still in use:${NC}"
    echo "$PORT_443_USERS"
else
    echo -e "${GREEN}✓ Port 443 free on IPv6${NC}"
fi

# Note: Port 22 will still show as in use by dropbear on LAN, but only on IPv4
echo -e "${BLUE}ℹ Port 22 may show as in use by dropbear (IPv4 only)${NC}"

# Step 4: Restart gateway service
echo ""
echo -e "${YELLOW}Step 4: Restarting IPv4-IPv6 gateway service...${NC}"

if [ -x /etc/init.d/ipv4-ipv6-gateway ]; then
    /etc/init.d/ipv4-ipv6-gateway restart

    # Wait for service to start
    echo -e "${BLUE}- Waiting for service to start...${NC}"
    sleep 5

    # Check if socat is now running on port 80
    SOCAT_80=$(ps | grep -E 'socat.*TCP6-LISTEN:80' | grep -v grep || true)
    SOCAT_443=$(ps | grep -E 'socat.*TCP6-LISTEN:443' | grep -v grep || true)
    SOCAT_22=$(ps | grep -E 'socat.*TCP6-LISTEN:22' | grep -v grep || true)

    if [ -n "$SOCAT_80" ]; then
        echo -e "${GREEN}✓ Socat proxy running on IPv6 port 80${NC}"
    else
        echo -e "${RED}✗ Socat proxy NOT running on port 80${NC}"
        echo -e "${YELLOW}  Check logs: tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
    fi

    if [ -n "$SOCAT_443" ]; then
        echo -e "${GREEN}✓ Socat proxy running on IPv6 port 443${NC}"
    else
        echo -e "${RED}✗ Socat proxy NOT running on port 443${NC}"
    fi

    if [ -n "$SOCAT_22" ]; then
        echo -e "${GREEN}✓ Socat proxy running on IPv6 port 22${NC}"
    else
        echo -e "${RED}✗ Socat proxy NOT running on port 22${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Gateway service not found at /etc/init.d/ipv4-ipv6-gateway${NC}"
    echo -e "${YELLOW}  Install the gateway first, then re-run this script${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Configuration Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Services configured:${NC}"
echo "  ✓ LuCI (uhttpd) - IPv4 only (http://192.168.1.1)"
echo "  ✓ SSH (dropbear) - IPv4 only (ssh root@192.168.1.1)"
echo "  ✓ Gateway proxies - Can bind to IPv6 ports 80, 443, 22"
echo ""
echo -e "${YELLOW}Test from devvm:${NC}"
echo "  curl -v http://[2620:10d:c050:100:46b7:d0ff:fea6:64fc]:80/"
echo "  curl -kv https://[2620:10d:c050:100:46b7:d0ff:fea6:64fc]:443/"
echo "  ssh root@2620:10d:c050:100:46b7:d0ff:fea6:64fc"
echo ""
echo -e "${YELLOW}Monitor connections:${NC}"
echo "  monitor-connections"
echo "  capture-traffic"
echo ""
echo -e "${YELLOW}View gateway logs:${NC}"
echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
echo -e "${BLUE}Note: If you need to revert, restore from:${NC}"
echo "  /etc/config/uhttpd.backup.*"
echo "  /etc/config/dropbear.backup.*"
echo ""
