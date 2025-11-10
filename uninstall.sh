#!/bin/bash
#
# uninstall.sh — Safely uninstall the IPv4↔IPv6 Gateway Service
# and restore the device to normal OpenWrt operation.
#
# This script:
#   - Stops and disables the gateway service
#   - Removes service files and helper scripts
#   - Restores network configuration to defaults
#   - Cleans up logs and working directories
#   - Leaves a backup of configs under /root/gateway_backup_<date>
#
# Run as root:  sh uninstall.sh

set -e

SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
INIT_SCRIPT="/etc/init.d/${SERVICE_NAME}"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
BACKUP_DIR="/root/gateway_backup_$(date +%Y%m%d_%H%M%S)"

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}IPv4↔IPv6 Gateway Uninstaller${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root.${NC}"
    exit 1
fi

# Step 1: Stop the service
echo -e "${YELLOW}Step 1: Stopping service (if running)...${NC}"
if [ -x "$INIT_SCRIPT" ]; then
    $INIT_SCRIPT stop || true
fi
if command -v systemctl &>/dev/null && [ -f "$SYSTEMD_SERVICE" ]; then
    systemctl stop $SERVICE_NAME || true
    systemctl disable $SERVICE_NAME || true
fi
echo -e "${GREEN}✓ Service stopped${NC}"

# Step 2: Backup configuration and logs
echo -e "${YELLOW}Step 2: Backing up configuration and logs...${NC}"
mkdir -p "$BACKUP_DIR"
if [ -d "$CONFIG_DIR" ]; then
    cp -r "$CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
fi
if [ -f "$LOG_FILE" ]; then
    cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true
fi
echo -e "${GREEN}✓ Backup saved at: ${BACKUP_DIR}${NC}"

# Step 3: Remove files and directories
echo -e "${YELLOW}Step 3: Removing installed files...${NC}"
rm -rf "$INSTALL_DIR" || true
rm -rf "$CONFIG_DIR" || true
rm -f "$INIT_SCRIPT" || true
rm -f "$SYSTEMD_SERVICE" || true
rm -f "$LOG_FILE" || true
rm -rf "/var/run/$SERVICE_NAME" || true

# Remove helper scripts
rm -f /usr/local/bin/gateway-status || true
rm -f /usr/local/bin/gateway-devices || true
echo -e "${GREEN}✓ Removed all service and helper files${NC}"

# Step 4: Restore default network config
DEFAULT_NET_CFG="/etc/config/network"
BACKUP_NET_CFG="${BACKUP_DIR}/network.backup"

echo -e "${YELLOW}Step 4: Restoring default OpenWrt network config...${NC}"

if [ -f "$DEFAULT_NET_CFG" ]; then
    cp "$DEFAULT_NET_CFG" "$BACKUP_NET_CFG"
fi

# Basic default LAN + WAN restore
cat > "$DEFAULT_NET_CFG" << 'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fd00::/48'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
	option ip6assign '60'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'eth0'

config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'

config interface 'wan6'
	option device 'eth1'
	option proto 'dhcpv6'
EOF

echo -e "${GREEN}✓ Default network configuration restored${NC}"

# Step 5: Reload network
echo -e "${YELLOW}Step 5: Restarting network service...${NC}"
/etc/init.d/network restart || true
echo -e "${GREEN}✓ Network restarted${NC}"

# Step 6: Remove autostart entries
echo -e "${YELLOW}Step 6: Cleaning autostart entries...${NC}"
if [ -x /etc/rc.common ]; then
    rm -f /etc/rc.d/*${SERVICE_NAME} || true
fi
echo -e "${GREEN}✓ Autostart cleaned${NC}"

# Step 7: Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Uninstallation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}System restored to default OpenWrt configuration.${NC}"
echo -e "${YELLOW}Backup saved at:${NC} ${BACKUP_DIR}"
echo ""
echo -e "${YELLOW}You can reinstall later using:${NC}"
echo "   sh install.sh"
echo ""