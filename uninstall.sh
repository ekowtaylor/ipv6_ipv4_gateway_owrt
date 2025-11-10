#!/bin/bash
#
# uninstall.sh — Safely uninstall the IPv4↔IPv6 Gateway Service
# and clean up all installed components.
#
# By default:
#   - Stops and disables the service
#   - Removes service files, configs, logs, helper scripts
#   - Leaves your existing network config alone
#
# Optional:
#   --reset-network  Restore a default OpenWrt-style /etc/config/network
#
# Run as root:  sh uninstall.sh [--reset-network]

set -e

SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
INIT_SCRIPT="/etc/init.d/${SERVICE_NAME}"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
RUN_DIR="/var/run/${SERVICE_NAME}"

BACKUP_DIR="/root/ipv4-ipv6-gateway_backup_$(date +%Y%m%d_%H%M%S)"
RESET_NETWORK=0

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Parse arguments ---------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --reset-network)
            RESET_NETWORK=1
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--reset-network]"
            exit 1
            ;;
    esac
done

# --- Init system detection ---------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
else
    INIT_SYSTEM="initd"
fi

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}IPv4↔IPv6 Gateway Uninstaller${NC}"
echo -e "${YELLOW}========================================${NC}"
echo -e "${BLUE}Detected init system: ${INIT_SYSTEM}${NC}\n"

# --- Root check --------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root.${NC}"
    exit 1
fi

# --- Step 1: Stop and disable service ----------------------------------------
echo -e "${YELLOW}Step 1: Stopping and disabling service...${NC}"

# init.d
if [ -x "$INIT_SCRIPT" ]; then
    echo -e "${BLUE}- Stopping init.d service...${NC}"
    "$INIT_SCRIPT" stop || true
    "$INIT_SCRIPT" disable || true
fi

# systemd
if [ "$INIT_SYSTEM" = "systemd" ] && [ -f "$SYSTEMD_SERVICE" ]; then
    echo -e "${BLUE}- Stopping systemd service...${NC}"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi

echo -e "${GREEN}✓ Service stopped and disabled (where applicable)${NC}\n"

# --- Step 2: Backup everything relevant --------------------------------------
echo -e "${YELLOW}Step 2: Backing up configuration, logs, and service files...${NC}"
mkdir -p "$BACKUP_DIR"

[ -d "$INSTALL_DIR" ]      && cp -a "$INSTALL_DIR"      "$BACKUP_DIR/" 2>/dev/null || true
[ -d "$CONFIG_DIR" ]       && cp -a "$CONFIG_DIR"       "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$LOG_FILE" ]         && cp    "$LOG_FILE"         "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$INIT_SCRIPT" ]      && cp    "$INIT_SCRIPT"      "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$SYSTEMD_SERVICE" ]  && cp    "$SYSTEMD_SERVICE"  "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/usr/bin/gateway-status" ]  && cp "/usr/bin/gateway-status"  "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/usr/bin/gateway-devices" ] && cp "/usr/bin/gateway-devices" "$BACKUP_DIR/" 2>/dev/null || true

echo -e "${GREEN}✓ Backup saved to: ${BACKUP_DIR}${NC}\n"

# --- Step 3: Remove installed files ------------------------------------------
echo -e "${YELLOW}Step 3: Removing installed files...${NC}"

rm -rf "$INSTALL_DIR"         || true
rm -rf "$CONFIG_DIR"          || true
rm -f  "$INIT_SCRIPT"         || true
rm -f  "$SYSTEMD_SERVICE"     || true
rm -f  "$LOG_FILE"            || true
rm -rf "$RUN_DIR"             || true
rm -f  /usr/bin/gateway-status   || true
rm -f  /usr/bin/gateway-devices  || true

echo -e "${GREEN}✓ Service, configs, logs, and helper scripts removed${NC}\n"

# --- Step 4: Optional network reset ------------------------------------------
if [ "$RESET_NETWORK" -eq 1 ]; then
    echo -e "${YELLOW}Step 4: Restoring default OpenWrt-style network config...${NC}"

    DEFAULT_NET_CFG="/etc/config/network"
    NET_BACKUP="${BACKUP_DIR}/network.before_reset"

    # Backup current network config if present
    if [ -f "$DEFAULT_NET_CFG" ]; then
        cp "$DEFAULT_NET_CFG" "$NET_BACKUP"
        echo -e "${BLUE}- Current /etc/config/network backed up to: ${NET_BACKUP}${NC}"
    fi

    # Write a sane default config (bridge LAN on eth0, WAN on eth1)
    cat > "$DEFAULT_NET_CFG" << 'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fd00::/48'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'eth0'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
	option ip6assign '60'

config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'

config interface 'wan6'
	option device 'eth1'
	option proto 'dhcpv6'
EOF

    echo -e "${BLUE}- Restarting network...${NC}"
    /etc/init.d/network restart || true

    echo -e "${GREEN}✓ Network configuration reset to default-style layout${NC}\n"
else
    echo -e "${YELLOW}Step 4: Skipping network reset (use --reset-network to restore defaults).${NC}\n"
fi

# --- Step 5: Final summary ----------------------------------------------------
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Uninstallation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Backup directory:${NC}  ${BACKUP_DIR}"
echo ""
if [ "$RESET_NETWORK" -eq 1 ]; then
    echo -e "${YELLOW}Network config was reset. You should now be able to reach the router at:${NC}"
    echo "  http://192.168.1.1  (LAN side, 192.168.1.0/24)"
else
    echo -e "${YELLOW}Existing network configuration was left unchanged.${NC}"
    echo "If something looks off, you can manually inspect /etc/config/network"
    echo "or re-run this script with:  $0 --reset-network"
fi
echo ""
echo -e "${YELLOW}To reinstall later, run:${NC}"
echo "  sh install.sh"
echo ""