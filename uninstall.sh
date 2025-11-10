#!/bin/bash
#
# uninstall.sh — Safely uninstall the IPv4↔IPv6 Gateway Service
# and clean up all installed components.
#
# Default:
#   - Stops and disables the service
#   - Removes service files, configs, logs, helper scripts
#   - DOES NOT touch /etc/config/network
#
# Optional:
#   --restore-network (or --reset-network)
#       Restore a safe network config using this priority:
#         1) network.original from install backup
#         2) /rom/etc/config/network (factory)
#         3) Synthesized default using existing UCI device names
#
# Run as root:  sh uninstall.sh [--restore-network]

set -e

SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
INIT_SCRIPT="/etc/init.d/${SERVICE_NAME}"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
RUN_DIR="/var/run/${SERVICE_NAME}"

BACKUP_DIR="/root/ipv4-ipv6-gateway_backup_$(date +%Y%m%d_%H%M%S)"
RESTORE_NETWORK=0

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Parse arguments ---------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --restore-network|--reset-network)
            RESTORE_NETWORK=1
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--restore-network]"
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

# Backup installed tree and configs
[ -d "$INSTALL_DIR" ]             && cp -a "$INSTALL_DIR"              "$BACKUP_DIR/" 2>/dev/null || true
[ -d "$CONFIG_DIR" ]              && cp -a "$CONFIG_DIR"               "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$LOG_FILE" ]                && cp    "$LOG_FILE"                 "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$INIT_SCRIPT" ]             && cp    "$INIT_SCRIPT"              "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$SYSTEMD_SERVICE" ]         && cp    "$SYSTEMD_SERVICE"          "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/usr/bin/gateway-status" ]  && cp "/usr/bin/gateway-status"      "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/usr/bin/gateway-devices" ] && cp "/usr/bin/gateway-devices"     "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/etc/config/network" ]      && cp "/etc/config/network"          "$BACKUP_DIR/network.current" 2>/dev/null || true

echo -e "${GREEN}✓ Backup saved to: ${BACKUP_DIR}${NC}\n"

# Path where install.sh stored original network config
INSTALL_NET_BACKUP="$BACKUP_DIR/ipv4-ipv6-gateway/network.original"

# --- Helper: simple LAN/WAN check --------------------------------------------
check_lan_wan() {
    echo -e "${YELLOW}Post-restore network check:${NC}"

    if command -v ifstatus >/dev/null 2>&1; then
        echo -e "${BLUE}- ifstatus lan:${NC}"
        ifstatus lan 2>/dev/null || echo "  (lan interface not defined)"
        echo ""
        echo -e "${BLUE}- ifstatus wan:${NC}"
        ifstatus wan 2>/dev/null || echo "  (wan interface not defined)"
    else
        echo -e "${BLUE}- ip -4 addr show:${NC}"
        ip -4 addr show || true
    fi

    echo ""
    echo -e "${YELLOW}If LAN seems down, connect a host directly and try 192.168.1.1/24.${NC}"
}

# --- Step 3: Optional network restore ----------------------------------------
if [ "$RESTORE_NETWORK" -eq 1 ]; then
    echo -e "${YELLOW}Step 3: Restoring network configuration...${NC}"

    DEFAULT_NET_CFG="/etc/config/network"
    NET_BEFORE="${BACKUP_DIR}/network.before_restore"

    # Backup current network config before changing it
    if [ -f "$DEFAULT_NET_CFG" ]; then
        cp "$DEFAULT_NET_CFG" "$NET_BEFORE"
        echo -e "${BLUE}- Current /etc/config/network backed up to: ${NET_BEFORE}${NC}"
    fi

    if [ -f "$INSTALL_NET_BACKUP" ]; then
        echo -e "${BLUE}- Restoring network from install backup: ${INSTALL_NET_BACKUP}${NC}"
        cp "$INSTALL_NET_BACKUP" "$DEFAULT_NET_CFG"

    elif [ -f "/rom/etc/config/network" ]; then
        echo -e "${BLUE}- Restoring factory network config from /rom/etc/config/network${NC}"
        cp /rom/etc/config/network "$DEFAULT_NET_CFG"

    else
        echo -e "${BLUE}- No install backup or /rom config found; building a sane default using existing devices...${NC}"

        LAN_DEV=""
        WAN_DEV=""

        if command -v uci >/dev/null 2>&1; then
            LAN_DEV=$(uci get network.lan.device 2>/dev/null || uci get network.lan.ifname 2>/dev/null || echo "")
            WAN_DEV=$(uci get network.wan.device 2>/dev/null || uci get network.wan.ifname 2>/dev/null || echo "")
        fi

        [ -z "$LAN_DEV" ] && LAN_DEV="eth0"
        [ -z "$WAN_DEV" ] && WAN_DEV="eth1"

        echo -e "${BLUE}- Using LAN device: ${LAN_DEV}${NC}"
        echo -e "${BLUE}- Using WAN device: ${WAN_DEV}${NC}"

        cat > "$DEFAULT_NET_CFG" << EOF
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
	list ports '${LAN_DEV}'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
	option ip6assign '60'

config interface 'wan'
	option device '${WAN_DEV}'
	option proto 'dhcp'

config interface 'wan6'
	option device '${WAN_DEV}'
	option proto 'dhcpv6'
EOF
    fi

    echo -e "${BLUE}- Restarting network and core services...${NC}"
    /etc/init.d/network restart || true
    /etc/init.d/dnsmasq restart 2>/dev/null || true
    /etc/init.d/odhcpd restart 2>/dev/null || true

    # Try to bring detected devices up (best-effort)
    if command -v uci >/dev/null 2>&1; then
        LAN_DEV2=$(uci get network.lan.device 2>/dev/null || uci get network.lan.ifname 2>/dev/null || echo "")
        WAN_DEV2=$(uci get network.wan.device 2>/dev/null || uci get network.wan.ifname 2>/dev/null || echo "")
        [ -n "$LAN_DEV2" ] && ip link set "$LAN_DEV2" up 2>/dev/null || true
        [ -n "$WAN_DEV2" ] && ip link set "$WAN_DEV2" up 2>/dev/null || true
    fi

    sleep 3
    echo -e "${GREEN}✓ Network restore attempt complete${NC}\n"
    check_lan_wan
else
    echo -e "${YELLOW}Step 3: Skipping network restore (use --restore-network to revert to original).${NC}\n"
fi

# --- Step 4: Remove installed files ------------------------------------------
echo -e "${YELLOW}Step 4: Removing installed files...${NC}"

rm -rf "$INSTALL_DIR"           || true
rm -rf "$CONFIG_DIR"            || true
rm -f  "$INIT_SCRIPT"           || true
rm -f  "$SYSTEMD_SERVICE"       || true
rm -f  "$LOG_FILE"              || true
rm -rf "$RUN_DIR"               || true
rm -f  /usr/bin/gateway-status  || true
rm -f  /usr/bin/gateway-devices || true

echo -e "${GREEN}✓ Service, configs, logs, and helper scripts removed${NC}\n"

# --- Step 5: Final summary ----------------------------------------------------
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Uninstallation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Backup directory:${NC}  ${BACKUP_DIR}"
echo ""
if [ "$RESTORE_NETWORK" -eq 1 ]; then
    echo -e "${YELLOW}Network config was restored using the best available source.${NC}"
    echo "If connectivity is odd, inspect:"
    echo "  /etc/config/network"
    echo "  ${BACKUP_DIR}/network.before_restore"
    echo "  ${BACKUP_DIR}/ipv4-ipv6-gateway/network.original (install snapshot)"
else
    echo -e "${YELLOW}Existing network configuration was left unchanged.${NC}"
    echo "If needed, you can manually restore from:"
    echo "  ${BACKUP_DIR}/network.current"
fi
echo ""
echo -e "${YELLOW}To reinstall later, run:${NC}"
echo "  sh install.sh"
echo ""