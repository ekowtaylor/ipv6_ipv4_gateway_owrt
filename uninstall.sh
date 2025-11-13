#!/bin/bash
#
# uninstall.sh — Safely uninstall the IPv4↔IPv6 Gateway Service
# and clean up all installed componenso ts.
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

# CRITICAL: Restore original MAC address on eth0
# The gateway may have spoofed a device's MAC for network authentication
# We need to restore the gateway's original MAC before uninstalling
echo -e "${BLUE}- Restoring original MAC address on eth0 (if saved)...${NC}"

# Try to find saved original MAC from device store
if [ -f "$CONFIG_DIR/devices.json" ]; then
    # Extract any MAC that was saved before spoofing
    # The gateway stores its work in devices.json, but original MAC isn't there
    # So we'll try to get it from the network backup if available
    echo -e "${BLUE}  Checking for saved original MAC...${NC}"
fi

# Check if there's a network interface backup with original MAC
if [ -f "$CONFIG_DIR/network.original" ]; then
    echo -e "${BLUE}  Found network backup, checking for MAC info...${NC}"
fi

# Best effort: Try to reset eth0 MAC to a predictable state
# Option 1: Read from device-tree or system
if [ -d "/sys/class/net/eth0" ]; then
    echo -e "${BLUE}  Attempting to restore eth0 MAC address...${NC}"

    # Try to get permanent MAC address from device
    if [ -f "/sys/class/net/eth0/address" ]; then
        CURRENT_MAC=$(cat /sys/class/net/eth0/address 2>/dev/null || echo "")
        echo -e "${BLUE}  Current eth0 MAC: ${CURRENT_MAC}${NC}"
    fi

    # Check if there's a permanent address stored
    if [ -f "/sys/class/net/eth0/perm_addr" ]; then
        PERM_MAC=$(cat /sys/class/net/eth0/perm_addr 2>/dev/null || echo "")
        if [ -n "$PERM_MAC" ] && [ "$PERM_MAC" != "00:00:00:00:00:00" ]; then
            echo -e "${BLUE}  Hardware/Permanent MAC: ${PERM_MAC}${NC}"

            # Only restore if current MAC is different
            if [ "$CURRENT_MAC" != "$PERM_MAC" ]; then
                echo -e "${YELLOW}  Restoring hardware MAC address to eth0...${NC}"
                ip link set eth0 down 2>/dev/null || true
                ip link set eth0 address "$PERM_MAC" 2>/dev/null || true
                ip link set eth0 up 2>/dev/null || true

                # Verify
                NEW_MAC=$(cat /sys/class/net/eth0/address 2>/dev/null || echo "")
                if [ "$NEW_MAC" = "$PERM_MAC" ]; then
                    echo -e "${GREEN}  ✓ Restored hardware MAC address: ${PERM_MAC}${NC}"
                else
                    echo -e "${YELLOW}  ⚠ Failed to restore MAC (may require reboot)${NC}"
                fi
            else
                echo -e "${GREEN}  ✓ eth0 already has hardware MAC address${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ No permanent MAC address found in sysfs${NC}"
            echo -e "${YELLOW}  ⚠ Manual MAC restoration may be required after uninstall${NC}"
            echo -e "${YELLOW}  ⚠ Rebooting the gateway will restore the hardware MAC${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ /sys/class/net/eth0/perm_addr not available${NC}"
        echo -e "${YELLOW}  ⚠ Recommend rebooting to restore hardware MAC address${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ eth0 interface not found in sysfs${NC}"
fi

# Kill any remaining socat processes (IPv6→IPv4 proxies)
echo -e "${BLUE}- Stopping IPv6→IPv4 socat proxies...${NC}"
SOCAT_PIDS=$(ps | grep -E 'socat.*TCP6-LISTEN.*TCP4:' | grep -v grep | awk '{print $1}')
if [ -n "$SOCAT_PIDS" ]; then
    echo "$SOCAT_PIDS" | while read pid; do
        kill "$pid" 2>/dev/null || true
    done
    echo -e "${GREEN}✓ Stopped $(echo "$SOCAT_PIDS" | wc -l) socat proxy processes${NC}"
else
    echo -e "${BLUE}  (No socat proxies found)${NC}"
fi

# Kill any remaining HAProxy processes (IPv6→IPv4 proxies)
echo -e "${BLUE}- Stopping HAProxy proxies...${NC}"
HAPROXY_PIDS=$(ps | grep -E 'haproxy.*\/etc\/haproxy' | grep -v grep | awk '{print $1}')
if [ -n "$HAPROXY_PIDS" ]; then
    echo "$HAPROXY_PIDS" | while read pid; do
        kill "$pid" 2>/dev/null || true
    done
    echo -e "${GREEN}✓ Stopped $(echo "$HAPROXY_PIDS" | wc -l) HAProxy processes${NC}"
else
    echo -e "${BLUE}  (No HAProxy processes found)${NC}"
fi

# Remove HAProxy config
if [ -f "/etc/haproxy/haproxy.cfg" ]; then
    rm -f "/etc/haproxy/haproxy.cfg"
    echo -e "${GREEN}✓ Removed HAProxy configuration${NC}"
fi

# CRITICAL: Clean up iptables/ip6tables rules (SURGICAL - only gateway rules)
echo -e "${BLUE}- Cleaning up gateway firewall rules (iptables/ip6tables)...${NC}"

if command -v iptables >/dev/null 2>&1; then
    echo -e "${BLUE}  Removing gateway-specific iptables rules...${NC}"

    # Try to read device info from state file to know what rules to remove
    if [ -f "$CONFIG_DIR/device.json" ]; then
        echo -e "${BLUE}    Reading device state for cleanup...${NC}"
        # Extract IPs if possible (use python/jq if available, otherwise best effort)
        if command -v python3 >/dev/null 2>&1; then
            WAN_IPV4=$(python3 -c "import json; f=open('$CONFIG_DIR/device.json'); d=json.load(f); print(d.get('wan_ipv4',''))" 2>/dev/null || echo "")
            LAN_IPV4=$(python3 -c "import json; f=open('$CONFIG_DIR/device.json'); d=json.load(f); print(d.get('lan_ipv4',''))" 2>/dev/null || echo "")
        fi
    fi

    # Remove port forwarding rules (check common ports used by gateway)
    # Ports from gateway_config.py: 8080:80, 2323:23, 8443:443, 2222:22, 5900:5900, 3389:3389
    for GW_PORT in 8080 2323 8443 2222 5900 3389; do
        # Try to delete DNAT rules for these ports (will fail silently if not present)
        iptables -t nat -D PREROUTING -p tcp --dport $GW_PORT -j DNAT 2>/dev/null || true
    done

    # If we know the LAN IP, remove FORWARD rules for it
    if [ -n "$LAN_IPV4" ]; then
        for DEV_PORT in 80 23 443 22 5900 3389; do
            iptables -D FORWARD -p tcp -d $LAN_IPV4 --dport $DEV_PORT -j ACCEPT 2>/dev/null || true
        done
        echo -e "${GREEN}    ✓ Removed FORWARD rules for $LAN_IPV4${NC}"
    fi

    echo -e "${GREEN}  ✓ Removed gateway-specific iptables rules${NC}"
fi

if command -v ip6tables >/dev/null 2>&1; then
    echo -e "${BLUE}  Removing gateway-specific ip6tables SNAT rules...${NC}"

    # Remove IPv6 SNAT rules (these are specific to the gateway)
    # Try to read LAN IP from state
    if [ -f "$CONFIG_DIR/device.json" ] && [ -z "$LAN_IPV4" ]; then
        if command -v python3 >/dev/null 2>&1; then
            LAN_IPV4=$(python3 -c "import json; f=open('$CONFIG_DIR/device.json'); d=json.load(f); print(d.get('lan_ipv4',''))" 2>/dev/null || echo "")
        fi
    fi

    # Remove SNAT rules for common device ports (80, 23)
    if [ -n "$LAN_IPV4" ]; then
        for PORT in 80 23; do
            ip6tables -t nat -D POSTROUTING -d $LAN_IPV4 -p tcp --dport $PORT -j SNAT --to-source 192.168.1.1 2>/dev/null || true
        done
        echo -e "${GREEN}    ✓ Removed IPv6 SNAT rules for $LAN_IPV4${NC}"
    else
        # Best effort - try common LAN IPs
        for LAN in 192.168.1.100 192.168.1.101 192.168.1.102; do
            for PORT in 80 23; do
                ip6tables -t nat -D POSTROUTING -d $LAN -p tcp --dport $PORT -j SNAT --to-source 192.168.1.1 2>/dev/null || true
            done
        done
        echo -e "${GREEN}    ✓ Attempted removal of IPv6 SNAT rules (best effort)${NC}"
    fi

    echo -e "${GREEN}  ✓ Removed gateway-specific ip6tables rules${NC}"
fi

# NOTE: We do NOT flush entire chains - that would break other firewall rules!
echo -e "${BLUE}  Existing firewall rules preserved (only gateway rules removed)${NC}"

# CRITICAL: Flush connection tracking table
echo -e "${BLUE}- Flushing connection tracking table...${NC}"
if [ -f /proc/net/nf_conntrack ]; then
    # Flush conntrack entries
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -F 2>/dev/null || true
        echo -e "${GREEN}  ✓ Flushed conntrack table${NC}"
    else
        # Alternative: write to sysctl
        echo 1 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
        sleep 1
        echo 262144 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
        echo -e "${GREEN}  ✓ Reset conntrack table${NC}"
    fi
else
    echo -e "${BLUE}  (Connection tracking not active)${NC}"
fi

# CRITICAL: Clean up IPv6 addresses on eth0
echo -e "${BLUE}- Cleaning up IPv6 addresses on eth0...${NC}"
if [ -d "/sys/class/net/eth0" ]; then
    # Flush all IPv6 addresses (except link-local)
    if command -v ip >/dev/null 2>&1; then
        IPV6_ADDRS=$(ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80::' | awk '{print $2}')
        if [ -n "$IPV6_ADDRS" ]; then
            echo "$IPV6_ADDRS" | while read addr; do
                ip -6 addr del "$addr" dev eth0 2>/dev/null || true
                echo -e "${BLUE}    Removed: $addr${NC}"
            done
            echo -e "${GREEN}  ✓ Cleaned up IPv6 addresses${NC}"
        else
            echo -e "${BLUE}  (No IPv6 addresses to clean)${NC}"
        fi
    fi
else
    echo -e "${YELLOW}  ⚠ eth0 interface not found${NC}"
fi

# CRITICAL: Clean up IPv4 addresses on eth0
echo -e "${BLUE}- Cleaning up IPv4 addresses on eth0...${NC}"
if [ -d "/sys/class/net/eth0" ]; then
    if command -v ip >/dev/null 2>&1; then
        IPV4_ADDRS=$(ip -4 addr show eth0 | grep 'inet' | grep -v '127.0.0.1' | awk '{print $2}')
        if [ -n "$IPV4_ADDRS" ]; then
            echo "$IPV4_ADDRS" | while read addr; do
                ip -4 addr del "$addr" dev eth0 2>/dev/null || true
                echo -e "${BLUE}    Removed: $addr${NC}"
            done
            echo -e "${GREEN}  ✓ Cleaned up IPv4 addresses${NC}"
        else
            echo -e "${BLUE}  (No IPv4 addresses to clean)${NC}"
        fi
    fi
fi

# CRITICAL: Clean up IPv6 proxy NDP entries
echo -e "${BLUE}- Cleaning up IPv6 Proxy NDP entries...${NC}"
if command -v ip >/dev/null 2>&1; then
    NDP_ENTRIES=$(ip -6 neigh show proxy 2>/dev/null | grep -v 'fe80::' | awk '{print $1}')
    if [ -n "$NDP_ENTRIES" ]; then
        echo "$NDP_ENTRIES" | while read ipv6; do
            ip -6 neigh del proxy "$ipv6" dev eth0 2>/dev/null || true
            echo -e "${BLUE}    Removed NDP proxy: $ipv6${NC}"
        done
        echo -e "${GREEN}  ✓ Cleaned up Proxy NDP entries${NC}"
    else
        echo -e "${BLUE}  (No Proxy NDP entries to clean)${NC}"
    fi
fi

# CRITICAL: Restore IPv6 sysctl settings on eth0
echo -e "${BLUE}- Restoring IPv6 sysctl settings on eth0...${NC}"
if command -v sysctl >/dev/null 2>&1; then
    # Restore default IPv6 settings
    sysctl -w net.ipv6.conf.eth0.accept_ra=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.eth0.autoconf=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null || true

    # Restore forwarding to safe default (0 = disabled)
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=0 2>/dev/null || true

    echo -e "${GREEN}  ✓ Restored IPv6 sysctl settings${NC}"
fi

# CRITICAL: Restart network to apply clean state
echo -e "${BLUE}- Restarting network to apply clean state...${NC}"
/etc/init.d/network restart 2>/dev/null || true
sleep 3
echo -e "${GREEN}  ✓ Network restarted${NC}"

# Restore IPv6 listening on LuCI and SSH (if backups exist)
echo -e "${BLUE}- Restoring LuCI and SSH IPv6 listening (if backups exist)...${NC}"

# Restore uhttpd config from backup
UHTTPD_BACKUP=$(ls -t /etc/config/uhttpd.backup.* 2>/dev/null | head -1)
if [ -n "$UHTTPD_BACKUP" ] && [ -f "$UHTTPD_BACKUP" ]; then
    echo -e "${BLUE}  Restoring uhttpd config from: $UHTTPD_BACKUP${NC}"
    cp "$UHTTPD_BACKUP" /etc/config/uhttpd
    /etc/init.d/uhttpd restart 2>/dev/null || true
    echo -e "${GREEN}  ✓ uhttpd configuration restored${NC}"
else
    echo -e "${YELLOW}  ⚠ No uhttpd backup found - LuCI may still be IPv4-only${NC}"
    echo -e "${YELLOW}  Reconfigure manually if needed:${NC}"
    echo "     uci set uhttpd.main.listen_http='0.0.0.0:80'"
    echo "     uci set uhttpd.main.listen_http6='[::]:80'"
    echo "     uci commit uhttpd && /etc/init.d/uhttpd restart"
fi

# Restore dropbear config from backup
DROPBEAR_BACKUP=$(ls -t /etc/config/dropbear.backup.* 2>/dev/null | head -1)
if [ -n "$DROPBEAR_BACKUP" ] && [ -f "$DROPBEAR_BACKUP" ]; then
    echo -e "${BLUE}  Restoring dropbear config from: $DROPBEAR_BACKUP${NC}"
    cp "$DROPBEAR_BACKUP" /etc/config/dropbear
    /etc/init.d/dropbear restart 2>/dev/null || true
    echo -e "${GREEN}  ✓ dropbear configuration restored${NC}"
else
    echo -e "${YELLOW}  ⚠ No dropbear backup found - SSH may still be LAN-only${NC}"
    echo -e "${YELLOW}  Reconfigure manually if needed:${NC}"
    echo "     uci delete dropbear.@dropbear[0].Interface"
    echo "     uci commit dropbear && /etc/init.d/dropbear restart"
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

rm -rf "$INSTALL_DIR"                || true
rm -rf "$CONFIG_DIR"                 || true
rm -f  "$INIT_SCRIPT"                || true
rm -f  "$SYSTEMD_SERVICE"            || true
rm -f  "$LOG_FILE"                   || true
rm -rf "$RUN_DIR"                    || true
rm -f  /usr/bin/gateway-status       || true
rm -f  /usr/bin/gateway-devices      || true
rm -f  /usr/bin/gateway-status-direct   || true
rm -f  /usr/bin/gateway-devices-direct  || true
rm -f  /usr/bin/gateway-diagnose     || true
rm -f  /usr/bin/gateway-port-forward || true
rm -f  /usr/bin/monitor-connections  || true
rm -f  /usr/bin/capture-traffic      || true
rm -f  /usr/bin/debug-connections    || true

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
