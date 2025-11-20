#!/bin/bash
#
# uninstall.sh — Simplified uninstaller for IPv4↔IPv6 Gateway (Single Device Mode)
# Safely uninstall the gateway service and clean up
#
# Usage: ./uninstall.sh [--restore-network]
#

set -e

SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
INIT_SCRIPT="/etc/init.d/${SERVICE_NAME}"

BACKUP_DIR="/root/ipv4-ipv6-gateway_backup_$(date +%Y%m%d_%H%M%S)"
RESTORE_NETWORK=0

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --restore-network|--reset-network)
            RESTORE_NETWORK=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--restore-network]"
            exit 1
            ;;
    esac
done

echo "========================================="
echo " IPv4↔IPv6 Gateway Uninstaller (Simple)"
echo "========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Step 1: Stop service
echo "Step 1: Stopping service..."

if [ -x "$INIT_SCRIPT" ]; then
    echo "- Stopping init.d service..."
    "$INIT_SCRIPT" stop 2>/dev/null || true
    "$INIT_SCRIPT" disable 2>/dev/null || true
fi

# Restore original MAC address
echo "- Restoring original MAC address (if saved)..."
if [ -f "$CONFIG_DIR/original_wan_mac.txt" ]; then
    ORIGINAL_MAC=$(cat "$CONFIG_DIR/original_wan_mac.txt")
    echo "  Found saved MAC: $ORIGINAL_MAC"

    ip link set eth0 down 2>/dev/null || true
    ip link set eth0 address "$ORIGINAL_MAC" 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true

    NEW_MAC=$(ip link show eth0 | grep -o 'link/ether [^ ]*' | awk '{print $2}')
    if [ "$NEW_MAC" = "$ORIGINAL_MAC" ]; then
        echo "  ✓ Restored original MAC: $ORIGINAL_MAC"
    else
        echo "  ⚠ Failed to restore MAC (may require reboot)"
    fi
else
    echo "  (No saved MAC found - may need manual restore)"
fi

# Kill Python service
killall python3 2>/dev/null || true

echo "✓ Service stopped"
echo ""

# Step 2: Backup files
echo "Step 2: Backing up configuration..."
mkdir -p "$BACKUP_DIR"

[ -d "$INSTALL_DIR" ]             && cp -a "$INSTALL_DIR" "$BACKUP_DIR/" 2>/dev/null || true
[ -d "$CONFIG_DIR" ]              && cp -a "$CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$LOG_FILE" ]                && cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$INIT_SCRIPT" ]             && cp "$INIT_SCRIPT" "$BACKUP_DIR/" 2>/dev/null || true
[ -f "/etc/config/network" ]      && cp "/etc/config/network" "$BACKUP_DIR/network.current" 2>/dev/null || true

echo "✓ Backup saved to: $BACKUP_DIR"
echo ""

# Step 3: Optional network restore
if [ "$RESTORE_NETWORK" -eq 1 ]; then
    echo "Step 3: Restoring network configuration..."

    # Use factory config if available
    if [ -f "/rom/etc/config/network" ]; then
        echo "- Restoring factory network config..."
        cp /rom/etc/config/network /etc/config/network
    else
        echo "- Creating default network config..."
        cat > /etc/config/network << 'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'lan'
	option device 'eth1'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'

config interface 'wan'
	option device 'eth0'
	option proto 'dhcp'

config interface 'wan6'
	option device 'eth0'
	option proto 'dhcpv6'
EOF
    fi

    echo "- Restarting network..."
    /etc/init.d/network restart 2>/dev/null || true
    sleep 3

    echo "✓ Network restored"
else
    echo "Step 3: Skipping network restore (use --restore-network to revert)"
fi
echo ""

# Step 4: Remove files
echo "Step 4: Removing installed files..."

rm -rf "$INSTALL_DIR" 2>/dev/null || true
rm -rf "$CONFIG_DIR" 2>/dev/null || true
rm -f "$INIT_SCRIPT" 2>/dev/null || true
rm -f "$LOG_FILE" 2>/dev/null || true
rm -f /usr/bin/gateway-status 2>/dev/null || true
rm -f /usr/bin/gateway-device 2>/dev/null || true

echo "✓ Files removed"
echo ""

# Final summary
echo "========================================="
echo " Uninstallation Complete"
echo "========================================="
echo ""
echo "Backup directory: $BACKUP_DIR"
echo ""
if [ "$RESTORE_NETWORK" -eq 1 ]; then
    echo "Network configuration restored to factory defaults"
else
    echo "Network configuration unchanged"
    echo "To restore: $0 --restore-network"
fi
echo ""
echo "To reinstall: ./install.sh --full-auto"
echo ""
