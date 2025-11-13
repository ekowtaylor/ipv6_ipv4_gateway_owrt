#!/bin/sh
#
# Setup permanent MAC spoofing using UCI (OpenWrt's native config system)
# This makes MAC changes persist across reboots and prevents netifd interference
#

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <device_mac_address>"
    echo "Example: $0 aa:bb:cc:dd:ee:ff"
    exit 1
fi

DEVICE_MAC="$1"
WAN_INTERFACE="wan"  # UCI interface name (not eth0!)

echo "========================================="
echo "Setup Permanent MAC via UCI"
echo "========================================="
echo ""
echo "Device MAC: $DEVICE_MAC"
echo "WAN Interface: $WAN_INTERFACE"
echo ""

# Validate MAC format
if ! echo "$DEVICE_MAC" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then
    echo "ERROR: Invalid MAC address format"
    echo "Expected: aa:bb:cc:dd:ee:ff"
    exit 1
fi

# Check if running on OpenWrt
if [ ! -f "/etc/openwrt_release" ]; then
    echo "WARNING: This doesn't appear to be OpenWrt"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Backup current network config
if [ -f "/etc/config/network" ]; then
    echo "Backing up /etc/config/network..."
    cp /etc/config/network /etc/config/network.backup.$(date +%Y%m%d_%H%M%S)
    echo "✓ Backup created"
fi

echo ""
echo "Setting permanent MAC in UCI..."

# Set MAC address for WAN interface
uci set network.${WAN_INTERFACE}.macaddr="${DEVICE_MAC}"

# Optional: Prevent auto-configuration (let gateway service manage it)
# uci set network.${WAN_INTERFACE}.auto='0'

# Commit changes
uci commit network

echo "✓ MAC address configured in UCI"
echo ""

# Show configuration
echo "Current UCI configuration for ${WAN_INTERFACE}:"
echo "────────────────────────────────────────"
uci show network.${WAN_INTERFACE} | grep -E 'macaddr|auto|proto' || true

echo ""
read -p "Reload network to apply changes? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Reloading network configuration..."
    /etc/init.d/network reload
    echo "✓ Network reloaded"

    echo ""
    echo "Waiting for network to stabilize..."
    sleep 3

    echo ""
    echo "Current MAC on eth0:"
    ip link show eth0 | grep -o 'link/ether [0-9a-f:]*' || true
else
    echo "Skipped network reload"
    echo "Run '/etc/init.d/network reload' manually to apply"
fi

echo ""
echo "========================================="
echo "✓ MAC address locked via UCI"
echo "========================================="
echo ""
echo "IMPORTANT:"
echo "  - MAC is now managed by UCI configuration"
echo "  - Survives reboots automatically"
echo "  - netifd will respect this MAC setting"
echo ""
echo "To revert:"
echo "  uci delete network.${WAN_INTERFACE}.macaddr"
echo "  uci commit network"
echo "  /etc/init.d/network reload"
echo ""
