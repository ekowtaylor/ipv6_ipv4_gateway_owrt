#!/bin/sh
#
# Disable OpenWrt netifd management of eth0
# This prevents OpenWrt from resetting the spoofed MAC address
#
# CRITICAL: The gateway service permanently sets eth0's MAC to the device MAC.
# If netifd manages eth0, it may reset the MAC to factory default, breaking network authentication.
#

set -e

echo "========================================="
echo "Disable netifd Management of eth0"
echo "========================================="
echo ""

# Check if running on OpenWrt
if [ ! -f "/etc/openwrt_release" ]; then
    echo "WARNING: This doesn't appear to be OpenWrt"
    echo "This script is designed for OpenWrt systems"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Backup network config
if [ -f "/etc/config/network" ]; then
    echo "Backing up /etc/config/network..."
    cp /etc/config/network /etc/config/network.backup.$(date +%Y%m%d_%H%M%S)
    echo "✓ Backup created"
else
    echo "WARNING: /etc/config/network not found"
fi

# Check current eth0 configuration
echo ""
echo "Current eth0 configuration:"
echo "─────────────────────────────"
uci show network | grep -i eth0 || echo "No eth0 configuration found"

echo ""
echo "Disabling netifd management of eth0..."
echo "─────────────────────────────────────"

# Remove eth0 from all network interfaces
# This prevents netifd from managing it

# Option 1: Remove eth0 from WAN interface (most common)
if uci get network.wan.ifname 2>/dev/null | grep -q "eth0"; then
    echo "Removing eth0 from network.wan.ifname..."
    uci delete network.wan.ifname
    echo "✓ Removed eth0 from WAN interface"
fi

# Option 2: Remove eth0 from WAN6 interface (IPv6 WAN)
if uci get network.wan6.ifname 2>/dev/null | grep -q "eth0"; then
    echo "Removing eth0 from network.wan6.ifname..."
    uci delete network.wan6.ifname
    echo "✓ Removed eth0 from WAN6 interface"
fi

# Option 3: Check for any other interfaces using eth0
echo ""
echo "Checking for other interfaces using eth0..."
for iface in $(uci show network | grep "=interface" | cut -d. -f2 | cut -d= -f1); do
    ifname=$(uci get network.$iface.ifname 2>/dev/null || echo "")
    if echo "$ifname" | grep -q "eth0"; then
        echo "WARNING: Interface '$iface' uses eth0: $ifname"
        echo "  Removing eth0 from network.$iface.ifname..."
        uci delete network.$iface.ifname
        echo "  ✓ Removed"
    fi
done

# Disable netifd's auto-configuration of eth0
echo ""
echo "Creating custom network configuration for eth0..."

# Check if a custom eth0 interface exists
if ! uci get network.eth0_custom 2>/dev/null; then
    # Create a dummy interface that tells netifd to leave eth0 alone
    uci set network.eth0_custom=interface
    uci set network.eth0_custom.ifname='eth0'
    uci set network.eth0_custom.proto='none'  # Don't configure it
    uci set network.eth0_custom.auto='0'      # Don't bring it up
    echo "✓ Created network.eth0_custom (proto=none, auto=0)"
fi

# Commit changes
echo ""
echo "Committing UCI changes..."
uci commit network
echo "✓ Changes committed"

# Show new configuration
echo ""
echo "New eth0 configuration:"
echo "─────────────────────────"
uci show network | grep -i eth0 || echo "No eth0 configuration found (good!)"

# Restart network service
echo ""
read -p "Restart network service to apply changes? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Restarting network service..."
    /etc/init.d/network restart
    echo "✓ Network service restarted"

    echo ""
    echo "Waiting for network to stabilize..."
    sleep 5

    echo ""
    echo "Current eth0 status:"
    ip link show eth0 || echo "ERROR: eth0 not found!"
else
    echo "Skipped network restart"
    echo "Run '/etc/init.d/network restart' manually to apply changes"
fi

echo ""
echo "========================================="
echo "✓ netifd management of eth0 disabled"
echo "========================================="
echo ""
echo "IMPORTANT:"
echo "  - eth0 is now MANUALLY managed by the gateway service"
echo "  - netifd will NOT reset eth0's MAC address"
echo "  - The gateway service will set eth0's MAC permanently"
echo ""
echo "To re-enable netifd management of eth0:"
echo "  1. Restore network config: cp /etc/config/network.backup.* /etc/config/network"
echo "  2. Reload network: /etc/init.d/network reload"
echo ""
