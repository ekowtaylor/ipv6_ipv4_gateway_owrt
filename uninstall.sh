#!/bin/sh
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
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Step 1: Stop service
echo "Step 1: Stopping service..."

# Disable service first (prevent auto-restart)
if [ -x "$INIT_SCRIPT" ]; then
    echo "- Disabling init.d service..."
    "$INIT_SCRIPT" disable 2>/dev/null || true
    echo "- Stopping init.d service..."
    "$INIT_SCRIPT" stop 2>/dev/null || true
    sleep 2
fi

# Kill only our specific gateway processes (not system processes!)
echo "- Killing gateway processes..."
pkill -9 -f "ipv4_ipv6_gateway.py" 2>/dev/null || true
pkill -9 -f "socat.*TCP6-LISTEN" 2>/dev/null || true
sleep 1

# DO NOT kill odhcp6c or udhcpc - these are used by the router itself!
# Killing them breaks the router's own DHCP client

# Verify gateway process is dead
if pgrep -f ipv4_ipv6_gateway.py >/dev/null 2>&1; then
    echo "  ⚠ Warning: Gateway process still running, attempting manual kill..."
    pkill -9 -f ipv4_ipv6_gateway.py
    sleep 1
fi

echo "  ✓ Gateway processes killed"

# Restore original MAC address via UCI (OpenWrt-compatible)
echo "- Restoring original MAC address (if saved)..."
if [ -f "$CONFIG_DIR/original_wan_mac.txt" ]; then
    ORIGINAL_MAC=$(cat "$CONFIG_DIR/original_wan_mac.txt")
    echo "  Found saved MAC: $ORIGINAL_MAC"

    # Remove MAC override from UCI (restore to default)
    echo "  Removing MAC override from UCI..."
    uci delete network.wan.macaddr 2>/dev/null || true
    uci commit network 2>/dev/null || true

    # Manually set it as fallback (in case UCI doesn't work)
    ip link set eth0 down 2>/dev/null || true
    ip link set eth0 address "$ORIGINAL_MAC" 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true

    # Reload WAN interface to apply UCI changes
    echo "  Reloading WAN interface..."
    ifdown wan 2>/dev/null || true
    sleep 1
    ifup wan 2>/dev/null || true
    sleep 2

    # Verify restoration
    NEW_MAC=$(ip link show eth0 | grep -o 'link/ether [^ ]*' | awk '{print $2}')
    if [ "$NEW_MAC" = "$ORIGINAL_MAC" ]; then
        echo "  ✓ Restored original MAC: $ORIGINAL_MAC"
    else
        echo "  ⚠ MAC is now: $NEW_MAC (may differ from original)"
        echo "  Note: This may be normal if device has factory MAC in flash"
    fi
else
    echo "  (No saved MAC found - leaving current MAC unchanged)"
fi

echo "✓ All services stopped and processes killed"
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

    # Restore from backup if available
    if [ -f "$CONFIG_DIR/network.backup" ]; then
        echo "- Restoring network from backup..."
        cp "$CONFIG_DIR/network.backup" /etc/config/network
    elif [ -f "/rom/etc/config/network" ]; then
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

    # Restore default DHCP config
    echo "- Restoring default DHCP config..."
    uci delete dhcp.lan 2>/dev/null || true
    uci set dhcp.lan=dhcp
    uci set dhcp.lan.interface='lan'
    uci set dhcp.lan.start='100'
    uci set dhcp.lan.limit='150'
    uci set dhcp.lan.leasetime='12h'
    uci commit dhcp

    # Restore default firewall config
    echo "- Restoring default firewall config..."
    if [ -f "/rom/etc/config/firewall" ]; then
        cp /rom/etc/config/firewall /etc/config/firewall
    else
        # Create minimal firewall config
        cat > /etc/config/firewall << 'EOF'
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option network 'lan'

config zone
	option name 'wan'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	option network 'wan wan6'

config rule
	option name 'Allow-Ping'
	option src 'wan'
	option proto 'icmp'
	option icmp_type 'echo-request'
	option family 'ipv4'
	option target 'ACCEPT'

config rule
	option name 'Allow-ICMPv6'
	option src 'wan'
	option proto 'icmp'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-DHCPv6'
	option src 'wan'
	option proto 'udp'
	option dest_port '546'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-IPv6-Proxy-HTTP-8080'
	option src 'wan'
	option proto 'tcp'
	option dest_port '8080'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-IPv6-Proxy-HTTP-5000'
	option src 'wan'
	option proto 'tcp'
	option dest_port '5000'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-IPv6-Proxy-Telnet'
	option src 'wan'
	option proto 'tcp'
	option dest_port '2323'
	option family 'ipv6'
	option target 'ACCEPT'

config forwarding
	option src 'lan'
	option dest 'wan'

config forwarding
	option src 'wan'
	option dest 'lan'
EOF
    fi
    uci commit firewall

    # Remove our sysctl entries EXCEPT IPv6 enablement
    echo "- Cleaning up sysctl config (keeping IPv6 enabled)..."
    if [ -f /etc/sysctl.conf ]; then
        # Remove only IP forwarding entries, NOT IPv6 disable_ipv6 settings
        # We want IPv6 to STAY ENABLED even after uninstall
        sed -i '/# Gateway IP forwarding/d' /etc/sysctl.conf
        sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
        sed -i '/net.ipv6.conf.all.forwarding=1/d' /etc/sysctl.conf
        # DO NOT remove these - keep IPv6 enabled:
        # - net.ipv6.conf.all.disable_ipv6=0
        # - net.ipv6.conf.default.disable_ipv6=0
        # - net.ipv6.conf.eth0.disable_ipv6=0
    fi

    # Disable IP forwarding (but keep IPv6 enabled!)
    echo "- Disabling IP forwarding (IPv6 stays enabled)..."
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

    # Keep IPv6 enabled (do NOT disable it)
    echo "- Ensuring IPv6 remains enabled..."
    echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6 2>/dev/null || true

    # Clean up iptables rules added by gateway
    echo "- Cleaning up iptables rules..."

    # DO NOT flush iptables - let firewall restart handle it!
    # Flushing breaks existing connections and is dangerous

    # Just restart firewall service - it will reload from UCI config
    echo "  ✓ iptables will be cleaned by firewall restart"

    # Restart all network services
    echo "- Restarting network services..."
    /etc/init.d/firewall restart 2>/dev/null || true
    sleep 2
    /etc/init.d/dnsmasq restart 2>/dev/null || true
    sleep 2
    /etc/init.d/network restart 2>/dev/null || true
    sleep 3

    echo "✓ Network fully restored"
    echo "  - Network config: Restored to factory defaults"
    echo "  - DHCP server: Restored to defaults"
    echo "  - Firewall: Restored to defaults"
    echo "  - IP forwarding: Disabled"
    echo "  - NAT rules: Cleaned"
else
    echo "Step 3: Skipping network restore (use --restore-network to revert)"
fi
echo ""

# Step 4: Remove IPv6 NAT packages (optional)
echo "Step 4: Checking for IPv6 NAT packages..."

if [ -f "$CONFIG_DIR/ipv6_nat_package.txt" ]; then
    echo "Found IPv6 NAT packages installed by gateway:"
    cat "$CONFIG_DIR/ipv6_nat_package.txt"
    echo ""

    echo "Do you want to remove these IPv6 NAT packages? (y/N)"
    if [ "$RESTORE_NETWORK" -eq 1 ]; then
        # In auto-restore mode, don't prompt
        REMOVE_IPV6_NAT="n"
        echo "  (skipped in auto-restore mode)"
    else
        read -r REMOVE_IPV6_NAT
    fi

    if [ "$REMOVE_IPV6_NAT" = "y" ] || [ "$REMOVE_IPV6_NAT" = "Y" ]; then
        echo "Removing IPv6 NAT packages..."
        while IFS= read -r pkg; do
            if [ -n "$pkg" ]; then
                echo "  Removing: $pkg"
                opkg remove "$pkg" 2>/dev/null || echo "    (already removed or not found)"
            fi
        done < "$CONFIG_DIR/ipv6_nat_package.txt"
        echo "✓ IPv6 NAT packages removed"
    else
        echo "✓ Keeping IPv6 NAT packages (can be used by other services)"
    fi
else
    echo "  (No IPv6 NAT package info found - nothing to remove)"
fi
echo ""

# Step 5: Remove files
echo "Step 5: Removing installed files..."

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
