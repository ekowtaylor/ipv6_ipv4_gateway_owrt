#!/bin/sh
#
# Manual Network Configuration Fix
# Use this if UCI import isn't working correctly
#

set -e

echo "========================================="
echo "Manual Network Configuration Fix"
echo "========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check current eth1 status
echo "Current eth1 status:"
ip addr show eth1 2>/dev/null || echo "  eth1 not found"
echo ""

# Option 1: Direct IP assignment (immediate, survives until reboot)
echo "Option 1: Assign IP directly (temporary until reboot)"
echo "  This will work immediately but won't survive a reboot"
echo ""
read -p "Apply direct IP assignment? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Bringing eth1 down..."
    ip link set eth1 down 2>/dev/null || true

    echo "Flushing existing addresses..."
    ip addr flush dev eth1 2>/dev/null || true

    echo "Assigning 192.168.1.1/24 to eth1..."
    ip addr add 192.168.1.1/24 dev eth1

    echo "Bringing eth1 up..."
    ip link set eth1 up

    echo "Verifying..."
    sleep 2
    ip addr show eth1 | grep "inet "

    echo ""
    echo "✓ IP assigned! Test with: ping 192.168.1.1"
    echo ""
fi

# Option 2: UCI configuration (persistent)
echo "Option 2: Configure via UCI (persistent)"
echo "  This will survive reboots but requires network restart"
echo ""
read -p "Apply UCI configuration? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Configuring LAN interface..."

    # Delete existing lan configuration
    uci delete network.lan 2>/dev/null || true

    # Create new lan configuration
    uci set network.lan=interface
    uci set network.lan.device='eth1'
    uci set network.lan.proto='static'
    uci set network.lan.ipaddr='192.168.1.1'
    uci set network.lan.netmask='255.255.255.0'

    # Delete existing wan configuration
    uci delete network.wan 2>/dev/null || true
    uci delete network.wan6 2>/dev/null || true

    # Create new wan configuration (dual-stack)
    # IPv4
    uci set network.wan=interface
    uci set network.wan.device='eth0'
    uci set network.wan.proto='dhcp'

    # IPv6
    uci set network.wan6=interface
    uci set network.wan6.device='eth0'
    uci set network.wan6.proto='dhcpv6'
    uci set network.wan6.reqaddress='try'
    uci set network.wan6.reqprefix='auto'

    echo "Committing changes..."
    uci commit network

    echo "Showing new configuration:"
    uci show network.lan
    uci show network.wan
    uci show network.wan6

    echo ""
    read -p "Restart network now? This will disconnect SSH! (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Restarting network in 3 seconds..."
        sleep 3
        /etc/init.d/network restart
        echo "Network restarted. Reconnect to 192.168.1.1"
    else
        echo "Skipped network restart. Run manually: /etc/init.d/network restart"
    fi
fi

# Option 3: Debug current config
echo ""
echo "Option 3: Debug current configuration"
echo ""
read -p "Show debug information? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "=== Current UCI Network Config ==="
    uci show network
    echo ""

    echo "=== /etc/config/network file ==="
    cat /etc/config/network
    echo ""

    echo "=== IP Addresses ==="
    ip addr show
    echo ""

    echo "=== Network Interfaces ==="
    ip link show
    echo ""

    echo "=== Routing Table ==="
    ip route show
    echo ""
fi

echo ""
echo "========================================="
echo "Manual fix completed"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Test: ping 192.168.1.1"
echo "  2. Verify: ip addr show eth1"
echo "  3. Check gateway: gateway-status"
echo "  4. Start DHCP: /etc/init.d/dnsmasq restart"
echo ""
