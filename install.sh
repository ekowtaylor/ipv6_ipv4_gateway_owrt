#!/bin/sh
# Simplified Installation Script for IPv4↔IPv6 Gateway (Single Device Mode)
# Installs Python service WITHOUT HTTP API server - uses direct scripts only
#
# Usage:
#   ./install.sh                    # Safe mode (manual steps required)
#   ./install.sh --full-auto        # Do everything automatically
#

set -e  # Exit on error

SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/ipv4-ipv6-gateway"
CONFIG_DIR="/etc/ipv4-ipv6-gateway"
LOG_DIR="/var/log"

# Parse command-line arguments
AUTO_START="false"
APPLY_NETWORK="false"
FULL_AUTO="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --auto-start)
            AUTO_START="true"
            shift
            ;;
        --apply-network)
            APPLY_NETWORK="true"
            shift
            ;;
        --full-auto)
            AUTO_START="true"
            APPLY_NETWORK="true"
            FULL_AUTO="true"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --auto-start           Automatically start the service after installation"
            echo "  --apply-network        Automatically apply network configuration"
            echo "  --full-auto            Do everything automatically (start + network)"
            echo "  --help                 Show this help message"
            echo ""
            echo "Simplified single-device gateway - No HTTP API server!"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "========================================="
echo " Simplified Gateway Installation (Single Device)"
echo "========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run as root"
    exit 1
fi

# Verify required files exist
echo "Checking required files..."
REQUIRED_FILES="ipv4_ipv6_gateway.py gateway_config.py gateway-status-direct.sh gateway-devices-direct.sh"

for file in $REQUIRED_FILES; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file missing: $file"
        echo "Please run this script from the directory containing all gateway files"
        exit 1
    fi
done
echo "✓ All required files found"
echo ""

# Install dependencies
echo "Installing dependencies..."
opkg update

# Install core dependencies (required)
echo "Installing core dependencies..."
opkg install python3 python3-pip ip-full iptables kmod-ipt-nat || {
    echo "ERROR: Failed to install core dependencies"
    exit 1
}

# Install DHCPv6 client (required for IPv6)
echo "Installing DHCPv6 client..."
opkg install odhcp6c || {
    echo "WARNING: odhcp6c installation failed - IPv6 may not work"
}

# Install socat (required for IPv6 proxy)
echo "Installing socat for IPv6 proxy..."
opkg install socat || {
    echo "WARNING: socat installation failed - IPv6 proxy will not work"
}

# Note: udhcpc is part of BusyBox and already included in OpenWrt
echo "✓ udhcpc (DHCPv4 client) is pre-installed in BusyBox"

# Install IPv6 NAT support (optional - try multiple package names)
echo ""
echo "Installing IPv6 NAT support (optional)..."
IPV6_NAT_INSTALLED=false

# Try different package names for IPv6 NAT (varies by OpenWrt version)
for pkg in kmod-ipt-nat6 kmod-nf-nat6 ip6tables-mod-nat; do
    echo "  Trying: $pkg"
    if opkg install "$pkg" 2>/dev/null; then
        echo "  ✓ Installed: $pkg"
        IPV6_NAT_INSTALLED=true
        break
    else
        echo "  ✗ Not available: $pkg"
    fi
done

# Install ip6tables if not already installed
opkg list-installed | grep -q ip6tables || opkg install ip6tables 2>/dev/null

if [ "$IPV6_NAT_INSTALLED" = "true" ]; then
    echo "✓ IPv6 NAT support installed"

    # Try to load kernel modules
    echo "  Loading IPv6 NAT kernel modules..."
    modprobe nf_nat 2>/dev/null || echo "  (nf_nat already loaded or not needed)"
    modprobe ip6table_nat 2>/dev/null || echo "  (ip6table_nat already loaded or not needed)"
    modprobe nf_conntrack 2>/dev/null || echo "  (nf_conntrack already loaded or not needed)"

    # Test if IPv6 NAT actually works
    if ip6tables -t nat -L >/dev/null 2>&1; then
        echo "  ✓ IPv6 NAT is functional"
    else
        echo "  ⚠ IPv6 NAT modules installed but not functional"
        echo "  This may require a reboot or kernel upgrade"
        IPV6_NAT_INSTALLED=false
    fi
else
    echo "⚠ IPv6 NAT support NOT available on this system"
    echo ""
    echo "This means:"
    echo "  ✓ Your device WILL have dual-stack internet access (IPv4 + IPv6)"
    echo "  ✗ External IPv6 clients CANNOT connect to your device services"
    echo ""
    echo "IPv6 proxy requires kernel NAT6 support which may not be available on:"
    echo "  - Older OpenWrt versions (< 19.07)"
    echo "  - Custom kernels without NAT6 compiled in"
    echo "  - Some embedded devices with minimal kernels"
    echo ""
    echo "To enable IPv6 proxy in the future:"
    echo "  1. Upgrade to OpenWrt 21.02 or newer"
    echo "  2. Or compile custom kernel with CONFIG_NF_NAT_IPV6=y"
fi

echo ""
echo "✓ Core dependencies installed"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
echo "✓ Directories created"
echo ""

# Install Python files
echo "Installing gateway service..."
cp ipv4_ipv6_gateway.py "$INSTALL_DIR/"
cp gateway_config.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ipv4_ipv6_gateway.py"
echo "✓ Service files installed to $INSTALL_DIR"
echo ""

# Install helper scripts
echo "Installing helper scripts..."
cp gateway-status-direct.sh /usr/bin/gateway-status
cp gateway-devices-direct.sh /usr/bin/gateway-device
chmod +x /usr/bin/gateway-status
chmod +x /usr/bin/gateway-device
echo "✓ Installed: gateway-status, gateway-device"
echo ""

# Create init.d service script
echo "Creating init.d service..."
cat > /etc/init.d/$SERVICE_NAME << 'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

PROG="/opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py"
PYTHON="/usr/bin/python3"

start_service() {
    procd_open_instance
    procd_set_param command $PYTHON $PROG
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    # Kill the service
    killall python3 2>/dev/null || true

    # Restore original MAC if exists
    if [ -f /etc/ipv4-ipv6-gateway/original_wan_mac.txt ]; then
        ORIGINAL_MAC=$(cat /etc/ipv4-ipv6-gateway/original_wan_mac.txt)
        echo "Restoring original WAN MAC: $ORIGINAL_MAC"
        ip link set eth0 down
        ip link set eth0 address $ORIGINAL_MAC
        ip link set eth0 up
    fi
}
EOF

chmod +x /etc/init.d/$SERVICE_NAME
echo "✓ Init.d service created"
echo ""

# Enable service
echo "Enabling service..."
/etc/init.d/$SERVICE_NAME enable
echo "✓ Service enabled (will start on boot)"
echo ""

# Create network configuration
if [ "$APPLY_NETWORK" = "true" ]; then
    echo "Applying network configuration..."

    # Configure eth1 (LAN)
    uci set network.lan=interface
    uci set network.lan.device='eth1'
    uci set network.lan.proto='static'
    uci set network.lan.ipaddr='192.168.1.1'
    uci set network.lan.netmask='255.255.255.0'

    # Configure eth0 (WAN) - dual-stack
    uci set network.wan=interface
    uci set network.wan.device='eth0'
    uci set network.wan.proto='dhcp'

    uci set network.wan6=interface
    uci set network.wan6.device='eth0'
    uci set network.wan6.proto='dhcpv6'
    uci set network.wan6.reqaddress='try'
    uci set network.wan6.reqprefix='auto'

    # Commit and apply
    uci commit network
    /etc/init.d/network restart

    echo "✓ Network configuration applied"
else
    echo "Skipping network configuration (use --apply-network to enable)"
    echo "Manual steps:"
    echo "  1. Configure eth1 as LAN: 192.168.1.1/24"
    echo "  2. Configure eth0 as WAN: DHCP + DHCPv6"
fi
echo ""

# Start service
if [ "$AUTO_START" = "true" ]; then
    echo "Starting service..."
    /etc/init.d/$SERVICE_NAME start
    sleep 2

    # Check if running
    if pgrep -f "ipv4_ipv6_gateway.py" > /dev/null; then
        echo "✓ Service started successfully"
    else
        echo "⚠ Service may have failed to start - check logs:"
        echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
    fi
else
    echo "Service NOT started (use --auto-start to enable)"
    echo "To start manually:"
    echo "  /etc/init.d/$SERVICE_NAME start"
fi
echo ""

echo "========================================="
echo " Installation Complete!"
echo "========================================="
echo ""
echo "Quick Start:"
echo "  1. Connect device to eth1 (LAN)"
echo "  2. Device will get 192.168.1.x via DHCP"
echo "  3. Gateway will auto-discover and configure"
echo "  4. Check status: gateway-status"
echo "  5. Check device: gateway-device"
echo "  6. View logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
echo "Service Control:"
echo "  /etc/init.d/$SERVICE_NAME start|stop|restart|status"
echo ""
echo "NOTE: This is simplified single-device mode"
echo "      - No HTTP API server on port 5050"
echo "      - Use 'gateway-status' and 'gateway-device' commands"
echo "      - Only ONE device supported at a time"
echo ""
