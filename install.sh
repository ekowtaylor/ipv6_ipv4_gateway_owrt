#!/bin/sh
# Simplified Installation Script for IPv4↔IPv6 Gateway (Single Device Mode)
# Installs Python service WITHOUT HTTP API server - uses direct scripts only
#
# Usage:
#   ./install.sh                    # Safe mode (manual steps required)
#   ./install.sh --full-auto        # Do everything automatically
#

set -e  # Exit on error

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
echo "Script directory: $SCRIPT_DIR"
echo ""

# Change to script directory to find files
cd "$SCRIPT_DIR" || {
    echo "ERROR: Cannot change to script directory: $SCRIPT_DIR"
    exit 1
}

echo "Working directory: $(pwd)"
echo ""

REQUIRED_FILES="ipv4_ipv6_gateway.py gateway_config.py gateway-status-direct.sh gateway-devices-direct.sh"

MISSING_FILES=""
for file in $REQUIRED_FILES; do
    if [ ! -f "$file" ]; then
        MISSING_FILES="$MISSING_FILES $file"
    fi
done

if [ -n "$MISSING_FILES" ]; then
    echo "ERROR: Required files missing:$MISSING_FILES"
    echo ""
    echo "Files in script directory:"
    ls -lh *.py *.sh 2>/dev/null || ls -lh
    echo ""
    echo "Please ensure the following files exist in the same directory as install.sh:"
    echo "  - ipv4_ipv6_gateway.py"
    echo "  - gateway_config.py"
    echo "  - gateway-status-direct.sh"
    echo "  - gateway-devices-direct.sh"
    echo ""
    exit 1
fi

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

# Use explicit paths from SCRIPT_DIR
if [ ! -f "$SCRIPT_DIR/gateway-status-direct.sh" ]; then
    echo "ERROR: gateway-status-direct.sh not found in $SCRIPT_DIR"
    ls -lh "$SCRIPT_DIR"/*.sh
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/gateway-devices-direct.sh" ]; then
    echo "ERROR: gateway-devices-direct.sh not found in $SCRIPT_DIR"
    ls -lh "$SCRIPT_DIR"/*.sh
    exit 1
fi

# Copy scripts with error handling
cp "$SCRIPT_DIR/gateway-status-direct.sh" /usr/bin/gateway-status || {
    echo "ERROR: Failed to copy gateway-status-direct.sh to /usr/bin/gateway-status"
    exit 1
}

cp "$SCRIPT_DIR/gateway-devices-direct.sh" /usr/bin/gateway-device || {
    echo "ERROR: Failed to copy gateway-devices-direct.sh to /usr/bin/gateway-device"
    exit 1
}

# Make scripts executable
chmod +x /usr/bin/gateway-status || {
    echo "ERROR: Failed to make gateway-status executable"
    exit 1
}

chmod +x /usr/bin/gateway-device || {
    echo "ERROR: Failed to make gateway-device executable"
    exit 1
}

# Verify scripts are accessible
if ! command -v gateway-status >/dev/null 2>&1; then
    echo "ERROR: gateway-status command not accessible after installation"
    exit 1
fi

if ! command -v gateway-device >/dev/null 2>&1; then
    echo "ERROR: gateway-device command not accessible after installation"
    exit 1
fi

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

    # Backup current network config
    echo "  Backing up current network config..."
    cp /etc/config/network "$CONFIG_DIR/network.backup" 2>/dev/null || true

    # Configure eth1 (LAN) - Static IP with DHCP server
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

    # Commit network changes
    uci commit network

    # Configure DHCP server on LAN (dnsmasq)
    echo "  Configuring DHCP server on LAN..."
    uci set dhcp.lan=dhcp
    uci set dhcp.lan.interface='lan'
    uci set dhcp.lan.start='100'
    uci set dhcp.lan.limit='150'
    uci set dhcp.lan.leasetime='12h'
    uci set dhcp.lan.dhcpv6='server'
    uci set dhcp.lan.ra='server'
    uci commit dhcp

    # Enable IP forwarding (required for gateway functionality)
    echo "  Enabling IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

    # Make forwarding persistent
    cat >> /etc/sysctl.conf << 'SYSCTL_EOF'
# Gateway IP forwarding (added by ipv4-ipv6-gateway installer)
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
SYSCTL_EOF

    # Configure basic firewall rules
    echo "  Configuring firewall..."

    # Set up zones
    uci set firewall.@zone[0]=zone
    uci set firewall.@zone[0].name='lan'
    uci set firewall.@zone[0].input='ACCEPT'
    uci set firewall.@zone[0].output='ACCEPT'
    uci set firewall.@zone[0].forward='ACCEPT'
    uci set firewall.@zone[0].network='lan'

    uci set firewall.@zone[1]=zone
    uci set firewall.@zone[1].name='wan'
    uci set firewall.@zone[1].input='REJECT'
    uci set firewall.@zone[1].output='ACCEPT'
    uci set firewall.@zone[1].forward='REJECT'
    uci set firewall.@zone[1].masq='1'
    uci set firewall.@zone[1].mtu_fix='1'
    uci set firewall.@zone[1].network='wan wan6'

    # Allow forwarding from LAN to WAN
    uci set firewall.@forwarding[0]=forwarding
    uci set firewall.@forwarding[0].src='lan'
    uci set firewall.@forwarding[0].dest='wan'

    uci commit firewall

    # Restart services to apply changes
    echo "  Restarting network services..."
    /etc/init.d/network restart
    sleep 3
    /etc/init.d/dnsmasq restart
    sleep 2
    /etc/init.d/firewall restart
    sleep 2

    echo "✓ Network configuration applied"
    echo "  - eth1 (LAN): 192.168.1.1/24 with DHCP server (100-250)"
    echo "  - eth0 (WAN): DHCPv4 + DHCPv6 client"
    echo "  - IP forwarding: Enabled"
    echo "  - Firewall: Configured with NAT"
else
    echo "Skipping network configuration (use --apply-network to enable)"
    echo "Manual steps required:"
    echo "  1. Configure eth1 as LAN: 192.168.1.1/24"
    echo "  2. Configure eth0 as WAN: DHCP + DHCPv6"
    echo "  3. Set up DHCP server on eth1 (dnsmasq)"
    echo "  4. Enable IP forwarding"
    echo "  5. Configure firewall for NAT"
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
