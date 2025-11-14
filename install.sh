#!/bin/bash
# Installation script for IPv4↔IPv6 Gateway Service
# Installs Python service, network configuration, and helper scripts

set -e  # Exit on error
set -u  # Exit on unbound variable
# Target: NanoPi R5C running OpenWrt (but also works on generic Linux with systemd)
#
# - Installs Python service under /opt/ipv4-ipv6-gateway
# - Creates config dir /etc/ipv4-ipv6-gateway
# - Sets up init.d (OpenWrt/procd) and optional systemd service
# - Creates helper CLI tools: gateway-status, gateway-devices
#
# Usage:
#   ./install.sh                    # Safe mode (manual steps required)
#   ./install.sh --auto-start       # Auto-start service after install
#   ./install.sh --apply-network    # Auto-apply network config
#   ./install.sh --full-auto        # Do everything automatically
#   ./install.sh --help             # Show this help
#

set -e

GATEWAY_USER="gateway"
GATEWAY_GROUP="gateway"
SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/ipv4-ipv6-gateway"
CONFIG_DIR="/etc/ipv4-ipv6-gateway"
LOG_DIR="/var/log"

# Parse command-line arguments
AUTO_START=false
APPLY_NETWORK=false
FULL_AUTO=false
FREE_IPV6_PORTS=true  # Default: true (automatically free IPv6 ports for gateway)

for arg in "$@"; do
    case $arg in
        --auto-start)
            AUTO_START=true
            shift
            ;;
        --apply-network)
            APPLY_NETWORK=true
            shift
            ;;
        --full-auto)
            AUTO_START=true
            APPLY_NETWORK=true
            FULL_AUTO=true
            shift
            ;;
        --free-ipv6-ports)
            FREE_IPV6_PORTS=true
            shift
            ;;
        --no-free-ipv6-ports)
            FREE_IPV6_PORTS=false
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --auto-start           Automatically start the service after installation"
            echo "  --apply-network        Automatically apply network configuration"
            echo "  --full-auto            Do everything automatically (start + network + ports)"
            echo "  --free-ipv6-ports      Free IPv6 ports 80/443/22 for gateway proxies (default)"
            echo "  --no-free-ipv6-ports   Skip freeing IPv6 ports (keep LuCI/SSH on IPv6)"
            echo "  --help                 Show this help message"
            echo ""
            echo "Default behavior (no flags):"
            echo "  - Installs all files and dependencies"
            echo "  - Enables service but DOES NOT start it"
            echo "  - Creates sample network config but DOES NOT apply it"
            echo "  - DOES free IPv6 ports for gateway proxies (disable with --no-free-ipv6-ports)"
            echo "  - Requires manual intervention for safety"
            echo ""
            echo "Examples:"
            echo "  $0                           # Safe mode (frees IPv6 ports)"
            echo "  $0 --auto-start              # Install and start service"
            echo "  $0 --apply-network           # Install and apply network config"
            echo "  $0 --full-auto               # Install, configure, and start everything"
            echo "  $0 --no-free-ipv6-ports      # Install but keep LuCI/SSH on IPv6"
            echo ""
            echo "IPv6 Port Freeing (enabled by default):"
            echo "  When enabled, configures OpenWrt services to free IPv6 ports:"
            echo "  - LuCI web UI: accessible only on http://192.168.1.1 (IPv4)"
            echo "  - SSH: accessible only on ssh root@192.168.1.1 (IPv4)"
            echo "  - Gateway proxies: can bind to IPv6 ports 80, 443, 22"
            echo "  This allows IPv6 clients to access devices via standard ports."
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect init system
if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
else
    INIT_SYSTEM="initd"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv4↔IPv6 Gateway Service Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}Detected init system: $INIT_SYSTEM${NC}\n"

# Check if running as root (portable method)
if [ "$(id -u)" -ne 0 ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Step 1: Install system dependencies (OpenWrt / opkg only)
echo -e "${YELLOW}Step 1: Installing system dependencies (if opkg is available)...${NC}"
if command -v opkg >/dev/null 2>&1; then
    echo -e "${BLUE}Running opkg update...${NC}"
    opkg update || echo -e "${YELLOW}⚠ opkg update failed (no WAN or mirror issue). Continuing...${NC}"

    echo -e "${BLUE}Installing core dependencies...${NC}"
    # Core Python packages
    opkg install python3 python3-light python3-logging 2>/dev/null || echo -e "${YELLOW}⚠ python3 packages may already be installed${NC}"

    # Network tools (required)
    opkg install ip-full 2>/dev/null || echo -e "${YELLOW}⚠ ip-full installation failed or already installed${NC}"
    opkg install odhcp6c 2>/dev/null || echo -e "${YELLOW}⚠ odhcp6c installation failed or already installed${NC}"
    opkg install iptables ip6tables 2>/dev/null || echo -e "${YELLOW}⚠ iptables installation failed or already installed${NC}"

    # IPv6→IPv4 proxy options (required for IPv6 clients to access IPv4-only devices)
    echo -e "${BLUE}Installing IPv6→IPv4 proxy (socat is default, HAProxy is optional)...${NC}"
    opkg install socat 2>/dev/null || echo -e "${YELLOW}⚠ socat installation failed or already installed${NC}"
    opkg install haproxy 2>/dev/null || echo -e "${YELLOW}⚠ haproxy installation failed or already installed (optional)${NC}"

    # Optional but recommended: legacy tools for compatibility
    echo -e "${BLUE}Installing optional compatibility tools...${NC}"
    opkg install net-tools 2>/dev/null || echo -e "${YELLOW}⚠ net-tools (provides 'arp' command) not available - will use 'ip neigh' instead${NC}"
    opkg install busybox 2>/dev/null || echo -e "${YELLOW}⚠ busybox already installed or not available${NC}"

    # Translation layer
    echo -e "${BLUE}Installing 464XLAT for IPv4/IPv6 translation...${NC}"
    opkg install 464xlat 2>/dev/null || echo -e "${YELLOW}⚠ 464xlat installation failed - may need to be configured manually${NC}"

    # Additional useful tools
    opkg install procps-ng procps-ng-sysctl 2>/dev/null || echo -e "${YELLOW}⚠ procps-ng (provides 'sysctl') not available${NC}"
    opkg install nano 2>/dev/null || echo -e "${YELLOW}⚠ nano text editor not available${NC}"
    opkg install bash 2>/dev/null || echo -e "${YELLOW}⚠ bash shell not available${NC}"
    opkg install tcpdump 2>/dev/null || echo -e "${YELLOW}⚠ tcpdump not available (useful for debugging)${NC}"

    # Configure bash with history support
    if command -v bash >/dev/null 2>&1; then
        echo -e "${BLUE}Configuring bash with history support...${NC}"
        cat > /root/.bashrc << 'BASHRC_EOF'
# Bash configuration for OpenWrt
export HISTFILE=/root/.bash_history
export HISTSIZE=1000
export HISTFILESIZE=2000
export HISTCONTROL=ignoredups:erasedups

# Append to history file, don't overwrite
shopt -s histappend

# Save multi-line commands as one command
shopt -s cmdhist

# Color prompt
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# Useful aliases
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'
alias gateway-logs='tail -f /var/log/ipv4-ipv6-gateway.log'
alias gateway-restart='/etc/init.d/ipv4-ipv6-gateway restart'
BASHRC_EOF
        chmod 644 /root/.bashrc
        echo -e "${GREEN}✓ bash configured with history and aliases${NC}"
    fi

    echo -e "${GREEN}✓ Package installation completed${NC}"
    echo -e "${BLUE}Note: Some warnings above are normal if packages are already installed.${NC}"

    # Verify critical proxy backends (HAProxy or socat)
    echo ""
    echo -e "${YELLOW}Verifying IPv6→IPv4 proxy backends...${NC}"

    HAPROXY_OK=false
    SOCAT_OK=false

    # Check HAProxy
    if command -v haproxy >/dev/null 2>&1; then
        echo -e "${BLUE}Checking HAProxy...${NC}"
        if haproxy -v >/dev/null 2>&1; then
            echo -e "${GREEN}✓ HAProxy installed and working (version: $(haproxy -v 2>&1 | head -1))${NC}"
            HAPROXY_OK=true
        else
            echo -e "${YELLOW}⚠ HAProxy binary found but may be broken${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ HAProxy not installed${NC}"
    fi

    # Check socat
    if command -v socat >/dev/null 2>&1; then
        echo -e "${BLUE}Checking socat...${NC}"
        if socat -V >/dev/null 2>&1; then
            echo -e "${GREEN}✓ socat installed and working (version: $(socat -V 2>&1 | head -1))${NC}"
            SOCAT_OK=true
        else
            echo -e "${YELLOW}⚠ socat binary found but may be broken${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ socat not installed${NC}"
    fi

    # Ensure at least one proxy backend is available
    if [ "$HAPROXY_OK" = false ] && [ "$SOCAT_OK" = false ]; then
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}ERROR: No proxy backend available!${NC}"
        echo -e "${RED}========================================${NC}"
        echo -e "${YELLOW}IPv6→IPv4 proxying requires either HAProxy or socat.${NC}"
        echo -e "${YELLOW}Try manually installing:${NC}"
        echo "  opkg update"
        echo "  opkg install haproxy"
        echo "  # OR"
        echo "  opkg install socat"
        echo ""
        echo -e "${YELLOW}You can continue installation, but IPv6→IPv4 proxying will NOT work.${NC}"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Installation cancelled."
            exit 1
        fi
    fi

    # Recommend HAProxy if both available
    if [ "$HAPROXY_OK" = true ] && [ "$SOCAT_OK" = true ]; then
        echo -e "${GREEN}✓ Both HAProxy and socat available (will use HAProxy by default)${NC}"
    elif [ "$HAPROXY_OK" = true ]; then
        echo -e "${GREEN}✓ HAProxy available (recommended for production)${NC}"
    elif [ "$SOCAT_OK" = true ]; then
        echo -e "${YELLOW}⚠ Only socat available (lightweight but less robust)${NC}"
        echo -e "${YELLOW}  Consider installing HAProxy for better reliability:${NC}"
        echo "  opkg install haproxy"
    fi

else
    echo -e "${YELLOW}opkg not found; assuming non-OpenWrt system.${NC}"
    echo -e "${YELLOW}Please ensure these packages are installed:${NC}"
    echo "  - python3 (with logging module)"
    echo "  - ip-full or iproute2"
    echo "  - odhcp6c"
    echo "  - iptables and ip6tables"
    echo "  - socat (for IPv6→IPv4 proxying - lightweight)"
    echo "  - haproxy (for IPv6→IPv4 proxying - production-grade)"
    echo "  - net-tools (optional, provides 'arp')"
    echo "  - 464xlat (for IPv4/IPv6 translation)"
  echo ""
fi
echo ""

# Optional: curl health check (for user info only)
echo -e "${YELLOW}Checking curl health...${NC}"
if command -v curl >/dev/null 2>&1; then
    if ! curl --version >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Detected a broken curl binary (libcurl/OpenSSL mismatch).${NC}"
        echo -e "${YELLOW}  The gateway helpers will fall back to wget where possible.${NC}"
    else
        echo -e "${GREEN}✓ curl appears to be working${NC}"
    fi
else
    echo -e "${YELLOW}curl not found; gateway helpers will use wget if available.${NC}"
fi
echo ""

# Step 1.5: Scan LAN for connected devices
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}PRE-INSTALL NETWORK SCAN${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Scanning LAN (eth1) for connected devices...${NC}"
echo -e "${BLUE}This helps validate your network setup before installation.${NC}"
echo ""

LAN_INTERFACE="eth1"
LAN_DEVICES_FOUND=0

# Cache command availability (avoid repeated checks)
HAS_IP_CMD=$(command -v ip >/dev/null 2>&1 && echo "yes" || echo "no")
HAS_FPING=$(command -v fping >/dev/null 2>&1 && echo "yes" || echo "no")
HAS_ARP=$(command -v arp >/dev/null 2>&1 && echo "yes" || echo "no")

# Check if eth1 exists and is up
if [ "$HAS_IP_CMD" = "yes" ]; then
    if ip link show "$LAN_INTERFACE" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ LAN interface $LAN_INTERFACE found${NC}"

        # Check if interface is up
        if ip link show "$LAN_INTERFACE" | grep -q "state UP"; then
            echo -e "${GREEN}✓ LAN interface is UP${NC}"
        else
            echo -e "${YELLOW}⚠ LAN interface is DOWN - bringing it up...${NC}"
            ip link set "$LAN_INTERFACE" up 2>/dev/null || echo -e "${YELLOW}  Could not bring up interface (may need manual configuration)${NC}"
            sleep 1
        fi

        # Get LAN IP address (optimized - single command)
        LAN_IP=$(ip -4 addr show "$LAN_INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)
        if [ -n "$LAN_IP" ]; then
            echo -e "${GREEN}✓ LAN IPv4: $LAN_IP${NC}"

            # Extract subnet (optimized)
            LAN_SUBNET="${LAN_IP%.*}"

            # Quick ping scan of likely device IPs
            echo -e "${BLUE}Scanning for devices on ${LAN_SUBNET}.0/24...${NC}"

            # OPTIMIZED: Parallel ping scan (much faster!)
            if [ "$HAS_FPING" = "yes" ]; then
                echo -e "${BLUE}Using fping for fast scan...${NC}"
                fping -q -a -g "${LAN_SUBNET}.100" "${LAN_SUBNET}.150" 2>/dev/null &
                fping -q -a -r 0 -t 200 "${LAN_SUBNET}.1" "${LAN_SUBNET}.129" "${LAN_SUBNET}.254" 2>/dev/null &
                wait
            else
                # OPTIMIZED: Parallel background pings (10x faster than sequential!)
                echo -e "${BLUE}Using parallel ping for scan (takes ~2 seconds)...${NC}"
                for i in 1 100 101 128 129 130 131 132 254; do
                    ping -c 1 -W 1 "${LAN_SUBNET}.${i}" >/dev/null 2>&1 &
                done
                # Wait for all background pings to complete
                wait
            fi

            # Wait for ARP table to populate (reduced from 2s to 1s)
            sleep 1

            # Check ARP table for discovered devices
            echo ""
            echo -e "${YELLOW}=== DEVICES FOUND ON LAN ===${NC}"

            if command -v ip >/dev/null 2>&1; then
                # Use 'ip neigh' (modern approach)
                ARP_ENTRIES=$(ip neigh show dev "$LAN_INTERFACE" 2>/dev/null | grep -v "FAILED")

                if [ -n "$ARP_ENTRIES" ]; then
                    LAN_DEVICES_FOUND=$(echo "$ARP_ENTRIES" | wc -l)
                    echo -e "${GREEN}Found $LAN_DEVICES_FOUND device(s) on $LAN_INTERFACE:${NC}"
                    echo ""
                    echo "$ARP_ENTRIES" | while read -r line; do
                        DEVICE_IP=$(echo "$line" | awk '{print $1}')
                        DEVICE_MAC=$(echo "$line" | grep -oP 'lladdr \K[0-9a-f:]+')
                        DEVICE_STATE=$(echo "$line" | awk '{print $NF}')

                        if [ -n "$DEVICE_MAC" ]; then
                            echo -e "  ${BLUE}•${NC} IP: ${GREEN}$DEVICE_IP${NC}  MAC: ${YELLOW}$DEVICE_MAC${NC}  State: $DEVICE_STATE"
                        fi
                    done
                    echo ""
                else
                    echo -e "${YELLOW}⚠ No devices found in ARP table${NC}"
                    LAN_DEVICES_FOUND=0
                fi
            elif command -v arp >/dev/null 2>&1; then
                # Fallback to legacy 'arp' command
                ARP_ENTRIES=$(arp -i "$LAN_INTERFACE" -n 2>/dev/null | grep -v "incomplete")

                if [ -n "$ARP_ENTRIES" ]; then
                    LAN_DEVICES_FOUND=$(echo "$ARP_ENTRIES" | wc -l)
                    echo -e "${GREEN}Found $LAN_DEVICES_FOUND device(s) on $LAN_INTERFACE:${NC}"
                    echo ""
                    echo "$ARP_ENTRIES" | tail -n +2 | while read -r line; do
                        DEVICE_IP=$(echo "$line" | awk '{print $1}')
                        DEVICE_MAC=$(echo "$line" | awk '{print $3}')

                        echo -e "  ${BLUE}•${NC} IP: ${GREEN}$DEVICE_IP${NC}  MAC: ${YELLOW}$DEVICE_MAC${NC}"
                    done
                    echo ""
                else
                    echo -e "${YELLOW}⚠ No devices found in ARP table${NC}"
                    LAN_DEVICES_FOUND=0
                fi
            else
                echo -e "${YELLOW}⚠ Neither 'ip' nor 'arp' command available - cannot check ARP table${NC}"
            fi

        else
            echo -e "${YELLOW}⚠ No IPv4 address configured on $LAN_INTERFACE${NC}"
            echo -e "${BLUE}  The installer will configure it as 192.168.1.1/24${NC}"
        fi

    else
        echo -e "${YELLOW}⚠ LAN interface $LAN_INTERFACE not found${NC}"
        echo -e "${BLUE}  Available interfaces:${NC}"
        ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "    " $2}' | head -5
    fi
else
    echo -e "${YELLOW}⚠ 'ip' command not available - skipping LAN scan${NC}"
fi

echo ""
echo -e "${YELLOW}=== SCAN SUMMARY ===${NC}"
if [ $LAN_DEVICES_FOUND -gt 0 ]; then
    echo -e "${GREEN}✓ Found $LAN_DEVICES_FOUND device(s) on LAN${NC}"
    echo -e "${GREEN}✓ Network setup looks good!${NC}"
    echo -e "${BLUE}  The gateway will discover and configure these devices automatically.${NC}"
else
    echo -e "${YELLOW}⚠ No devices detected on LAN${NC}"
    echo -e "${YELLOW}  This could mean:${NC}"
    echo -e "${YELLOW}  1. No device is connected to eth1${NC}"
    echo -e "${YELLOW}  2. Device is connected but hasn't sent any packets yet${NC}"
    echo -e "${YELLOW}  3. LAN interface needs configuration (installer will handle this)${NC}"
    echo ""
    echo -e "${BLUE}  After installation, connect your device and the gateway will detect it automatically.${NC}"
fi
echo ""
echo -e "${GREEN}========================================${NC}"
echo ""

# Step 2: Create directories
echo -e "${YELLOW}Step 2: Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "/var/run/$SERVICE_NAME"
echo -e "${GREEN}✓ Directories created${NC}\n"

# Step 3: Copy Python files
echo -e "${YELLOW}Step 3: Installing Python files...${NC}"
# Validate that required Python files exist
for file in ipv4_ipv6_gateway.py gateway_config.py gateway_api_server.py haproxy_manager.py; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: Required file '$file' not found in current directory${NC}"
        echo -e "${YELLOW}Make sure you're running this script from the project root directory${NC}"
        exit 1
    fi
done

# Copy files
cp ipv4_ipv6_gateway.py "$INSTALL_DIR/"
cp gateway_config.py "$INSTALL_DIR/"
cp gateway_api_server.py "$INSTALL_DIR/"
cp haproxy_manager.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ipv4_ipv6_gateway.py"
echo -e "${GREEN}✓ Python files installed to $INSTALL_DIR${NC}\n"

# Step 3.5: Copy diagnostic and direct helper scripts (if available)
echo -e "${YELLOW}Step 3.5: Installing diagnostic and direct helper scripts...${NC}"
if [ -f "diagnose-and-fix.sh" ]; then
    cp diagnose-and-fix.sh /usr/bin/gateway-diagnose
    chmod +x /usr/bin/gateway-diagnose
    echo -e "${GREEN}✓ Diagnostic script installed to /usr/bin/gateway-diagnose${NC}"
else
    echo -e "${YELLOW}⚠ diagnose-and-fix.sh not found, skipping${NC}"
fi

if [ -f "gateway-status-direct.sh" ]; then
    cp gateway-status-direct.sh /usr/bin/gateway-status-direct
    chmod +x /usr/bin/gateway-status-direct
    echo -e "${GREEN}✓ Direct status script installed to /usr/bin/gateway-status-direct (works without API)${NC}"
else
    echo -e "${YELLOW}⚠ gateway-status-direct.sh not found, skipping${NC}"
fi

if [ -f "gateway-devices-direct.sh" ]; then
    cp gateway-devices-direct.sh /usr/bin/gateway-devices-direct
    chmod +x /usr/bin/gateway-devices-direct
    echo -e "${GREEN}✓ Direct devices script installed to /usr/bin/gateway-devices-direct (works without API)${NC}"
else
    echo -e "${YELLOW}⚠ gateway-devices-direct.sh not found, skipping${NC}"
fi

if [ -f "setup-port-forwarding.sh" ]; then
    cp setup-port-forwarding.sh /usr/bin/gateway-port-forward
    chmod +x /usr/bin/gateway-port-forward
    echo -e "${GREEN}✓ Port forwarding script installed to /usr/bin/gateway-port-forward${NC}"
else
    echo -e "${YELLOW}⚠ setup-port-forwarding.sh not found, skipping${NC}"
fi

if [ -f "monitor-connections.sh" ]; then
    cp monitor-connections.sh /usr/bin/monitor-connections
    chmod +x /usr/bin/monitor-connections
    echo -e "${GREEN}✓ Connection monitor script installed to /usr/bin/monitor-connections${NC}"
else
    echo -e "${YELLOW}⚠ monitor-connections.sh not found, skipping${NC}"
fi

if [ -f "capture-traffic.sh" ]; then
    cp capture-traffic.sh /usr/bin/capture-traffic
    chmod +x /usr/bin/capture-traffic
    echo -e "${GREEN}✓ Traffic capture script installed to /usr/bin/capture-traffic${NC}"
else
    echo -e "${YELLOW}⚠ capture-traffic.sh not found, skipping${NC}"
fi

if [ -f "debug-connections.sh" ]; then
    cp debug-connections.sh /usr/bin/debug-connections
    chmod +x /usr/bin/debug-connections
    echo -e "${GREEN}✓ Connection debug script installed to /usr/bin/debug-connections${NC}"
else
    echo -e "${YELLOW}⚠ debug-connections.sh not found, skipping${NC}"
fi
echo ""

# Step 4: Create systemd service file (only if systemd exists)
if [ "$INIT_SYSTEM" = "systemd" ]; then
    echo -e "${YELLOW}Step 4: Creating systemd service...${NC}"
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=IPv4↔IPv6 Gateway Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ipv4_ipv6_gateway.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/$SERVICE_NAME.service
    echo -e "${GREEN}✓ Systemd service created${NC}\n"
else
    echo -e "${BLUE}Step 4: Skipping systemd (not available)${NC}\n"
fi

# Step 5: Create init.d script (OpenWrt / rc.common + procd)
echo -e "${YELLOW}Step 5: Creating init.d script...${NC}"
cat > /etc/init.d/$SERVICE_NAME << 'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=01

USE_PROCD=1
SERVICE_NAME="ipv4-ipv6-gateway"
DAEMON="/usr/bin/python3"
DAEMON_OPTS="/opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py"
PIDFILE="/var/run/ipv4-ipv6-gateway.pid"
LOGFILE="/var/log/ipv4-ipv6-gateway.log"

start_service() {
    mkdir -p /var/run/$SERVICE_NAME

    procd_open_instance
    procd_set_param command "$DAEMON" $DAEMON_OPTS
    procd_set_param respawn
    procd_set_param pidfile "$PIDFILE"
    procd_close_instance
}

stop_service() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
}

status() {
    if [ -f "$PIDFILE" ]; then
        if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "IPv4↔IPv6 Gateway Service is running (PID: $(cat "$PIDFILE"))"
            return 0
        fi
    fi
    echo "IPv4↔IPv6 Gateway Service is not running"
    return 1
}
EOF

chmod +x /etc/init.d/$SERVICE_NAME
echo -e "${GREEN}✓ Init.d script created${NC}\n"

# Step 6: Backup current network config and create sample UCI config
echo -e "${YELLOW}Step 6: Backing up network config and creating sample UCI config...${NC}"

LIVE_NET_CFG="/etc/config/network"
LIVE_DHCP_CFG="/etc/config/dhcp"
ORIG_NET_BACKUP="$CONFIG_DIR/network.original"
ORIG_DHCP_BACKUP="$CONFIG_DIR/dhcp.original"

# Backup network config
if [ -f "$LIVE_NET_CFG" ]; then
    # Only back up once so we don't overwrite the original baseline
    if [ ! -f "$ORIG_NET_BACKUP" ]; then
        cp "$LIVE_NET_CFG" "$ORIG_NET_BACKUP"
        echo -e "${GREEN}✓ Backed up current /etc/config/network to $ORIG_NET_BACKUP${NC}"
    else
        echo -e "${YELLOW}⚠ Network backup already exists at $ORIG_NET_BACKUP, not overwriting${NC}"
    fi
else
    echo -e "${YELLOW}⚠ /etc/config/network not found, skipping backup${NC}"
fi

# Backup DHCP config
if [ -f "$LIVE_DHCP_CFG" ]; then
    if [ ! -f "$ORIG_DHCP_BACKUP" ]; then
        cp "$LIVE_DHCP_CFG" "$ORIG_DHCP_BACKUP"
        echo -e "${GREEN}✓ Backed up current /etc/config/dhcp to $ORIG_DHCP_BACKUP${NC}"
    else
        echo -e "${YELLOW}⚠ DHCP backup already exists at $ORIG_DHCP_BACKUP, not overwriting${NC}"
    fi
else
    echo -e "${YELLOW}⚠ /etc/config/dhcp not found, skipping backup${NC}"
fi

# Create network configuration
cat > "$CONFIG_DIR/network-config.uci" << 'EOF'
package network

# Flexible IPv4/IPv6 Gateway Network Configuration
# eth1 (LAN side) - IPv4 devices (always 192.168.1.0/24)
# eth0 (WAN side) - Supports IPv4, IPv6, or dual-stack

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
	option reqaddress 'try'
	option reqprefix 'auto'

config device
	option name 'eth0'

config device
	option name 'eth1'
EOF

echo -e "${GREEN}✓ Network configuration created at $CONFIG_DIR/network-config.uci${NC}"

# Create DHCP configuration
cat > "$CONFIG_DIR/dhcp-config.uci" << 'EOF'
package dhcp

# DHCP server configuration for LAN (eth1) interface
# Provides IPv4 addresses to devices on 192.168.1.0/24 network

config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	option dhcpv4 'server'
	option dhcpv6 'disabled'
	option ra 'disabled'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'
EOF

echo -e "${GREEN}✓ DHCP configuration created at $CONFIG_DIR/dhcp-config.uci${NC}\n"

# Step 6.5: Create firewall configuration and enable IPv6 traffic
echo -e "${YELLOW}Step 6.5: Creating firewall configuration...${NC}"
cat > "$CONFIG_DIR/firewall-config.uci" << 'EOF'
package firewall

# Firewall configuration for dual-stack gateway
# Allows forwarding between LAN (eth1) and WAN (eth0)
# Enables IPv6 TCP traffic for HAProxy proxying

config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option syn_flood '1'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	option mtu_fix '1'

config forwarding
	option src 'lan'
	option dest 'wan'

config rule
	option name 'Allow-DHCP-Renew'
	option src 'wan'
	option proto 'udp'
	option dest_port '68'
	option target 'ACCEPT'
	option family 'ipv4'

config rule
	option name 'Allow-DHCPv6'
	option src 'wan'
	option proto 'udp'
	option dest_port '546'
	option target 'ACCEPT'
	option family 'ipv6'

config rule
	option name 'Allow-ICMPv6'
	option src 'wan'
	option proto 'icmp'
	option icmp_type 'echo-request'
	option family 'ipv6'
	option target 'ACCEPT'

config rule
	option name 'Allow-IPv6-TCP-Proxy'
	option src 'wan'
	option proto 'tcp'
	option family 'ipv6'
	option target 'ACCEPT'
EOF

echo -e "${GREEN}✓ Firewall configuration created at $CONFIG_DIR/firewall-config.uci${NC}"

# Immediately enable IPv6 TCP traffic with ip6tables (if available)
echo -e "${YELLOW}Enabling IPv6 TCP traffic with ip6tables...${NC}"
if command -v ip6tables >/dev/null 2>&1; then
    # Allow incoming IPv6 TCP connections
    ip6tables -I INPUT -p tcp -j ACCEPT 2>/dev/null || echo -e "${YELLOW}⚠ Could not add ip6tables INPUT rule${NC}"

    # Allow forwarding IPv6 TCP
    ip6tables -I FORWARD -p tcp -j ACCEPT 2>/dev/null || echo -e "${YELLOW}⚠ Could not add ip6tables FORWARD rule${NC}"

    # Allow established/related connections
    ip6tables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || echo -e "${YELLOW}⚠ Could not add ip6tables state rule${NC}"

    # Allow ICMPv6 (ping, neighbor discovery, etc.)
    ip6tables -I INPUT -p ipv6-icmp -j ACCEPT 2>/dev/null || echo -e "${YELLOW}⚠ Could not add ip6tables ICMPv6 rule${NC}"

    echo -e "${GREEN}✓ IPv6 firewall rules added with ip6tables${NC}"
else
    echo -e "${YELLOW}⚠ ip6tables not found - IPv6 firewall rules not added${NC}"
    echo -e "${YELLOW}  Apply firewall config manually: uci import firewall < $CONFIG_DIR/firewall-config.uci${NC}"
fi
echo ""

# Step 7: Create sample override configuration
echo -e "${YELLOW}Step 7: Creating sample override configuration...${NC}"
cat > "$CONFIG_DIR/config.py" << 'EOF'
# Override any settings from gateway_config.py here
# Example:
# LOG_LEVEL = 'DEBUG'
# ARP_MONITOR_INTERVAL = 5
# API_PORT = 8888
EOF
echo -e "${GREEN}✓ Sample configuration created at $CONFIG_DIR/config.py${NC}\n"

# Step 8: Enable services
echo -e "${YELLOW}Step 8: Enabling services...${NC}"
if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl daemon-reload || true
    systemctl enable $SERVICE_NAME || true
    echo -e "${GREEN}✓ Service enabled with systemd${NC}"
fi

if [ -x "/etc/init.d/$SERVICE_NAME" ]; then
    /etc/init.d/$SERVICE_NAME enable || true
    echo -e "${GREEN}✓ Service enabled with init.d (OpenWrt)${NC}"
fi
echo ""

# Step 8.5: Free IPv6 ports 80, 443, 22 for gateway proxies
if [ "$FREE_IPV6_PORTS" = true ]; then
    echo -e "${YELLOW}Step 8.5: Freeing IPv6 ports for gateway proxies...${NC}"
    echo -e "${BLUE}Configuring OpenWrt services to free IPv6 ports 80, 443, 22...${NC}"

    # Check if UCI is available (OpenWrt only)
    if command -v uci >/dev/null 2>&1; then
        # Configure uhttpd (LuCI) to IPv4 only
        if [ -f /etc/config/uhttpd ]; then
            echo -e "${BLUE}- Configuring LuCI web interface (uhttpd) to LAN IPv4 only...${NC}"
            echo -e "${BLUE}  This frees up WAN ports 80/443 for device IPv6→IPv4 proxies${NC}"

            # Backup current uhttpd config
            cp /etc/config/uhttpd /etc/config/uhttpd.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

            # Stop uhttpd
            /etc/init.d/uhttpd stop 2>/dev/null || true

            # CRITICAL: Remove any wildcard bindings (including IPv6 [::])
            # This ensures LuCI doesn't bind to WAN interface
            uci delete uhttpd.main.listen_http 2>/dev/null || true
            uci delete uhttpd.main.listen_https 2>/dev/null || true
            uci delete uhttpd.main.listen_http6 2>/dev/null || true
            uci delete uhttpd.main.listen_https6 2>/dev/null || true

            # Set explicit LAN IPv4 addresses ONLY
            # This binds to 192.168.1.1 (LAN) and leaves WAN free
            uci add_list uhttpd.main.listen_http='192.168.1.1:80' 2>/dev/null || true
            uci add_list uhttpd.main.listen_https='192.168.1.1:443' 2>/dev/null || true

            # Commit and restart
            uci commit uhttpd 2>/dev/null || true
            /etc/init.d/uhttpd start 2>/dev/null || true

            echo -e "${GREEN}  ✓ LuCI bound to LAN only (http://192.168.1.1)${NC}"
            echo -e "${GREEN}  ✓ WAN ports 80/443 now available for device proxies${NC}"
        else
            echo -e "${YELLOW}  ⚠ uhttpd config not found, skipping${NC}"
        fi

        # Configure dropbear (SSH) to LAN/IPv4 only
        if [ -f /etc/config/dropbear ]; then
            echo -e "${BLUE}- Configuring SSH server (dropbear) to LAN only...${NC}"
            echo -e "${BLUE}  This frees up WAN port 22 for device IPv6→IPv4 proxies${NC}"

            # Backup current dropbear config
            cp /etc/config/dropbear /etc/config/dropbear.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

            # Set Interface to 'lan' (restricts to LAN subnet, blocks WAN access)
            uci set dropbear.@dropbear[0].Interface='lan' 2>/dev/null || true
            uci set dropbear.@dropbear[0].GatewayPorts='off' 2>/dev/null || true

            # Commit and restart
            uci commit dropbear 2>/dev/null || true
            /etc/init.d/dropbear restart 2>/dev/null || true

            echo -e "${GREEN}  ✓ SSH configured for LAN/IPv4 only (ssh root@192.168.1.1)${NC}"
        else
            echo -e "${YELLOW}  ⚠ dropbear config not found, skipping${NC}"
        fi

        echo -e "${GREEN}✓ IPv6 ports 80, 443, 22 freed for gateway proxies${NC}"
        echo -e "${BLUE}  LuCI web UI: http://192.168.1.1 (IPv4 only)${NC}"
        echo -e "${BLUE}  SSH: ssh root@192.168.1.1 (IPv4 only)${NC}"
        echo -e "${BLUE}  Gateway proxies: Can bind to IPv6 ports 80, 443, 22${NC}"
    else
        echo -e "${YELLOW}UCI not found (not OpenWrt) - skipping IPv6 port freeing${NC}"
        echo -e "${YELLOW}Manually free ports 80, 443, 22 on IPv6 if needed${NC}"
    fi
else
    echo -e "${BLUE}Step 8.5: Skipping IPv6 port freeing (--no-free-ipv6-ports specified)${NC}"
    echo -e "${YELLOW}⚠ Gateway proxies may conflict with LuCI/SSH on IPv6 ports 80, 443, 22${NC}"
    echo -e "${YELLOW}  Run free-ipv6-ports.sh manually if needed${NC}"
fi
echo ""

# Step 9: Create helper scripts (API-based and direct)
echo -e "${YELLOW}Step 9: Creating helper scripts...${NC}"

# Status script (API-based, requires network)
cat > /usr/bin/gateway-status << 'EOF'
#!/bin/sh
# Try multiple hosts to find working API endpoint
for HOST in 127.0.0.1 192.168.1.1 localhost; do
    URL="http://${HOST}:5050/status"

    http_get() {
        if command -v curl >/dev/null 2>&1; then
            curl -s --connect-timeout 2 "$1" 2>&1
            return $?
        fi

        if command -v wget >/dev/null 2>&1; then
            wget -qO- --timeout=2 "$1" 2>&1
            return $?
        fi

        echo "Error: neither curl nor wget is available" >&2
        return 1
    }

    # Get the response
    RESPONSE=$(http_get "$URL")
    EXIT_CODE=$?

    # If successful, use this host
    if [ $EXIT_CODE -eq 0 ] && [ -n "$RESPONSE" ]; then
        # Try to parse as JSON
        echo "$RESPONSE" | python3 -m json.tool 2>/dev/null
        if [ $? -eq 0 ]; then
            exit 0
        fi
    fi
done

# If we get here, all attempts failed
echo "Error: Failed to connect to API server"
echo ""
echo "Troubleshooting:"
echo "  1. Check if service is running: ps | grep ipv4_ipv6_gateway"
echo "  2. Check logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo "  3. Check port: netstat -tlnp | grep 5050"
echo "  4. Try manually: curl http://192.168.1.1:5050/status"
exit 1
EOF
chmod +x /usr/bin/gateway-status

# Devices script
cat > /usr/bin/gateway-devices << 'EOF'
#!/bin/sh
STATUS="${1:-all}"

# Try multiple hosts to find working API endpoint
for HOST in 127.0.0.1 192.168.1.1 localhost; do
    URL="http://${HOST}:5050/devices?status=${STATUS}"

    http_get() {
        if command -v curl >/dev/null 2>&1; then
            curl -s --connect-timeout 2 "$1" 2>&1
            return $?
        fi

        if command -v wget >/dev/null 2>&1; then
            wget -qO- --timeout=2 "$1" 2>&1
            return $?
        fi

        echo "Error: neither curl nor wget is available" >&2
        return 1
    }

    # Get the response
    RESPONSE=$(http_get "$URL")
    EXIT_CODE=$?

    # If successful, use this host
    if [ $EXIT_CODE -eq 0 ] && [ -n "$RESPONSE" ]; then
        # Try to parse as JSON
        echo "$RESPONSE" | python3 -m json.tool 2>/dev/null
        if [ $? -eq 0 ]; then
            exit 0
        fi
    fi
done

# If we get here, all attempts failed
echo "Error: Failed to connect to API server"
echo "Tried: 127.0.0.1, 192.168.1.1, localhost"
echo ""
echo "Try manually: curl http://192.168.1.1:5050/devices"
exit 1
EOF
chmod +x /usr/bin/gateway-devices

echo -e "${GREEN}✓ Helper scripts created${NC}\n"

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}Init System: $INIT_SYSTEM${NC}\n"

# Automatic actions based on flags
if [ "$APPLY_NETWORK" = true ]; then
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}AUTO-APPLYING NETWORK CONFIGURATION${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${RED}⚠ WARNING: This may disconnect your SSH session!${NC}"
    echo -e "${YELLOW}Applying network config in 5 seconds... (Ctrl+C to cancel)${NC}"
    sleep 5

    if command -v uci >/dev/null 2>&1; then
        echo -e "${BLUE}Backing up current configuration...${NC}"
        uci export network > /tmp/network.backup.uci.tmp || true
        uci export dhcp > /tmp/dhcp.backup.uci.tmp || true
        echo -e "${GREEN}✓ Backup created${NC}"

        echo -e "${BLUE}Importing network configuration...${NC}"
        uci import network < "$CONFIG_DIR/network-config.uci" || {
            echo -e "${RED}⚠ Failed to import network config${NC}"
            echo -e "${YELLOW}Manual import: uci import network < $CONFIG_DIR/network-config.uci${NC}"
        }

        echo -e "${BLUE}Importing DHCP configuration...${NC}"
        uci import dhcp < "$CONFIG_DIR/dhcp-config.uci" || {
            echo -e "${RED}⚠ Failed to import DHCP config${NC}"
            echo -e "${YELLOW}Manual import: uci import dhcp < $CONFIG_DIR/dhcp-config.uci${NC}"
        }

        echo -e "${BLUE}Committing changes...${NC}"
        uci commit || echo -e "${RED}⚠ Failed to commit UCI changes${NC}"

        echo -e "${BLUE}Restarting network...${NC}"
        /etc/init.d/network restart || echo -e "${RED}⚠ Failed to restart network${NC}"
        sleep 3

        echo -e "${BLUE}Restarting DHCP server (dnsmasq)...${NC}"
        /etc/init.d/dnsmasq restart || echo -e "${RED}⚠ Failed to restart dnsmasq${NC}"

        echo -e "${GREEN}✓ Network configuration applied${NC}"
        echo -e "${YELLOW}⚠ If you lost SSH connection, reconnect to 192.168.1.1${NC}"
    else
        echo -e "${YELLOW}UCI not found (not OpenWrt?). Skipping network config.${NC}"
    fi
    echo ""
fi

if [ "$AUTO_START" = true ]; then
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}AUTO-STARTING SERVICE${NC}"
    echo -e "${YELLOW}========================================${NC}"

    if [ "$INIT_SYSTEM" = "systemd" ]; then
        echo -e "${BLUE}Starting service with systemd...${NC}"
        systemctl start $SERVICE_NAME
        sleep 2
        systemctl status $SERVICE_NAME --no-pager || true
    else
        echo -e "${BLUE}Starting service with init.d...${NC}"
        /etc/init.d/$SERVICE_NAME start
        sleep 2
        /etc/init.d/$SERVICE_NAME status || true
    fi

    echo ""
    echo -e "${BLUE}Checking service health...${NC}"
    sleep 3
    if gateway-status >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Service started successfully!${NC}"
        echo ""
        gateway-status
    else
        echo -e "${YELLOW}⚠ Service may still be starting or encountered an error${NC}"
        echo -e "${YELLOW}  Check logs: tail -f /var/log/ipv4-ipv6-gateway.log${NC}"
    fi
    echo ""
fi

# Show next steps or completion message
if [ "$FULL_AUTO" = true ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}FULLY AUTOMATIC INSTALLATION COMPLETE!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${GREEN}✓ All dependencies installed${NC}"
    echo -e "${GREEN}✓ Service files created${NC}"
    echo -e "${GREEN}✓ Network configuration applied${NC}"
    echo -e "${GREEN}✓ Service started${NC}"
    echo ""
    echo -e "${YELLOW}Quick Commands:${NC}"
    echo "   gateway-status          # Check status"
    echo "   gateway-devices         # List devices"
    echo "   gateway-port-forward quick-device 192.168.1.100  # Setup port forwarding"
    echo "   tail -f /var/log/ipv4-ipv6-gateway.log  # View logs"
    echo ""
elif [ "$AUTO_START" = true ] || [ "$APPLY_NETWORK" = true ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}SEMI-AUTOMATIC INSTALLATION COMPLETE!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    if [ "$AUTO_START" = false ]; then
        echo -e "${YELLOW}Remaining Manual Steps:${NC}"
        echo ""
        echo "2. Start the gateway service:"
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            echo "   systemctl start $SERVICE_NAME"
        else
            echo "   /etc/init.d/$SERVICE_NAME start"
        fi
        echo ""
    fi
    if [ "$APPLY_NETWORK" = false ]; then
        echo -e "${YELLOW}Remaining Manual Steps:${NC}"
        echo ""
        echo "1. Review and apply network configuration:"
        echo "   cat $CONFIG_DIR/network-config.uci"
        echo "   cat $CONFIG_DIR/dhcp-config.uci"
        echo "   uci import network < $CONFIG_DIR/network-config.uci"
        echo "   uci import dhcp < $CONFIG_DIR/dhcp-config.uci"
        echo "   uci commit"
        echo "   /etc/init.d/network restart"
        echo "   /etc/init.d/dnsmasq restart"
        echo ""
    fi
else
    echo -e "${YELLOW}Next Steps (Manual):${NC}"
    echo ""
    echo "1. Review and apply network configuration:"
    echo "   cat $CONFIG_DIR/network-config.uci"
    echo "   uci import < $CONFIG_DIR/network-config.uci"
    echo "   /etc/init.d/network restart"
    echo ""
    echo "2. Start the gateway service:"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        echo "   systemctl start $SERVICE_NAME"
        echo "   systemctl status $SERVICE_NAME"
    else
        echo "   /etc/init.d/$SERVICE_NAME start"
        echo "   /etc/init.d/$SERVICE_NAME status"
    fi
    echo ""
    echo "3. Check status:"
    echo "   gateway-status"
    echo ""
fi

echo -e "${YELLOW}Diagnostic Commands:${NC}"
echo "   gateway-diagnose        # Run comprehensive diagnostic"
echo "   gateway-diagnose --fix-all   # Apply all recommended fixes"
echo ""
echo -e "${YELLOW}Monitoring Commands:${NC}"
echo "   gateway-status          # Check gateway status"
echo "   gateway-devices         # List all devices"
echo "   gateway-devices active  # List active devices"
echo "   tail -f /var/log/ipv4-ipv6-gateway.log  # View logs"
echo ""
echo -e "${YELLOW}API Endpoints:${NC}"
echo "   http://localhost:5050/health    # Health check"
echo "   http://localhost:5050/status    # Gateway status"
echo "   http://localhost:5050/devices   # List devices"
echo ""
echo -e "${GREEN}Installation Locations:${NC}"
echo "   Service: $INSTALL_DIR"
echo "   Config:  $CONFIG_DIR"
echo "   Logs:    $LOG_DIR"
echo ""
echo -e "${YELLOW}Service Management:${NC}"
if [ "$INIT_SYSTEM" = "systemd" ]; then
    echo "   systemctl start/stop/restart/status $SERVICE_NAME"
else
    echo "   /etc/init.d/$SERVICE_NAME start/stop/restart/status"
    echo "   /etc/init.d/$SERVICE_NAME enable/disable (auto-start)"
fi
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}Tip: Run with --full-auto next time for zero-touch deployment!${NC}"
echo -e "${GREEN}========================================${NC}\n"
