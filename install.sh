#!/bin/bash

# Installation script for IPv4↔IPv6 Gateway Service
# Run this on the NanoPi R5C after flashing OpenWrt

set -e

GATEWAY_USER="gateway"
GATEWAY_GROUP="gateway"
SERVICE_NAME="ipv4-ipv6-gateway"
INSTALL_DIR="/opt/ipv4-ipv6-gateway"
CONFIG_DIR="/etc/ipv4-ipv6-gateway"
LOG_DIR="/var/log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv4↔IPv6 Gateway Service Installer${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Step 1: Install Python dependencies
echo -e "${YELLOW}Step 1: Installing system dependencies...${NC}"
opkg update
opkg install python3 python3-light python3-logging
opkg install odhcp6c iptables ip6tables
opkg install 464xlat
echo -e "${GREEN}✓ Dependencies installed${NC}\n"

# Step 2: Create directories
echo -e "${YELLOW}Step 2: Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "/var/run/$SERVICE_NAME"
echo -e "${GREEN}✓ Directories created${NC}\n"

# Step 3: Copy Python files
echo -e "${YELLOW}Step 3: Installing Python files...${NC}"
cp ipv4_ipv6_gateway.py "$INSTALL_DIR/"
cp gateway_config.py "$INSTALL_DIR/"
cp gateway_api_server.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ipv4_ipv6_gateway.py"
echo -e "${GREEN}✓ Python files installed${NC}\n"

# Step 4: Create systemd service file
echo -e "${YELLOW}Step 4: Creating systemd service...${NC}"
cat > /etc/systemd/system/$SERVICE_NAME.service << 'EOF'
[Unit]
Description=IPv4↔IPv6 Gateway Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/ipv4-ipv6-gateway
ExecStart=/usr/bin/python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/$SERVICE_NAME.service
echo -e "${GREEN}✓ Systemd service created${NC}\n"

# Step 5: Create init.d script (alternative for systems without systemd)
echo -e "${YELLOW}Step 5: Creating init.d script...${NC}"
cat > /etc/init.d/$SERVICE_NAME << 'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=01

start() {
    echo "Starting IPv4↔IPv6 Gateway Service..."
    /usr/bin/python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py &
    echo $! > /var/run/ipv4-ipv6-gateway.pid
}

stop() {
    echo "Stopping IPv4↔IPv6 Gateway Service..."
    kill $(cat /var/run/ipv4-ipv6-gateway.pid 2>/dev/null) 2>/dev/null || true
    rm -f /var/run/ipv4-ipv6-gateway.pid
}

restart() {
    stop
    sleep 1
    start
}

status() {
    if [ -f /var/run/ipv4-ipv6-gateway.pid ]; then
        if kill -0 $(cat /var/run/ipv4-ipv6-gateway.pid) 2>/dev/null; then
            echo "IPv4↔IPv6 Gateway Service is running"
            return 0
        fi
    fi
    echo "IPv4↔IPv6 Gateway Service is not running"
    return 1
}
EOF

chmod +x /etc/init.d/$SERVICE_NAME
echo -e "${GREEN}✓ Init.d script created${NC}\n"

# Step 6: Configure network interfaces
echo -e "${YELLOW}Step 6: Configuring network interfaces...${NC}"
cat > "$CONFIG_DIR/network-config.uci" << 'EOF'
config interface 'lan'
	option ifname 'eth0'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'

config interface 'wan'
	option ifname 'eth1'
	option proto 'dhcpv6'
EOF

echo -e "${GREEN}✓ Network configuration created at $CONFIG_DIR/network-config.uci${NC}\n"

# Step 7: Create sample configuration
echo -e "${YELLOW}Step 7: Creating sample configuration...${NC}"
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
if command -v systemctl &> /dev/null; then
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    echo -e "${GREEN}✓ Service enabled with systemd${NC}"
else
    /etc/init.d/$SERVICE_NAME enable
    echo -e "${GREEN}✓ Service enabled with init.d${NC}"
fi
echo -e ""

# Step 9: Create helper scripts
echo -e "${YELLOW}Step 9: Creating helper scripts...${NC}"

# Status script
cat > /usr/local/bin/gateway-status << 'EOF'
#!/bin/bash
curl -s http://127.0.0.1:8080/status | python3 -m json.tool
EOF
chmod +x /usr/local/bin/gateway-status

# Devices script
cat > /usr/local/bin/gateway-devices << 'EOF'
#!/bin/bash
curl -s "http://127.0.0.1:8080/devices?status=${1:-all}" | python3 -m json.tool
EOF
chmod +x /usr/local/bin/gateway-devices

echo -e "${GREEN}✓ Helper scripts created${NC}\n"

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Configure network interfaces:"
echo "   uci import < $CONFIG_DIR/network-config.uci"
echo "   /etc/init.d/network restart"
echo ""
echo "2. Start the gateway service:"
if command -v systemctl &> /dev/null; then
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
echo "4. List devices:"
echo "   gateway-devices"
echo "   gateway-devices active"
echo ""
echo "5. View logs:"
echo "   tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
echo -e "${YELLOW}API Server:${NC}"
echo "   http://localhost:8080"
echo "   http://localhost:8080/status"
echo "   http://localhost:8080/devices"
echo ""
echo -e "${GREEN}Installation directory: $INSTALL_DIR${NC}"
echo -e "${GREEN}Configuration directory: $CONFIG_DIR${NC}"
echo -e "${GREEN}Log directory: $LOG_DIR${NC}\n"