#!/bin/sh
#
# Diagnostic and Fix Script for IPv4↔IPv6 Gateway
# Checks network configuration and service status, provides fixes
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Check if running on OpenWrt
if ! command -v uci >/dev/null 2>&1; then
    log_error "This script must be run on OpenWrt (uci not found)"
    exit 1
fi

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

section "DIAGNOSTIC REPORT"

# ============================
# 1. Check Network Configuration
# ============================
section "1. Network Configuration Check"

log_info "Checking eth1 configuration..."
if uci show network.lan >/dev/null 2>&1; then
    ETH1_DEVICE=$(uci get network.lan.device 2>/dev/null || echo "not set")
    ETH1_PROTO=$(uci get network.lan.proto 2>/dev/null || echo "not set")
    ETH1_IPADDR=$(uci get network.lan.ipaddr 2>/dev/null || echo "not set")
    ETH1_NETMASK=$(uci get network.lan.netmask 2>/dev/null || echo "not set")

    echo "  - Device: $ETH1_DEVICE"
    echo "  - Protocol: $ETH1_PROTO"
    echo "  - IP Address: $ETH1_IPADDR"
    echo "  - Netmask: $ETH1_NETMASK"

    if [ "$ETH1_IPADDR" = "192.168.1.1" ]; then
        log_success "eth1 is configured with 192.168.1.1"
        ETH1_CONFIG_OK=1
    else
        log_warning "eth1 IP is not 192.168.1.1 (current: $ETH1_IPADDR)"
        ETH1_CONFIG_OK=0
    fi
else
    log_error "network.lan configuration not found"
    ETH1_CONFIG_OK=0
fi

log_info "Checking eth1 runtime IP address..."
ETH1_IP=$(ip addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "")
if [ -n "$ETH1_IP" ]; then
    echo "  - Runtime IP: $ETH1_IP"
    if [ "$ETH1_IP" = "192.168.1.1" ]; then
        log_success "eth1 has correct IP address at runtime"
        ETH1_RUNTIME_OK=1
    else
        log_warning "eth1 runtime IP mismatch (expected: 192.168.1.1, got: $ETH1_IP)"
        ETH1_RUNTIME_OK=0
    fi
else
    log_error "eth1 has no IP address assigned"
    ETH1_RUNTIME_OK=0
fi

log_info "Checking eth0 (WAN) configuration..."
if uci show network.wan >/dev/null 2>&1; then
    ETH0_DEVICE=$(uci get network.wan.device 2>/dev/null || echo "not set")
    ETH0_PROTO=$(uci get network.wan.proto 2>/dev/null || echo "not set")

    echo "  - Device: $ETH0_DEVICE"
    echo "  - IPv4 Protocol: $ETH0_PROTO"

    if [ "$ETH0_PROTO" = "dhcp" ]; then
        log_success "eth0 is configured for DHCPv4"
        ETH0_IPV4_OK=1
    else
        log_warning "eth0 IPv4 protocol is not dhcp (current: $ETH0_PROTO)"
        ETH0_IPV4_OK=0
    fi
else
    log_error "network.wan configuration not found"
    ETH0_IPV4_OK=0
fi

log_info "Checking eth0 (WAN) IPv6 configuration..."
if uci show network.wan6 >/dev/null 2>&1; then
    ETH0_IPV6_PROTO=$(uci get network.wan6.proto 2>/dev/null || echo "not set")

    echo "  - IPv6 Protocol: $ETH0_IPV6_PROTO"

    if [ "$ETH0_IPV6_PROTO" = "dhcpv6" ]; then
        log_success "eth0 is configured for DHCPv6"
        ETH0_IPV6_OK=1
    else
        log_warning "eth0 IPv6 protocol is not dhcpv6 (current: $ETH0_IPV6_PROTO)"
        ETH0_IPV6_OK=0
    fi
else
    log_warning "network.wan6 configuration not found (IPv6 disabled)"
    ETH0_IPV6_OK=0
fi

# At least one should be configured
if [ "$ETH0_IPV4_OK" -eq 1 ] || [ "$ETH0_IPV6_OK" -eq 1 ]; then
    ETH0_CONFIG_OK=1
else
    ETH0_CONFIG_OK=0
fi

# ============================
# 2. Check DHCP Server
# ============================
section "2. DHCP Server Check"

log_info "Checking DHCP server configuration..."
if uci show dhcp.lan >/dev/null 2>&1; then
    DHCP_INTERFACE=$(uci get dhcp.lan.interface 2>/dev/null || echo "not set")
    DHCP_START=$(uci get dhcp.lan.start 2>/dev/null || echo "not set")
    DHCP_LIMIT=$(uci get dhcp.lan.limit 2>/dev/null || echo "not set")

    echo "  - Interface: $DHCP_INTERFACE"
    echo "  - Start: $DHCP_START"
    echo "  - Limit: $DHCP_LIMIT"

    if [ "$DHCP_INTERFACE" = "lan" ] && [ "$DHCP_START" != "not set" ]; then
        log_success "DHCP server is configured for lan interface"
        DHCP_CONFIG_OK=1
    else
        log_warning "DHCP server configuration might be incomplete"
        DHCP_CONFIG_OK=0
    fi
else
    log_error "DHCP configuration not found"
    DHCP_CONFIG_OK=0
fi

log_info "Checking if dnsmasq is running..."
if pgrep -x dnsmasq >/dev/null; then
    log_success "dnsmasq (DHCP server) is running"
    DHCP_RUNNING=1
else
    log_error "dnsmasq is not running"
    DHCP_RUNNING=0
fi

# ============================
# 3. Check Gateway Service
# ============================
section "3. Gateway Service Check"

log_info "Checking if gateway service exists..."
if [ -f "/etc/init.d/ipv4-ipv6-gateway" ]; then
    log_success "Gateway service script exists"
    SERVICE_EXISTS=1
else
    log_error "Gateway service script not found"
    SERVICE_EXISTS=0
fi

log_info "Checking if gateway service is enabled..."
if [ -L "/etc/rc.d/S99ipv4-ipv6-gateway" ] || [ -L "/etc/rc.d/"*"ipv4-ipv6-gateway" ]; then
    log_success "Gateway service is enabled"
    SERVICE_ENABLED=1
else
    log_warning "Gateway service is not enabled"
    SERVICE_ENABLED=0
fi

log_info "Checking if gateway service is running..."
if pgrep -f "ipv4_ipv6_gateway.py" >/dev/null; then
    log_success "Gateway service process is running"
    SERVICE_RUNNING=1
    PID=$(pgrep -f "ipv4_ipv6_gateway.py")
    echo "  - PID: $PID"
else
    log_error "Gateway service is not running"
    SERVICE_RUNNING=0
fi

# ============================
# 4. Check API Server
# ============================
section "4. API Server Check"

log_info "Checking if API server is listening on port 5050..."
if netstat -tuln 2>/dev/null | grep -q ':5050' || ss -tuln 2>/dev/null | grep -q ':5050'; then
    log_success "API server is listening on port 5050"
    API_LISTENING=1
else
    log_error "API server is not listening on port 5050"
    API_LISTENING=0
fi

log_info "Testing API connectivity (127.0.0.1:5050)..."
if curl -s --connect-timeout 2 http://127.0.0.1:5050/health >/dev/null 2>&1; then
    log_success "API is accessible via 127.0.0.1:5050"
    API_LOCALHOST_OK=1
else
    log_error "Cannot connect to API via 127.0.0.1:5050"
    API_LOCALHOST_OK=0
fi

log_info "Testing API connectivity (192.168.1.1:5050)..."
if [ "$ETH1_RUNTIME_OK" -eq 1 ]; then
    if curl -s --connect-timeout 2 http://192.168.1.1:5050/health >/dev/null 2>&1; then
        log_success "API is accessible via 192.168.1.1:5050"
        API_ETH1_OK=1
    else
        log_error "Cannot connect to API via 192.168.1.1:5050"
        API_ETH1_OK=0
    fi
else
    log_warning "Skipping 192.168.1.1 test (eth1 not configured correctly)"
    API_ETH1_OK=0
fi

# ============================
# 5. Check Firewall
# ============================
section "5. Firewall Check"

log_info "Checking IP forwarding..."
IPV4_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
IPV6_FORWARD=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")

echo "  - IPv4 forwarding: $IPV4_FORWARD"
echo "  - IPv6 forwarding: $IPV6_FORWARD"

if [ "$IPV4_FORWARD" = "1" ] && [ "$IPV6_FORWARD" = "1" ]; then
    log_success "IP forwarding is enabled"
    FORWARDING_OK=1
else
    log_warning "IP forwarding is not fully enabled"
    FORWARDING_OK=0
fi

log_info "Checking iptables rules..."
if iptables -L FORWARD -n 2>/dev/null | grep -q ACCEPT; then
    log_success "iptables FORWARD rules exist"
    IPTABLES_OK=1
else
    log_warning "No iptables FORWARD rules found"
    IPTABLES_OK=0
fi

# ============================
# 6. Summary and Recommendations
# ============================
section "SUMMARY"

TOTAL_CHECKS=14
PASSED_CHECKS=0

[ "$ETH1_CONFIG_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$ETH1_RUNTIME_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$ETH0_CONFIG_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$DHCP_CONFIG_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$DHCP_RUNNING" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$SERVICE_EXISTS" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$SERVICE_ENABLED" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$SERVICE_RUNNING" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$API_LISTENING" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$API_LOCALHOST_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$API_ETH1_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$FORWARDING_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))
[ "$IPTABLES_OK" -eq 1 ] && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo "Checks passed: $PASSED_CHECKS/$TOTAL_CHECKS"
echo ""

# ============================
# 7. Provide Fixes
# ============================
section "RECOMMENDED FIXES"

if [ "$ETH1_CONFIG_OK" -eq 0 ] || [ "$ETH1_RUNTIME_OK" -eq 0 ] || [ "$ETH0_CONFIG_OK" -eq 0 ]; then
    log_warning "Network configuration is incomplete or incorrect"
    echo ""
    echo "FIX: Apply network configuration from /etc/ipv4-ipv6-gateway/network-config.uci:"
    echo "  1. uci import network < /etc/ipv4-ipv6-gateway/network-config.uci"
    echo "  2. uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci"
    echo "  3. uci commit"
    echo "  4. /etc/init.d/network restart"
    echo ""
    echo "OR run the automated fix:"
    echo "  $0 --fix-network"
    echo ""
fi

if [ "$SERVICE_RUNNING" -eq 0 ]; then
    log_warning "Gateway service is not running"
    echo ""
    echo "FIX: Start the gateway service:"
    echo "  /etc/init.d/ipv4-ipv6-gateway start"
    echo ""
    echo "OR run the automated fix:"
    echo "  $0 --fix-service"
    echo ""
fi

if [ "$API_LISTENING" -eq 0 ] && [ "$SERVICE_RUNNING" -eq 1 ]; then
    log_warning "Service is running but API is not listening"
    echo ""
    echo "FIX: Check service logs for errors:"
    echo "  tail -50 /var/log/ipv4-ipv6-gateway.log"
    echo ""
    echo "Then restart the service:"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
fi

if [ "$DHCP_RUNNING" -eq 0 ]; then
    log_warning "DHCP server (dnsmasq) is not running"
    echo ""
    echo "FIX: Start dnsmasq:"
    echo "  /etc/init.d/dnsmasq start"
    echo ""
fi

# ============================
# Automated Fixes
# ============================

if [ "$1" = "--fix-network" ]; then
    section "APPLYING NETWORK CONFIGURATION FIX"

    log_info "Checking if network config files exist..."
    if [ ! -f "/etc/ipv4-ipv6-gateway/network-config.uci" ]; then
        log_error "Network config file not found: /etc/ipv4-ipv6-gateway/network-config.uci"
        exit 1
    fi

    log_info "Backing up current network configuration..."
    uci export network > /etc/ipv4-ipv6-gateway/network.backup.uci
    uci export dhcp > /etc/ipv4-ipv6-gateway/dhcp.backup.uci
    log_success "Backup created"

    log_info "Applying network configuration..."
    uci import network < /etc/ipv4-ipv6-gateway/network-config.uci

    if [ -f "/etc/ipv4-ipv6-gateway/dhcp-config.uci" ]; then
        log_info "Applying DHCP configuration..."
        uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
    fi

    log_info "Committing changes..."
    uci commit

    log_success "Network configuration applied"
    log_info "Restarting network..."
    /etc/init.d/network restart

    sleep 3

    log_success "Network restarted"
    log_info "Restarting dnsmasq..."
    /etc/init.d/dnsmasq restart

    log_success "Network configuration fix completed"
    echo ""
    echo "Please run the diagnostic again to verify:"
    echo "  $0"
    exit 0
fi

if [ "$1" = "--fix-service" ]; then
    section "FIXING GATEWAY SERVICE"

    log_info "Stopping gateway service (if running)..."
    /etc/init.d/ipv4-ipv6-gateway stop 2>/dev/null || true
    sleep 2

    log_info "Starting gateway service..."
    /etc/init.d/ipv4-ipv6-gateway start
    sleep 3

    log_info "Checking service status..."
    if pgrep -f "ipv4_ipv6_gateway.py" >/dev/null; then
        log_success "Gateway service is now running"
        PID=$(pgrep -f "ipv4_ipv6_gateway.py")
        echo "  - PID: $PID"
    else
        log_error "Gateway service failed to start"
        log_info "Showing last 30 lines of log:"
        tail -30 /var/log/ipv4-ipv6-gateway.log
        exit 1
    fi

    log_success "Gateway service fix completed"
    echo ""
    echo "Please run the diagnostic again to verify:"
    echo "  $0"
    exit 0
fi

if [ "$1" = "--fix-all" ]; then
    log_info "Running all automated fixes..."
    echo ""

    # Fix network first
    if [ "$ETH1_CONFIG_OK" -eq 0 ] || [ "$ETH1_RUNTIME_OK" -eq 0 ]; then
        $0 --fix-network
    fi

    # Then fix service
    if [ "$SERVICE_RUNNING" -eq 0 ]; then
        $0 --fix-service
    fi

    log_success "All fixes applied"
    exit 0
fi

# ============================
# Usage Information
# ============================
section "USAGE"
echo "Run diagnostic only:"
echo "  $0"
echo ""
echo "Apply network configuration fix:"
echo "  $0 --fix-network"
echo ""
echo "Fix gateway service:"
echo "  $0 --fix-service"
echo ""
echo "Apply all fixes:"
echo "  $0 --fix-all"
echo ""
