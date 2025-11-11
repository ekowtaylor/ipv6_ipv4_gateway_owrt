#!/bin/sh
#
# IPv6 Port Forwarding Setup (NAT64 + Port Forwarding)
# Allows IPv6-only clients to access IPv4 devices
#
# This script sets up:
# 1. NAT64 translation (IPv6 → IPv4)
# 2. Port forwarding (IPv4 gateway → IPv4 device)
#
# Usage:
#   ./setup-ipv6-port-forwarding.sh enable <device_ip>
#   ./setup-ipv6-port-forwarding.sh disable
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WAN_INTERFACE="eth0"
LAN_INTERFACE="eth1"

# NAT64 prefix (well-known prefix for IPv4-embedded IPv6 addresses)
NAT64_PREFIX="64:ff9b::/96"

show_help() {
    echo "IPv6 Port Forwarding Setup"
    echo ""
    echo "Enables IPv6-only clients to access IPv4 devices via NAT64 + port forwarding."
    echo ""
    echo "Usage:"
    echo "  $0 enable <device_ip>     Enable IPv6 port forwarding for device"
    echo "  $0 disable                Disable IPv6 port forwarding"
    echo "  $0 status                 Show current configuration"
    echo ""
    echo "Example:"
    echo "  $0 enable 192.168.1.100"
    echo ""
    echo "After enabling, IPv6 clients can access:"
    echo "  http://[<gateway-ipv6>]:8080    # Device's HTTP (port 80)"
    echo "  telnet <gateway-ipv6> 2323      # Device's Telnet (port 23)"
    echo ""
}

enable_nat64() {
    DEVICE_IP=$1

    if [ -z "$DEVICE_IP" ]; then
        echo -e "${RED}Error: Device IP required${NC}"
        echo "Usage: $0 enable <device_ip>"
        exit 1
    fi

    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Enabling IPv6 Port Forwarding${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    echo -e "${BLUE}Target device: $DEVICE_IP${NC}"
    echo ""

    # Get gateway's IPv6 address
    GATEWAY_IPV6=$(ip -6 addr show $WAN_INTERFACE | grep 'inet6' | grep -v 'fe80' | head -1 | awk '{print $2}' | cut -d'/' -f1)

    if [ -z "$GATEWAY_IPV6" ]; then
        echo -e "${RED}Error: No IPv6 address found on $WAN_INTERFACE${NC}"
        echo -e "${YELLOW}Make sure eth0 has a global IPv6 address${NC}"
        exit 1
    fi

    echo -e "${BLUE}Gateway IPv6: $GATEWAY_IPV6${NC}"
    echo ""

    # Step 1: Enable IPv6 forwarding
    echo -e "${YELLOW}Step 1: Enabling IPv6 forwarding...${NC}"
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    sysctl -w net.ipv6.conf.$WAN_INTERFACE.forwarding=1 >/dev/null
    echo -e "${GREEN}✓ IPv6 forwarding enabled${NC}"
    echo ""

    # Step 2: Set up IPv6 firewall rules (ip6tables)
    echo -e "${YELLOW}Step 2: Setting up IPv6 firewall rules...${NC}"

    # Allow forwarding from WAN to LAN
    ip6tables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT 2>/dev/null || true
    ip6tables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT 2>/dev/null || true

    echo -e "${GREEN}✓ IPv6 firewall rules added${NC}"
    echo ""

    # Step 3: Set up port forwarding (same as IPv4)
    echo -e "${YELLOW}Step 3: Setting up port forwards (IPv4)...${NC}"

    # HTTP
    iptables -t nat -A PREROUTING -i $WAN_INTERFACE -p tcp --dport 8080 \
        -j DNAT --to-destination $DEVICE_IP:80 2>/dev/null || true
    iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE \
        -p tcp -d $DEVICE_IP --dport 80 -j ACCEPT 2>/dev/null || true

    # Telnet
    iptables -t nat -A PREROUTING -i $WAN_INTERFACE -p tcp --dport 2323 \
        -j DNAT --to-destination $DEVICE_IP:23 2>/dev/null || true
    iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE \
        -p tcp -d $DEVICE_IP --dport 23 -j ACCEPT 2>/dev/null || true

    echo -e "${GREEN}✓ Port forwards configured${NC}"
    echo ""

    # Step 4: Install Tayga (NAT64) if available
    echo -e "${YELLOW}Step 4: Checking for NAT64 support (Tayga)...${NC}"

    if command -v tayga >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Tayga found, configuring NAT64...${NC}"

        # Create tayga config
        cat > /tmp/tayga.conf << EOF
tun-device nat64
ipv4-addr 192.168.255.1
ipv6-addr fc00::1
prefix $NAT64_PREFIX
dynamic-pool 192.168.255.0/24
data-dir /var/db/tayga
EOF

        # Start tayga
        mkdir -p /var/db/tayga
        tayga --config /tmp/tayga.conf --mktun 2>/dev/null || true
        tayga --config /tmp/tayga.conf 2>/dev/null &

        # Add routes
        ip link set nat64 up
        ip route add $NAT64_PREFIX dev nat64 2>/dev/null || true

        echo -e "${GREEN}✓ NAT64 configured${NC}"
    else
        echo -e "${YELLOW}⚠ Tayga not found - install with: opkg install tayga${NC}"
        echo -e "${YELLOW}  Without NAT64, only dual-stack clients can access forwarded ports${NC}"
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}IPv6 Port Forwarding Enabled!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Access from IPv6 clients:${NC}"
    echo ""
    echo -e "${BLUE}HTTP:${NC}"
    echo "  http://[${GATEWAY_IPV6}]:8080"
    echo ""
    echo -e "${BLUE}Telnet:${NC}"
    echo "  telnet ${GATEWAY_IPV6} 2323"
    echo ""
    echo -e "${YELLOW}Or use dual-stack (if available):${NC}"
    echo "  http://192.168.1.1:8080"
    echo ""
}

disable_nat64() {
    echo -e "${YELLOW}Disabling IPv6 port forwarding...${NC}"

    # Stop tayga
    pkill tayga 2>/dev/null || true

    # Remove tayga interface
    ip link del nat64 2>/dev/null || true

    # Remove routes
    ip route del $NAT64_PREFIX 2>/dev/null || true

    echo -e "${GREEN}✓ IPv6 port forwarding disabled${NC}"
}

show_status() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}IPv6 Port Forwarding Status${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    # Check IPv6 address
    echo -e "${YELLOW}Gateway IPv6 Address:${NC}"
    ip -6 addr show $WAN_INTERFACE | grep 'inet6' | grep -v 'fe80' || echo "  (no global IPv6 address)"
    echo ""

    # Check IPv6 forwarding
    echo -e "${YELLOW}IPv6 Forwarding:${NC}"
    if [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" = "1" ]; then
        echo -e "  ${GREEN}Enabled${NC}"
    else
        echo -e "  ${RED}Disabled${NC}"
    fi
    echo ""

    # Check Tayga
    echo -e "${YELLOW}NAT64 (Tayga):${NC}"
    if pgrep tayga >/dev/null 2>&1; then
        echo -e "  ${GREEN}Running${NC}"
        ip addr show nat64 2>/dev/null || echo "  (interface not found)"
    else
        echo -e "  ${RED}Not running${NC}"
    fi
    echo ""

    # Check ip6tables
    echo -e "${YELLOW}IPv6 Firewall Rules:${NC}"
    ip6tables -L FORWARD -n | grep -E "eth0|eth1" || echo "  (no forwarding rules)"
    echo ""
}

# Main
case "$1" in
    enable)
        shift
        enable_nat64 "$@"
        ;;
    disable)
        disable_nat64
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
