#!/bin/sh
#
# Port Forwarding Helper Script
# Forwards ports from gateway's WAN interface to devices on LAN
#
# Usage:
#   ./setup-port-forwarding.sh add <wan_port> <device_ip> <device_port>
#   ./setup-port-forwarding.sh remove <wan_port> <device_ip> <device_port>
#   ./setup-port-forwarding.sh list
#   ./setup-port-forwarding.sh quick-device <device_ip>
#
# Examples:
#   ./setup-port-forwarding.sh add 8080 192.168.1.100 80       # HTTP
#   ./setup-port-forwarding.sh add 2323 192.168.1.100 23       # Telnet
#   ./setup-port-forwarding.sh quick-device 192.168.1.100      # Common ports
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WAN_INTERFACE="eth0"
LAN_INTERFACE="eth1"

show_help() {
    echo "Port Forwarding Helper for IPv4↔IPv6 Gateway"
    echo ""
    echo "Usage:"
    echo "  $0 add <wan_port> <device_ip> <device_port>     Add port forward"
    echo "  $0 remove <wan_port> <device_ip> <device_port>  Remove port forward"
    echo "  $0 list                                          List active forwards"
    echo "  $0 quick-device <device_ip>                     Forward common ports (80,23,443,22)"
    echo ""
    echo "Examples:"
    echo "  $0 add 8080 192.168.1.100 80        # Gateway:8080 → Device:80 (HTTP)"
    echo "  $0 add 2323 192.168.1.100 23        # Gateway:2323 → Device:23 (Telnet)"
    echo "  $0 add 8443 192.168.1.100 443       # Gateway:8443 → Device:443 (HTTPS)"
    echo "  $0 quick-device 192.168.1.100       # Auto-forward all common ports"
    echo ""
    echo "After adding forwards, access services at:"
    echo "  http://192.168.1.1:8080             # From LAN"
    echo "  http://<gateway-wan-ip>:8080        # From WAN (if gateway has WAN IP)"
    echo ""
}

add_forward() {
    WAN_PORT=$1
    DEVICE_IP=$2
    DEVICE_PORT=$3

    if [ -z "$WAN_PORT" ] || [ -z "$DEVICE_IP" ] || [ -z "$DEVICE_PORT" ]; then
        echo -e "${RED}Error: Missing arguments${NC}"
        echo "Usage: $0 add <wan_port> <device_ip> <device_port>"
        exit 1
    fi

    # Validate port numbers (1-65535)
    if ! echo "$WAN_PORT" | grep -qE '^[0-9]+$' || [ "$WAN_PORT" -lt 1 ] || [ "$WAN_PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid WAN port number (must be 1-65535)${NC}"
        exit 1
    fi

    if ! echo "$DEVICE_PORT" | grep -qE '^[0-9]+$' || [ "$DEVICE_PORT" -lt 1 ] || [ "$DEVICE_PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid device port number (must be 1-65535)${NC}"
        exit 1
    fi

    # Validate IP address format (basic IPv4 validation)
    if ! echo "$DEVICE_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo -e "${RED}Error: Invalid IP address format${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Adding port forward: WAN:$WAN_PORT → $DEVICE_IP:$DEVICE_PORT${NC}"

    # DNAT rule: Redirect incoming traffic on WAN_PORT to device
    iptables -t nat -A PREROUTING -i "$WAN_INTERFACE" -p tcp --dport "$WAN_PORT" \
        -j DNAT --to-destination "$DEVICE_IP:$DEVICE_PORT"

    # Allow forwarding to the device
    iptables -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" \
        -p tcp -d "$DEVICE_IP" --dport "$DEVICE_PORT" -j ACCEPT

    # Allow return traffic
    iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" \
        -p tcp -s "$DEVICE_IP" --sport "$DEVICE_PORT" -j ACCEPT

    # Also forward from gateway itself (for LAN access via gateway IP)
    iptables -t nat -A OUTPUT -p tcp --dport "$WAN_PORT" \
        -j DNAT --to-destination "$DEVICE_IP:$DEVICE_PORT"

    echo -e "${GREEN}✓ Port forward added${NC}"
    echo -e "${BLUE}Access via:${NC}"
    echo "  - From LAN: http://192.168.1.1:$WAN_PORT"
    echo "  - From WAN: http://<gateway-wan-ip>:$WAN_PORT"
    echo ""
}

remove_forward() {
    WAN_PORT=$1
    DEVICE_IP=$2
    DEVICE_PORT=$3

    if [ -z "$WAN_PORT" ] || [ -z "$DEVICE_IP" ] || [ -z "$DEVICE_PORT" ]; then
        echo -e "${RED}Error: Missing arguments${NC}"
        echo "Usage: $0 remove <wan_port> <device_ip> <device_port>"
        exit 1
    fi

    # Validate port numbers (1-65535)
    if ! echo "$WAN_PORT" | grep -qE '^[0-9]+$' || [ "$WAN_PORT" -lt 1 ] || [ "$WAN_PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid WAN port number (must be 1-65535)${NC}"
        exit 1
    fi

    if ! echo "$DEVICE_PORT" | grep -qE '^[0-9]+$' || [ "$DEVICE_PORT" -lt 1 ] || [ "$DEVICE_PORT" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid device port number (must be 1-65535)${NC}"
        exit 1
    fi

    # Validate IP address format (basic IPv4 validation)
    if ! echo "$DEVICE_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo -e "${RED}Error: Invalid IP address format${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Removing port forward: WAN:$WAN_PORT → $DEVICE_IP:$DEVICE_PORT${NC}"

    # Remove DNAT rules
    iptables -t nat -D PREROUTING -i "$WAN_INTERFACE" -p tcp --dport "$WAN_PORT" \
        -j DNAT --to-destination "$DEVICE_IP:$DEVICE_PORT" 2>/dev/null || echo "PREROUTING rule not found"

    iptables -t nat -D OUTPUT -p tcp --dport "$WAN_PORT" \
        -j DNAT --to-destination "$DEVICE_IP:$DEVICE_PORT" 2>/dev/null || echo "OUTPUT rule not found"

    # Remove FORWARD rules
    iptables -D FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" \
        -p tcp -d "$DEVICE_IP" --dport "$DEVICE_PORT" -j ACCEPT 2>/dev/null || echo "FORWARD rule not found"

    iptables -D FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" \
        -p tcp -s "$DEVICE_IP" --sport "$DEVICE_PORT" -j ACCEPT 2>/dev/null || echo "Return FORWARD rule not found"

    echo -e "${GREEN}✓ Port forward removed${NC}"
}

list_forwards() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Current Port Forwards${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}NAT PREROUTING (WAN → LAN):${NC}"
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep DNAT || echo "  (none)"
    echo ""
    echo -e "${YELLOW}FORWARD Rules:${NC}"
    iptables -L FORWARD -n -v --line-numbers | grep -E "192.168.1\." || echo "  (none)"
    echo ""
}

quick_device() {
    DEVICE_IP=$1

    if [ -z "$DEVICE_IP" ]; then
        echo -e "${RED}Error: Device IP required${NC}"
        echo "Usage: $0 quick-device <device_ip>"
        exit 1
    fi

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Quick Setup for Device: $DEVICE_IP${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "This will forward common ports:"
    echo "  8080 → $DEVICE_IP:80   (HTTP)"
    echo "  2323 → $DEVICE_IP:23   (Telnet)"
    echo "  8443 → $DEVICE_IP:443  (HTTPS)"
    echo "  2222 → $DEVICE_IP:22   (SSH)"
    echo ""
    read -p "Continue? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi

    echo ""
    add_forward 8080 $DEVICE_IP 80
    add_forward 2323 $DEVICE_IP 23
    add_forward 8443 $DEVICE_IP 443 2>/dev/null || echo -e "${YELLOW}⚠ HTTPS forward may not be needed${NC}"
    add_forward 2222 $DEVICE_IP 22 2>/dev/null || echo -e "${YELLOW}⚠ SSH forward may not be needed${NC}"

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Quick Setup Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Access device services:${NC}"
    echo "  HTTP:   http://192.168.1.1:8080"
    echo "  Telnet: telnet 192.168.1.1 2323"
    echo ""
}

# Main
case "$1" in
    add)
        shift
        add_forward "$@"
        ;;
    remove)
        shift
        remove_forward "$@"
        ;;
    list)
        list_forwards
        ;;
    quick-device)
        shift
        quick_device "$@"
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
