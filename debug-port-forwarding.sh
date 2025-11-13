#!/bin/sh
#
# Debug IPv4 Port Forwarding - Comprehensive diagnostics
# Checks everything related to IPv4 NAT port forwarding
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv4 Port Forwarding Debugger${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}⚠ Warning: Not running as root. Some checks may fail.${NC}"
    echo ""
fi

# Get device state
STATE_FILE="/etc/ipv4-ipv6-gateway/device.json"

if [ ! -f "$STATE_FILE" ]; then
    echo -e "${RED}✗ Device state file not found: $STATE_FILE${NC}"
    echo -e "${YELLOW}  Gateway service may not be running or no device configured${NC}"
    echo ""
    echo -e "${YELLOW}Quick checks:${NC}"
    echo "  1. Is service running? ps | grep ipv4_ipv6_gateway"
    echo "  2. Check logs: tail -50 /var/log/ipv4-ipv6-gateway.log"
    exit 1
fi

# Parse device state
echo -e "${YELLOW}1. Device State${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "$STATE_FILE"
else
    cat "$STATE_FILE"
fi
echo ""

# Extract key info
MAC=$(cat "$STATE_FILE" | grep '"mac_address"' | cut -d'"' -f4)
LAN_IP=$(cat "$STATE_FILE" | grep '"lan_ipv4"' | cut -d'"' -f4)
WAN_IPV4=$(cat "$STATE_FILE" | grep '"wan_ipv4"' | cut -d'"' -f4)
STATUS=$(cat "$STATE_FILE" | grep '"status"' | cut -d'"' -f4)

if [ -z "$LAN_IP" ] || [ "$LAN_IP" = "null" ]; then
    echo -e "${RED}✗ No LAN IP in device state!${NC}"
    exit 1
fi

if [ -z "$WAN_IPV4" ] || [ "$WAN_IPV4" = "null" ]; then
    echo -e "${RED}✗ No WAN IPv4 in device state!${NC}"
    echo -e "${YELLOW}  Device may not have obtained IPv4 via DHCP${NC}"
    echo -e "${YELLOW}  Port forwarding requires WAN IPv4${NC}"
    echo ""
fi

echo -e "${GREEN}Device Summary:${NC}"
echo "  MAC:      $MAC"
echo "  LAN IP:   $LAN_IP"
echo "  WAN IPv4: ${WAN_IPV4:-N/A}"
echo "  Status:   $STATUS"
echo ""

# Check WAN interface current IP
echo -e "${YELLOW}2. WAN Interface Status${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

WAN_IF="eth0"
CURRENT_WAN_IP=$(ip -4 addr show "$WAN_IF" 2>/dev/null | grep 'inet' | awk '{print $2}' | cut -d/ -f1)

if [ -n "$CURRENT_WAN_IP" ]; then
    echo -e "${GREEN}✓ WAN Interface ($WAN_IF) has IPv4: $CURRENT_WAN_IP${NC}"

    if [ "$CURRENT_WAN_IP" != "$WAN_IPV4" ]; then
        echo -e "${RED}✗ IP MISMATCH!${NC}"
        echo -e "${YELLOW}  State file WAN IP: $WAN_IPV4${NC}"
        echo -e "${YELLOW}  Current WAN IP:    $CURRENT_WAN_IP${NC}"
        echo -e "${RED}  Port forwarding rules will NOT work!${NC}"
        echo -e "${YELLOW}  Gateway needs to detect the WAN change and reconfigure${NC}"
        WAN_IPV4="$CURRENT_WAN_IP"  # Use current for testing
    else
        echo -e "${GREEN}✓ WAN IP matches state file${NC}"
    fi
else
    echo -e "${RED}✗ No IPv4 address on WAN interface!${NC}"
fi
echo ""

# Check LAN connectivity
echo -e "${YELLOW}3. LAN Connectivity (Gateway ↔ Device)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Ping test
echo -n "Ping test to $LAN_IP ... "
if ping -c 2 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Device is reachable${NC}"
else
    echo -e "${RED}✗ Device is NOT reachable!${NC}"
    echo -e "${YELLOW}  Device may be offline or disconnected${NC}"
fi

# Check ARP entry
echo -n "ARP entry for $LAN_IP ... "
ARP_ENTRY=$(ip neigh show "$LAN_IP" 2>/dev/null)
if [ -n "$ARP_ENTRY" ]; then
    echo -e "${GREEN}✓ Found${NC}"
    echo "  $ARP_ENTRY"
else
    echo -e "${RED}✗ Not in ARP table${NC}"
fi
echo ""

# Test web server on device
echo -e "${YELLOW}4. Device Web Server Test${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -n "Testing HTTP on $LAN_IP:80 ... "
if command -v nc >/dev/null 2>&1; then
    if nc -zv -w 3 "$LAN_IP" 80 2>&1 | grep -q succeeded; then
        echo -e "${GREEN}✓ Port 80 is OPEN${NC}"
    else
        echo -e "${RED}✗ Port 80 is CLOSED or filtered${NC}"
        echo -e "${YELLOW}  Device may not have a web server running${NC}"
    fi
else
    # Fallback to curl
    if curl -s --max-time 3 "http://$LAN_IP" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Web server responding${NC}"
    else
        echo -e "${RED}✗ No response from web server${NC}"
    fi
fi

echo -n "Attempting HTTP request ... "
HTTP_RESP=$(curl -s --max-time 3 -w "HTTP %{http_code}" "http://$LAN_IP" 2>/dev/null)
if [ -n "$HTTP_RESP" ]; then
    echo -e "${GREEN}✓ Got response: $HTTP_RESP${NC}"
else
    echo -e "${RED}✗ No HTTP response${NC}"
fi
echo ""

# Check NAT rules
echo -e "${YELLOW}5. IPv4 NAT Rules (Port Forwarding)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check PREROUTING (DNAT) rules
echo -e "${BLUE}DNAT Rules (PREROUTING chain):${NC}"
DNAT_RULES=$(iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -E "8080|2323|2222|8443|5900|3389")

if [ -n "$DNAT_RULES" ]; then
    echo -e "${GREEN}✓ Port forwarding rules found:${NC}"
    echo "$DNAT_RULES" | while IFS= read -r line; do
        echo "  $line"

        # Highlight if WAN IP doesn't match
        if echo "$line" | grep -q "$WAN_IPV4"; then
            echo -e "    ${GREEN}✓ Rule matches current WAN IP ($WAN_IPV4)${NC}"
        else
            RULE_IP=$(echo "$line" | awk '{print $8}')
            if [ -n "$RULE_IP" ] && [ "$RULE_IP" != "0.0.0.0/0" ]; then
                echo -e "    ${RED}✗ Rule has different IP: $RULE_IP (should be $WAN_IPV4)${NC}"
            fi
        fi
    done
else
    echo -e "${RED}✗ No port forwarding rules found!${NC}"
    echo -e "${YELLOW}  Expected rules for ports: 8080, 2323, 2222, 8443, 5900, 3389${NC}"
fi
echo ""

# Check FORWARD rules
echo -e "${BLUE}FORWARD Rules (for port forwarding traffic):${NC}"
FORWARD_RULES=$(iptables -L FORWARD -n -v 2>/dev/null | grep -E "$LAN_IP.*:80|$LAN_IP.*:23|$LAN_IP.*:22")

if [ -n "$FORWARD_RULES" ]; then
    echo -e "${GREEN}✓ FORWARD rules found:${NC}"
    echo "$FORWARD_RULES" | while IFS= read -r line; do
        echo "  $line"
    done
else
    echo -e "${RED}✗ No FORWARD rules found for $LAN_IP!${NC}"
    echo -e "${YELLOW}  Traffic may be blocked by firewall${NC}"
fi
echo ""

# Check MASQUERADE/SNAT
echo -e "${BLUE}NAT POSTROUTING (Masquerade/SNAT):${NC}"
MASQ_RULES=$(iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "MASQUERADE|SNAT")

if [ -n "$MASQ_RULES" ]; then
    echo -e "${GREEN}✓ Masquerade/SNAT rules found:${NC}"
    echo "$MASQ_RULES" | head -5 | while IFS= read -r line; do
        echo "  $line"
    done
else
    echo -e "${RED}✗ No MASQUERADE/SNAT rules!${NC}"
    echo -e "${YELLOW}  Return traffic may not work${NC}"
fi
echo ""

# Test actual port forwarding
echo -e "${YELLOW}6. Port Forwarding Live Test${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ -n "$WAN_IPV4" ] && [ "$WAN_IPV4" != "null" ]; then
    echo "Testing port forwards from gateway to device..."
    echo ""

    # Test port 8080 → 80
    echo -n "  8080 → 80 (HTTP): "
    if curl -s --max-time 3 "http://$WAN_IPV4:8080" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Working${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi

    # Test port 2323 → 23
    echo -n "  2323 → 23 (Telnet): "
    if nc -zv -w 2 "$WAN_IPV4" 2323 2>&1 | grep -q succeeded; then
        echo -e "${GREEN}✓ Port open${NC}"
    else
        echo -e "${RED}✗ Port closed${NC}"
    fi

    # Test port 2222 → 22
    echo -n "  2222 → 22 (SSH): "
    if nc -zv -w 2 "$WAN_IPV4" 2222 2>&1 | grep -q succeeded; then
        echo -e "${GREEN}✓ Port open${NC}"
    else
        echo -e "${RED}✗ Port closed${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No WAN IPv4 available for testing${NC}"
fi
echo ""

# Check conntrack
echo -e "${YELLOW}7. Connection Tracking${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ -f /proc/net/nf_conntrack ]; then
    echo -n "Active connections to $LAN_IP: "
    CONN_COUNT=$(cat /proc/net/nf_conntrack 2>/dev/null | grep "$LAN_IP" | wc -l)
    echo "$CONN_COUNT"

    if [ "$CONN_COUNT" -gt 0 ]; then
        echo -e "${BLUE}Recent connections:${NC}"
        cat /proc/net/nf_conntrack | grep "$LAN_IP" | head -5 | while IFS= read -r line; do
            echo "  $line"
        done
    fi
else
    echo -e "${YELLOW}Connection tracking not available${NC}"
fi
echo ""

# Check service logs
echo -e "${YELLOW}8. Recent Gateway Logs${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

LOG_FILE="/var/log/ipv4-ipv6-gateway.log"

if [ -f "$LOG_FILE" ]; then
    echo -e "${BLUE}Last 20 lines (filtered for port forwarding):${NC}"
    tail -50 "$LOG_FILE" | grep -iE "port|forward|dnat|8080|ipv4|error|warning" | tail -20
    echo ""

    echo -e "${BLUE}Configuration events:${NC}"
    tail -100 "$LOG_FILE" | grep -iE "configuring device|configured successfully|port forward" | tail -10
else
    echo -e "${RED}✗ Log file not found: $LOG_FILE${NC}"
fi
echo ""

# Summary and recommendations
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary & Recommendations${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

ISSUES=0

# Check 1: Device reachable
if ! ping -c 1 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    echo -e "${RED}✗ Device is not reachable on LAN${NC}"
    echo "  Action: Check if device is connected to eth1"
    ISSUES=$((ISSUES + 1))
fi

# Check 2: Web server running
if command -v nc >/dev/null 2>&1; then
    if ! nc -zv -w 2 "$LAN_IP" 80 2>&1 | grep -q succeeded; then
        echo -e "${RED}✗ Device port 80 is not accessible${NC}"
        echo "  Action: Start web server on device (port 80)"
        ISSUES=$((ISSUES + 1))
    fi
fi

# Check 3: WAN IP
if [ -z "$WAN_IPV4" ] || [ "$WAN_IPV4" = "null" ]; then
    echo -e "${RED}✗ No WAN IPv4 address${NC}"
    echo "  Action: Check DHCP on WAN interface (eth0)"
    ISSUES=$((ISSUES + 1))
fi

# Check 4: NAT rules
if [ -z "$DNAT_RULES" ]; then
    echo -e "${RED}✗ No port forwarding rules installed${NC}"
    echo "  Action: Check gateway logs, restart service"
    ISSUES=$((ISSUES + 1))
fi

# Check 5: IP mismatch
if [ -n "$CURRENT_WAN_IP" ] && [ -n "$WAN_IPV4" ] && [ "$CURRENT_WAN_IP" != "$WAN_IPV4" ]; then
    echo -e "${RED}✗ WAN IP mismatch (rules out of date)${NC}"
    echo "  Action: Wait for gateway to detect change or restart service"
    ISSUES=$((ISSUES + 1))
fi

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ No issues detected!${NC}"
    echo ""
    echo "Port forwarding should be working."
    echo "If you still can't connect from external, check:"
    echo "  1. External firewall/router settings"
    echo "  2. ISP blocking ports"
    echo "  3. Try from different network"
else
    echo -e "${YELLOW}Found $ISSUES potential issues (see above)${NC}"
    echo ""
    echo "Quick fixes to try:"
    echo "  1. Restart gateway: /etc/init.d/ipv4-ipv6-gateway restart"
    echo "  2. Check device: ping $LAN_IP && curl http://$LAN_IP"
    echo "  3. Check logs: tail -f /var/log/ipv4-ipv6-gateway.log"
fi
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Manual Testing Commands${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Test from gateway (internal):"
echo "  curl http://$LAN_IP"
if [ -n "$WAN_IPV4" ]; then
    echo "  curl http://$WAN_IPV4:8080"
fi
echo ""
echo "Test from external machine:"
if [ -n "$WAN_IPV4" ]; then
    echo "  curl http://$WAN_IPV4:8080"
    echo "  telnet $WAN_IPV4 2323"
    echo "  ssh -p 2222 user@$WAN_IPV4"
fi
echo ""

echo "View live connections:"
echo "  watch -n 1 'cat /proc/net/nf_conntrack | grep $LAN_IP'"
echo ""

echo "View live logs:"
echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
