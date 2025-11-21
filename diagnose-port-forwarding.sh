#!/bin/sh
#
# UNIFIED PORT FORWARDING DIAGNOSTIC
# Checks both IPv4 NAT port forwarding AND IPv6 proxy functionality
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "UNIFIED PORT FORWARDING DIAGNOSTIC"
echo "IPv4 NAT + IPv6 Proxy"
echo "=========================================="
echo ""

# Get device info
DEVICE_LAN_IP=""
DEVICE_WAN_IPV4=""
DEVICE_WAN_IPV6=""
DEVICE_MAC=""

if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IPV4=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IPV6=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv6"' | cut -d'"' -f4)
    DEVICE_MAC=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"mac_address"' | cut -d'"' -f4)
fi

echo -e "${BLUE}Device Information:${NC}"
echo "------------------------------"
echo "Device MAC:     ${DEVICE_MAC:-NOT FOUND}"
echo "Device LAN IP:  ${DEVICE_LAN_IP:-NOT FOUND}"
echo "Device WAN IPv4: ${DEVICE_WAN_IPV4:-NOT FOUND}"
echo "Device WAN IPv6: ${DEVICE_WAN_IPV6:-NOT FOUND}"
echo ""

# Check if device is configured
if [ -z "$DEVICE_LAN_IP" ]; then
    echo -e "${RED}❌ ERROR: No device configured!${NC}"
    echo "   Port forwarding cannot work without a device"
    exit 1
fi

echo "=========================================="
echo "PART 1: IPv4 PORT FORWARDING (NAT)"
echo "=========================================="
echo ""

if [ -z "$DEVICE_WAN_IPV4" ]; then
    echo -e "${YELLOW}⚠ Device has NO IPv4 address${NC}"
    echo "  IPv4 port forwarding will not work"
    echo ""
else
    echo -e "${GREEN}✓ Device has IPv4: $DEVICE_WAN_IPV4${NC}"
    echo ""

    echo -e "${BLUE}1. Firewall INPUT Rules (traffic TO router):${NC}"
    echo "------------------------------"
    uci show firewall | grep -E "(Allow-Device|Allow-Ping)" | grep "rule\[" | head -10
    echo ""

    echo -e "${BLUE}2. Firewall FORWARD Rules (traffic THROUGH router):${NC}"
    echo "------------------------------"
    uci show firewall | grep "forwarding" || echo "  ⚠ No forwarding rules found!"
    echo ""

    echo -e "${BLUE}3. Firewall WAN Zone Configuration:${NC}"
    echo "------------------------------"
    uci show firewall | grep "@zone\[1\]" | grep -E "(name|input|forward)"
    echo ""

    WAN_FORWARD=$(uci get firewall.@zone[1].forward 2>/dev/null)
    echo "WAN zone forward policy: ${WAN_FORWARD:-UNKNOWN}"
    if [ "$WAN_FORWARD" = "REJECT" ]; then
        echo -e "${YELLOW}  ⚠ WARNING: WAN forward is REJECT - this blocks forwarding!${NC}"
        echo "  Port forwards will NOT work with this setting"
    fi
    echo ""

    echo -e "${BLUE}4. iptables NAT Rules (DNAT for port forwarding):${NC}"
    echo "------------------------------"
    echo "Checking for common port forwards (8080, 5000, 2323, 2222)..."
    DNAT_RULES=$(iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "(8080|5000|2323|2222)")
    if [ -n "$DNAT_RULES" ]; then
        echo "$DNAT_RULES"
    else
        echo -e "${RED}  ✗ No DNAT rules found!${NC}"
    fi
    echo ""

    echo -e "${BLUE}5. iptables MASQUERADE Rule (return traffic):${NC}"
    echo "------------------------------"
    echo "Checking for MASQUERADE rule (required for return traffic)..."
    MASQ_RULE=$(iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE | grep 192.168.1)
    if [ -n "$MASQ_RULE" ]; then
        echo -e "${GREEN}✓ MASQUERADE rule found:${NC}"
        echo "$MASQ_RULE"
    else
        echo -e "${RED}✗ MASQUERADE rule MISSING!${NC}"
        echo "  Device replies will use wrong source IP"
    fi
    echo ""

    echo -e "${BLUE}6. iptables FORWARD Rules (allow forwarded traffic):${NC}"
    echo "------------------------------"
    FORWARD_RULES=$(iptables -L FORWARD -n -v --line-numbers | grep "$DEVICE_LAN_IP")
    if [ -n "$FORWARD_RULES" ]; then
        echo "$FORWARD_RULES"
    else
        echo -e "${RED}  ✗ No FORWARD rules for device!${NC}"
    fi
    echo ""

    echo -e "${BLUE}7. Test Port Listening on Device:${NC}"
    echo "------------------------------"
    echo "Checking if device has services listening..."

    # Test common ports
    for port in 80 5000 23 22; do
        if nc -z -w 2 "$DEVICE_LAN_IP" "$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓ Port $port is OPEN on device${NC}"
        else
            echo -e "  ${YELLOW}✗ Port $port is CLOSED on device${NC}"
        fi
    done
    echo ""
fi

echo "=========================================="
echo "PART 2: IPv6 PROXY (IPv6 → IPv4)"
echo "=========================================="
echo ""

if [ -z "$DEVICE_WAN_IPV6" ]; then
    echo -e "${YELLOW}⚠ Device has NO IPv6 address${NC}"
    echo "  IPv6 proxy will not work"
    echo ""
else
    echo -e "${GREEN}✓ Device has IPv6: $DEVICE_WAN_IPV6${NC}"
    echo ""

    echo -e "${BLUE}1. socat Proxy Processes:${NC}"
    echo "------------------------------"
    SOCAT_COUNT=$(ps aux | grep -c "[s]ocat.*TCP6-LISTEN")
    if [ "$SOCAT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Found $SOCAT_COUNT socat process(es)${NC}"
        echo ""
        ps aux | grep "[s]ocat" | grep -v grep
    else
        echo -e "${RED}❌ NO socat processes running!${NC}"
        echo "   IPv6→IPv4 proxy is NOT working"
    fi
    echo ""

    echo -e "${BLUE}2. ip6tables NAT Support:${NC}"
    echo "------------------------------"
    if ip6tables -t nat -L >/dev/null 2>&1; then
        echo -e "${GREEN}✓ ip6tables NAT is available${NC}"
        echo ""
        echo "Current ip6tables NAT rules (POSTROUTING):"
        ip6tables -t nat -L POSTROUTING -n -v | head -15
    else
        echo -e "${RED}❌ ip6tables NAT is NOT available!${NC}"
        echo "   This is required for IPv6→IPv4 proxy"
        echo ""
        echo "Install with:"
        echo "  opkg update"
        echo "  opkg install kmod-ipt-nat6 ip6tables-mod-nat"
    fi
    echo ""

    echo -e "${BLUE}3. ip6tables SNAT Rules (return traffic):${NC}"
    echo "------------------------------"
    if ip6tables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -q "$DEVICE_LAN_IP"; then
        echo -e "${GREEN}✓ SNAT rules found for device${NC}"
        ip6tables -t nat -L POSTROUTING -n -v | grep "$DEVICE_LAN_IP"
    else
        echo -e "${YELLOW}⚠ No SNAT rules found for device${NC}"
        echo "  IPv6 proxy may not work correctly"
    fi
    echo ""

    echo -e "${BLUE}4. IPv6 Proxy Listening Ports:${NC}"
    echo "------------------------------"
    echo "Expected ports: 8080, 2323, 5000"
    echo ""

    if command -v netstat >/dev/null 2>&1; then
        IPV6_PORTS=$(netstat -tuln | grep -E ":::8080|:::2323|:::5000")
        if [ -n "$IPV6_PORTS" ]; then
            echo -e "${GREEN}✓ IPv6 ports listening:${NC}"
            echo "$IPV6_PORTS"
        else
            echo -e "${RED}❌ No IPv6 ports listening!${NC}"
        fi
    elif command -v ss >/dev/null 2>&1; then
        IPV6_PORTS=$(ss -tuln | grep -E "::]:8080|::]:2323|::]:5000")
        if [ -n "$IPV6_PORTS" ]; then
            echo -e "${GREEN}✓ IPv6 ports listening:${NC}"
            echo "$IPV6_PORTS"
        else
            echo -e "${RED}❌ No IPv6 ports listening!${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ netstat/ss not available - cannot check listening ports${NC}"
    fi
    echo ""

    echo -e "${BLUE}5. Gateway Logs (IPv6 proxy):${NC}"
    echo "------------------------------"
    if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
        echo "Recent IPv6 proxy log entries:"
        grep -i "ipv6 proxy\|ipv6→ipv4\|socat" /var/log/ipv4-ipv6-gateway.log | tail -10
        echo ""

        if grep -q "IPv6 NAT support" /var/log/ipv4-ipv6-gateway.log; then
            echo -e "${YELLOW}⚠ Warning found in logs about IPv6 NAT support${NC}"
        fi
    else
        echo "Log file not found!"
    fi
    echo ""
fi

echo "=========================================="
echo "DIAGNOSIS SUMMARY"
echo "=========================================="
echo ""

# Count issues
ISSUES=0

# IPv4 checks
if [ -n "$DEVICE_WAN_IPV4" ]; then
    HAS_DNAT=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c "8080\|5000\|2323")
    HAS_FORWARD=$(iptables -L FORWARD -n 2>/dev/null | grep -c "$DEVICE_LAN_IP")
    HAS_MASQ=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep MASQUERADE | grep -c 192.168.1)

    echo -e "${BLUE}IPv4 Status:${NC}"

    if [ "$HAS_DNAT" -eq 0 ]; then
        echo -e "${RED}❌ NO DNAT rules found!${NC}"
        echo "   Gateway service may not be running or device not configured"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ DNAT rules exist${NC}"
    fi

    if [ "$HAS_FORWARD" -eq 0 ]; then
        echo -e "${RED}❌ NO FORWARD rules found for device!${NC}"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ FORWARD rules exist${NC}"
    fi

    if [ "$HAS_MASQ" -eq 0 ]; then
        echo -e "${RED}❌ NO MASQUERADE rule found!${NC}"
        echo "   Return traffic will fail"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ MASQUERADE rule exists${NC}"
    fi

    WAN_FORWARD=$(uci get firewall.@zone[1].forward 2>/dev/null)
    if [ "$WAN_FORWARD" = "REJECT" ]; then
        echo -e "${RED}❌ WAN zone forward policy is REJECT!${NC}"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ WAN zone allows forwarding${NC}"
    fi
else
    echo -e "${YELLOW}⊘ IPv4: Not configured${NC}"
fi

echo ""

# IPv6 checks
if [ -n "$DEVICE_WAN_IPV6" ]; then
    HAS_SOCAT=$(ps aux | grep -c "[s]ocat.*TCP6-LISTEN")
    HAS_NAT6=$(ip6tables -t nat -L >/dev/null 2>&1 && echo "yes" || echo "no")
    HAS_SNAT=$(ip6tables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -c "$DEVICE_LAN_IP")

    echo -e "${BLUE}IPv6 Status:${NC}"

    if [ "$HAS_NAT6" = "no" ]; then
        echo -e "${RED}❌ IPv6 NAT support NOT available${NC}"
        echo "   Install: opkg install kmod-ipt-nat6 ip6tables-mod-nat"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ IPv6 NAT support available${NC}"
    fi

    if [ "$HAS_SOCAT" -eq 0 ]; then
        echo -e "${RED}❌ NO socat processes running!${NC}"
        echo "   IPv6 proxy is not active"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}✓ socat processes running ($HAS_SOCAT)${NC}"
    fi

    if [ "$HAS_SNAT" -eq 0 ]; then
        echo -e "${YELLOW}⚠ No SNAT rules for device${NC}"
        echo "   IPv6 proxy may have return traffic issues"
    else
        echo -e "${GREEN}✓ SNAT rules exist ($HAS_SNAT)${NC}"
    fi
else
    echo -e "${YELLOW}⊘ IPv6: Not configured${NC}"
fi

echo ""

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ No obvious issues detected!${NC}"
    echo ""
    echo "If port forwarding still doesn't work:"
    echo "  - Check firewall on the device itself"
    echo "  - Verify device services are listening on correct ports"
    echo "  - Check upstream firewall/NAT"
else
    echo -e "${RED}Found $ISSUES issue(s) - see above for details${NC}"
fi

echo ""
echo "=========================================="
echo "QUICK FIXES"
echo "=========================================="
echo ""

if [ -n "$DEVICE_WAN_IPV4" ] && [ "$HAS_DNAT" -eq 0 ]; then
    echo -e "${BLUE}IPv4 Port Forwarding Fix:${NC}"
    echo "  sh fix-port-forwarding.sh"
    echo ""
fi

if [ -n "$DEVICE_WAN_IPV6" ] && [ "$HAS_NAT6" = "no" ]; then
    echo -e "${BLUE}IPv6 NAT Support Install:${NC}"
    echo "  opkg update"
    echo "  opkg install kmod-ipt-nat6 ip6tables-mod-nat"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
fi

if [ "$HAS_SOCAT" -eq 0 ] && [ -n "$DEVICE_WAN_IPV6" ] && [ "$HAS_NAT6" = "yes" ]; then
    echo -e "${BLUE}Restart Gateway Service:${NC}"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
    echo ""
fi

echo "=========================================="
echo "TEST CONNECTIVITY"
echo "=========================================="
echo ""

if [ -n "$DEVICE_WAN_IPV4" ]; then
    echo -e "${BLUE}Test IPv4 Port Forwarding:${NC}"
    echo "  From external client:"
    echo "  curl http://$DEVICE_WAN_IPV4:8080"
    echo "  telnet $DEVICE_WAN_IPV4 2323"
    echo ""
fi

if [ -n "$DEVICE_WAN_IPV6" ]; then
    echo -e "${BLUE}Test IPv6 Proxy:${NC}"
    echo "  From external IPv6-enabled client:"
    echo "  curl 'http://[$DEVICE_WAN_IPV6]:8080'"
    echo "  curl 'http://[$DEVICE_WAN_IPV6]:5000'"
    echo "  telnet $DEVICE_WAN_IPV6 2323"
    echo ""
fi

echo "=========================================="
echo ""
