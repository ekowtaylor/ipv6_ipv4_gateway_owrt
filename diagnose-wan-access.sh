#!/bin/sh
#
# DIAGNOSE WAN ACCESS - Why can't I curl/telnet the router?
# Helps understand what's accessible and what's blocked
#

echo "=========================================="
echo "WAN ACCESS DIAGNOSTICS"
echo "=========================================="
echo ""

# Get WAN IP
WAN_IP=$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')
echo "Router WAN IP: ${WAN_IP:-NOT FOUND}"
echo ""

# Check what's listening on the router
echo "Services listening on router:"
echo "------------------------------"
netstat -tuln 2>/dev/null | grep "LISTEN" | grep -E ":(80|443|22|23|8080|2323)" || echo "(No common services found)"
echo ""

# Check firewall rules
echo "Firewall WAN zone configuration:"
echo "------------------------------"
uci show firewall | grep "@zone\[1\]" | grep -E "(name|input|output|forward)"
echo ""

# Check if there are any port forwards
echo "Active port forwarding rules (iptables):"
echo "------------------------------"
iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -E "(tcp|udp)" || echo "(No port forwards found)"
echo ""

# Check gateway status
echo "Gateway device status:"
echo "------------------------------"
if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    cat /etc/ipv4-ipv6-gateway/device.json | grep -E "(mac_address|lan_ipv4|wan_ipv4)" | head -3
    echo ""

    # Extract device IPs
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv4"' | cut -d'"' -f4)

    if [ -n "$DEVICE_WAN_IP" ] && [ "$DEVICE_WAN_IP" != "null" ]; then
        echo "Device is configured with WAN IP: $DEVICE_WAN_IP"
        echo ""
        echo "Port forwards to device (should work from upstream):"
        echo "  curl http://${DEVICE_WAN_IP}:8080    → Device HTTP (port 80)"
        echo "  telnet ${DEVICE_WAN_IP} 2323         → Device Telnet (port 23)"
        echo "  ssh -p 2222 user@${DEVICE_WAN_IP}    → Device SSH (port 22)"
        echo ""
    fi
else
    echo "No device configured yet"
fi
echo ""

echo "=========================================="
echo "UNDERSTANDING WAN ACCESS"
echo "=========================================="
echo ""
echo "ROUTER vs DEVICE Access:"
echo "------------------------------"
echo ""
echo "1. ROUTER WAN IP (${WAN_IP:-N/A}):"
echo "   ✅ ping ${WAN_IP:-<wan-ip>}               (ICMP allowed)"
echo "   ❌ curl http://${WAN_IP:-<wan-ip>}        (HTTP blocked - security!)"
echo "   ❌ telnet ${WAN_IP:-<wan-ip>}             (Telnet blocked - security!)"
echo "   ❌ Most TCP ports blocked by firewall"
echo ""
echo "   Why? The firewall blocks incoming TCP to protect the router."
echo "   This is CORRECT security behavior!"
echo ""

if [ -n "$DEVICE_WAN_IP" ] && [ "$DEVICE_WAN_IP" != "null" ]; then
    echo "2. DEVICE WAN IP (${DEVICE_WAN_IP}):"
    echo "   ✅ curl http://${DEVICE_WAN_IP}:8080   (Port forward works!)"
    echo "   ✅ telnet ${DEVICE_WAN_IP} 2323        (Port forward works!)"
    echo "   ✅ ssh -p 2222 user@${DEVICE_WAN_IP}   (Port forward works!)"
    echo ""
    echo "   These work because of port forwarding rules!"
fi
echo ""

echo "=========================================="
echo "SOLUTIONS"
echo "=========================================="
echo ""
echo "What are you trying to access?"
echo ""
echo "A) Access ROUTER from upstream network:"
echo "   - SSH to router: Need to open port 22"
echo "   - LuCI web: Need to open port 80/443"
echo "   - Run: sh diagnose-wan-access.sh --open-router-ports"
echo ""
echo "B) Access DEVICE via port forwards:"
echo "   - Already works! Use device's WAN IP"
echo "   - curl http://${DEVICE_WAN_IP:-<device-ip>}:8080"
echo "   - telnet ${DEVICE_WAN_IP:-<device-ip>} 2323"
echo ""
echo "C) Access router from LAN side:"
echo "   - ssh root@192.168.1.1 (always works)"
echo "   - http://192.168.1.1 (LuCI web interface)"
echo ""

# Check if user wants to open router ports
if [ "$1" = "--open-router-ports" ]; then
    echo ""
    echo "=========================================="
    echo "OPENING ROUTER PORTS (SSH + LuCI)"
    echo "=========================================="
    echo ""

    echo "⚠ WARNING: This opens the router to upstream network!"
    echo "Only do this if upstream network is trusted (e.g., home LAN)"
    echo ""
    read -p "Continue? (yes/no): " CONFIRM

    if [ "$CONFIRM" = "yes" ]; then
        echo ""
        echo "Adding firewall rules for SSH (22) and HTTP (80)..."

        # Add rule for SSH
        uci add firewall rule
        uci set firewall.@rule[-1].name='Allow-WAN-SSH'
        uci set firewall.@rule[-1].src='wan'
        uci set firewall.@rule[-1].proto='tcp'
        uci set firewall.@rule[-1].dest_port='22'
        uci set firewall.@rule[-1].target='ACCEPT'

        # Add rule for HTTP (LuCI)
        uci add firewall rule
        uci set firewall.@rule[-1].name='Allow-WAN-HTTP'
        uci set firewall.@rule[-1].src='wan'
        uci set firewall.@rule[-1].proto='tcp'
        uci set firewall.@rule[-1].dest_port='80'
        uci set firewall.@rule[-1].target='ACCEPT'

        uci commit firewall
        /etc/init.d/firewall restart

        echo "✓ Router ports opened!"
        echo ""
        echo "You can now:"
        echo "  ssh root@${WAN_IP}        (SSH to router)"
        echo "  http://${WAN_IP}          (LuCI web interface)"
        echo ""
    else
        echo "Cancelled"
    fi
fi
