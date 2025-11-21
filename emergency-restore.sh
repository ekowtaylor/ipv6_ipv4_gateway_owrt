#!/bin/sh
#
# EMERGENCY NETWORK RESTORE
# Use this when gateway breaks network and uninstall fails
#

echo "═══════════════════════════════════════════════════════════"
echo "EMERGENCY NETWORK RESTORE"
echo "═══════════════════════════════════════════════════════════"
echo ""
date
echo ""

# STEP 1: Kill all gateway processes
echo "1. Killing gateway processes..."
killall python3 2>/dev/null || true
killall socat 2>/dev/null || true
echo "   ✓ Processes killed"
echo ""

# STEP 2: Flush ALL iptables rules
echo "2. Flushing ALL iptables rules..."
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -X 2>/dev/null || true
ip6tables -F 2>/dev/null || true
ip6tables -t nat -F 2>/dev/null || true
ip6tables -t mangle -F 2>/dev/null || true
ip6tables -X 2>/dev/null || true
echo "   ✓ iptables flushed"
echo ""

# STEP 3: Set default ACCEPT policies
echo "3. Setting permissive firewall policies..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
ip6tables -P INPUT ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD ACCEPT
echo "   ✓ Firewall policies set to ACCEPT"
echo ""

# STEP 4: Restore original MAC if saved
echo "4. Restoring original MAC..."
if [ -f /etc/ipv4-ipv6-gateway/original_wan_mac.txt ]; then
    ORIGINAL_MAC=$(cat /etc/ipv4-ipv6-gateway/original_wan_mac.txt)
    echo "   Found saved MAC: $ORIGINAL_MAC"

    # Remove from UCI
    uci delete network.wan.macaddr 2>/dev/null || true
    uci commit network 2>/dev/null || true

    # Set manually
    ip link set eth0 down 2>/dev/null || true
    ip link set eth0 address "$ORIGINAL_MAC" 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true

    echo "   ✓ MAC restored to: $ORIGINAL_MAC"
else
    echo "   ⚠ No saved MAC found - leaving current MAC"
fi
echo ""

# STEP 5: Reset network to factory defaults
echo "5. Restoring factory network configuration..."

# Create minimal working network config
cat > /etc/config/network << 'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

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
EOF

echo "   ✓ Network config restored"
echo ""

# STEP 6: Reset firewall to factory defaults
echo "6. Restoring factory firewall configuration..."

cat > /etc/config/firewall << 'EOF'
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	list network 'lan'

config zone
	option name 'wan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	list network 'wan'
	list network 'wan6'

config forwarding
	option src 'lan'
	option dest 'wan'
EOF

echo "   ✓ Firewall config restored (WAN input=ACCEPT for debugging)"
echo ""

# STEP 7: Reset DHCP
echo "7. Restoring DHCP configuration..."

uci delete dhcp.lan 2>/dev/null || true
uci set dhcp.lan=dhcp
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.start='100'
uci set dhcp.lan.limit='150'
uci set dhcp.lan.leasetime='12h'
uci commit dhcp

echo "   ✓ DHCP config restored"
echo ""

# STEP 8: Enable IPv6
echo "8. Enabling IPv6..."
echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 0 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6
echo "   ✓ IPv6 enabled"
echo ""

# STEP 9: Disable IP forwarding (normal router mode)
echo "9. Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
echo "   ✓ IP forwarding disabled"
echo ""

# STEP 10: Restart all network services
echo "10. Restarting network services..."
echo "    This will take about 15 seconds..."

/etc/init.d/firewall stop 2>/dev/null || true
sleep 1

/etc/init.d/dnsmasq stop 2>/dev/null || true
sleep 1

/etc/init.d/network restart
sleep 5

/etc/init.d/dnsmasq start
sleep 3

/etc/init.d/firewall start
sleep 3

echo "    ✓ All services restarted"
echo ""

# STEP 11: Check connectivity
echo "11. Checking connectivity..."

# Wait for DHCP
echo "    Waiting 5 seconds for DHCP..."
sleep 5

# Check if eth0 has IP
WAN_IP=$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')
if [ -n "$WAN_IP" ]; then
    echo "    ✓ WAN IPv4: $WAN_IP"
else
    echo "    ✗ No WAN IPv4 address!"
    echo "      Trying manual DHCP..."
    udhcpc -i eth0 -n -q
    sleep 3
    WAN_IP=$(ip -4 addr show eth0 | grep -o 'inet [0-9.]*' | awk '{print $2}')
    if [ -n "$WAN_IP" ]; then
        echo "      ✓ Got IP: $WAN_IP"
    else
        echo "      ✗ Still no IP - check cable!"
    fi
fi

# Check if we can ping upstream
echo "    Testing upstream connectivity..."
if ping -c 2 -W 2 192.168.8.1 >/dev/null 2>&1; then
    echo "    ✓ Can ping upstream router (192.168.8.1)"
else
    echo "    ✗ Cannot ping upstream router"
fi

# Check internet
echo "    Testing internet connectivity..."
if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "    ✓ Internet connectivity works!"
else
    echo "    ✗ No internet connectivity"
fi

echo ""

# STEP 12: Show current status
echo "12. Current Network Status"
echo "─────────────────────────────────────────────────────────"
echo ""

echo "Interfaces:"
ip -4 addr show eth0 | grep inet
ip -4 addr show eth1 | grep inet
echo ""

echo "MAC Addresses:"
echo "  eth0: $(ip link show eth0 | grep ether | awk '{print $2}')"
echo "  eth1: $(ip link show eth1 | grep ether | awk '{print $2}')"
echo ""

echo "Default Route:"
ip route show default
echo ""

echo "Firewall Status:"
/etc/init.d/firewall status 2>&1 | head -3
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "EMERGENCY RESTORE COMPLETE"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ -n "$WAN_IP" ]; then
    echo "✓ Network connectivity restored!"
    echo ""
    echo "You should now be able to:"
    echo "  - Ping the router on WAN: $WAN_IP"
    echo "  - SSH to the router: ssh root@$WAN_IP"
    echo "  - Access LuCI: http://$WAN_IP or http://192.168.1.1"
    echo ""
    echo "Next steps:"
    echo "  1. Verify connectivity from upstream network"
    echo "  2. If gateway broke something permanently, reboot router"
    echo "  3. Before reinstalling gateway, review what went wrong"
else
    echo "⚠ WARNING: Could not restore WAN connectivity!"
    echo ""
    echo "Possible issues:"
    echo "  - WAN cable unplugged"
    echo "  - Upstream router not responding"
    echo "  - eth0 hardware issue"
    echo ""
    echo "Try:"
    echo "  1. Check WAN cable is plugged in"
    echo "  2. Reboot router: reboot"
    echo "  3. Check upstream router (192.168.8.1)"
fi

echo ""
