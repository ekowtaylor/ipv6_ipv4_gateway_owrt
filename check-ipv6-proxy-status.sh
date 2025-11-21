#!/bin/sh
#
# CHECK IPv6 PROXY STATUS - Is IPv6→IPv4 proxying working?
#

echo "=========================================="
echo "IPv6 PROXY STATUS CHECK"
echo "=========================================="
echo ""

# Get device info
DEVICE_LAN_IP=""
DEVICE_WAN_IPV6=""

if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IPV6=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv6"' | cut -d'"' -f4)
fi

echo "Device Information:"
echo "------------------------------"
echo "LAN IPv4:  ${DEVICE_LAN_IP:-NOT FOUND}"
echo "WAN IPv6:  ${DEVICE_WAN_IPV6:-NOT FOUND}"
echo ""

# Check socat processes
echo "1. Checking socat processes:"
echo "------------------------------"
SOCAT_COUNT=$(ps aux | grep -c "[s]ocat.*TCP6-LISTEN")
if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo "✅ Found $SOCAT_COUNT socat processes"
    echo ""
    ps aux | grep "[s]ocat" | grep -v grep
else
    echo "❌ NO socat processes running!"
    echo "   IPv6→IPv4 proxy is NOT working"
fi
echo ""

# Check ip6tables NAT support
echo "2. Checking ip6tables NAT support:"
echo "------------------------------"
if ip6tables -t nat -L >/dev/null 2>&1; then
    echo "✅ ip6tables NAT is available"
    echo ""
    echo "Current ip6tables NAT rules:"
    ip6tables -t nat -L POSTROUTING -n -v | head -10
else
    echo "❌ ip6tables NAT is NOT available!"
    echo "   This is required for IPv6→IPv4 proxy"
    echo ""
    echo "Install with:"
    echo "  opkg install kmod-ipt-nat6"
    echo "  or"
    echo "  opkg install ip6tables-mod-nat"
fi
echo ""

# Check if IPv6 proxy ports are listening
echo "3. Checking IPv6 proxy listening ports:"
echo "------------------------------"
echo "Expected ports: 8080, 2323, 5000"
echo ""

if command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep -E ":::8080|:::2323|:::5000"
    if [ $? -ne 0 ]; then
        echo "❌ No IPv6 ports listening!"
    fi
elif command -v ss >/dev/null 2>&1; then
    ss -tuln | grep -E "::]:8080|::]:2323|::]:5000"
    if [ $? -ne 0 ]; then
        echo "❌ No IPv6 ports listening!"
    fi
else
    echo "⚠ netstat/ss not available - cannot check listening ports"
fi
echo ""

# Check gateway logs for IPv6 proxy setup
echo "4. Checking gateway logs for IPv6 proxy:"
echo "------------------------------"
if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    echo "Recent IPv6 proxy log entries:"
    grep -i "ipv6 proxy\|ipv6→ipv4\|socat" /var/log/ipv4-ipv6-gateway.log | tail -10

    if grep -q "IPv6 NAT support" /var/log/ipv4-ipv6-gateway.log; then
        echo ""
        echo "⚠ Warning found in logs about IPv6 NAT support"
    fi
else
    echo "Log file not found!"
fi
echo ""

echo "=========================================="
echo "DIAGNOSIS"
echo "=========================================="
echo ""

# Determine issue
HAS_SOCAT=$(ps aux | grep -c "[s]ocat")
HAS_NAT6=$(ip6tables -t nat -L >/dev/null 2>&1 && echo "yes" || echo "no")

if [ "$HAS_SOCAT" -eq 0 ] && [ "$HAS_NAT6" = "no" ]; then
    echo "❌ PROBLEM: IPv6 NAT not available"
    echo ""
    echo "The router doesn't have IPv6 NAT kernel support."
    echo "This is required for IPv6→IPv4 proxying."
    echo ""
    echo "SOLUTION:"
    echo "  opkg update"
    echo "  opkg install kmod-ipt-nat6 ip6tables-mod-nat"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo ""
elif [ "$HAS_SOCAT" -eq 0 ]; then
    echo "❌ PROBLEM: socat not running"
    echo ""
    echo "Gateway service may not be running or failed to start proxies."
    echo ""
    echo "SOLUTION:"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
else
    echo "✅ IPv6→IPv4 proxy appears to be running"
    echo ""
    echo "If you can ping IPv6 but not access HTTP:"
    echo "  1. Device web server may only listen on IPv4 (0.0.0.0)"
    echo "  2. Device firewall may block connections from gateway"
    echo "  3. Test from external IPv6 client:"
    echo ""
    echo "     curl 'http://[${DEVICE_WAN_IPV6:-<ipv6>}]:5000'"
    echo ""
fi

echo "=========================================="
echo "TEST IPv6 PROXY"
echo "=========================================="
echo ""
echo "From an external IPv6-enabled machine, try:"
echo ""
echo "  # Ping (should work)"
echo "  ping6 ${DEVICE_WAN_IPV6:-<device-ipv6>}"
echo ""
echo "  # HTTP via IPv6 proxy (port 5000)"
echo "  curl 'http://[${DEVICE_WAN_IPV6:-<device-ipv6>}]:5000'"
echo ""
echo "  # HTTP via IPv6 proxy (port 8080 → device:80)"
echo "  curl 'http://[${DEVICE_WAN_IPV6:-<device-ipv6>}]:8080'"
echo ""
echo "  # Telnet via IPv6 proxy"
echo "  telnet ${DEVICE_WAN_IPV6:-<device-ipv6>} 2323"
echo ""
