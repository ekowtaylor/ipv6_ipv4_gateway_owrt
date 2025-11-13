#!/bin/sh
#
# Diagnose IPv6 Proxy Issues
# Run this on the OpenWrt gateway to check why HTTP/telnet proxies aren't working
#

echo "=========================================="
echo "IPv6 Proxy Diagnostics"
echo "=========================================="
echo ""

# Get device info from gateway
echo "1. Checking Gateway Service Status..."
echo "────────────────────────────────────────"

if ! curl -s http://localhost:8000/health >/dev/null 2>&1; then
    echo "❌ Gateway API not responding on localhost:8000"
    echo "   Is the gateway service running?"
    echo ""
    echo "   Check with: ps | grep python | grep gateway"
    ps | grep python | grep gateway || echo "   (No gateway process found)"
    exit 1
fi

echo "✅ Gateway API is running"
echo ""

# Get device information
echo "2. Checking Connected Devices..."
echo "────────────────────────────────────────"

DEVICE_JSON=$(curl -s http://localhost:8000/devices 2>/dev/null)
if [ -z "$DEVICE_JSON" ]; then
    echo "❌ Cannot get device list from gateway"
    exit 1
fi

# Parse JSON to get device info (simple grep/awk parsing for busybox)
MAC=$(echo "$DEVICE_JSON" | grep -o '"mac_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV4=$(echo "$DEVICE_JSON" | grep -o '"ipv4_address":"[^"]*"' | head -1 | cut -d'"' -f4)
IPV6=$(echo "$DEVICE_JSON" | grep -o '"ipv6_address":"[^"]*"' | head -1 | cut -d'"' -f4)
STATUS=$(echo "$DEVICE_JSON" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$MAC" ]; then
    echo "❌ No devices found in gateway"
    echo ""
    echo "Full response:"
    echo "$DEVICE_JSON"
    exit 1
fi

echo "Device Information:"
echo "  MAC:    $MAC"
echo "  LAN IP: $IPV4"
echo "  WAN IP: $IPV6"
echo "  Status: $STATUS"
echo ""

if [ -z "$IPV6" ] || [ "$IPV6" = "null" ]; then
    echo "❌ CRITICAL: Device has no IPv6 address!"
    echo "   This is why proxies cannot start - they need an IPv6 to bind to"
    echo ""
    echo "   Possible causes:"
    echo "   - DHCPv6 failed during discovery"
    echo "   - SLAAC didn't assign an IPv6"
    echo "   - Router doesn't support IPv6"
    echo ""
    echo "   Check gateway logs:"
    echo "   tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i ipv6"
    exit 1
fi

echo "✅ Device has IPv6 address"
echo ""

# Check if IPv6 is configured on eth0
echo "3. Checking IPv6 on WAN Interface (eth0)..."
echo "────────────────────────────────────────"

ETH0_IPV6=$(ip -6 addr show eth0 | grep 'inet6' | grep -v 'fe80' | awk '{print $2}' | cut -d'/' -f1)

if [ -z "$ETH0_IPV6" ]; then
    echo "❌ CRITICAL: No IPv6 addresses on eth0!"
    echo ""
    echo "   This is the problem - proxies need to bind to IPv6 on eth0"
    echo ""
    echo "   eth0 addresses:"
    ip -6 addr show eth0
    exit 1
fi

echo "✅ eth0 has IPv6 addresses:"
echo "$ETH0_IPV6" | while read addr; do
    if echo "$addr" | grep -q "$IPV6"; then
        echo "  ✅ $addr (device IPv6 - CORRECT!)"
    else
        echo "     $addr"
    fi
done
echo ""

# Check if device IPv6 is on eth0
if ! echo "$ETH0_IPV6" | grep -q "$IPV6"; then
    echo "⚠️  WARNING: Device IPv6 $IPV6 not found on eth0!"
    echo "   Proxies cannot bind to this address"
    echo ""
    echo "   This usually means:"
    echo "   - IPv6 was obtained but not added to eth0"
    echo "   - DHCPv6 didn't configure the interface"
    echo ""
    echo "   Try manually adding it:"
    echo "   ip -6 addr add $IPV6/64 dev eth0"
    exit 1
fi

echo "✅ Device IPv6 is configured on eth0"
echo ""

# Check proxy processes
echo "4. Checking Proxy Processes..."
echo "────────────────────────────────────────"

SOCAT_COUNT=$(ps | grep -c "[s]ocat.*TCP6-LISTEN" || echo "0")
HAPROXY_COUNT=$(ps | grep -c "[h]aproxy" || echo "0")

if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo "✅ Found $SOCAT_COUNT socat proxy processes:"
    echo ""
    ps | grep "[s]ocat" | while read line; do
        PID=$(echo "$line" | awk '{print $1}')
        echo "  PID $PID:"
        echo "  $line" | awk '{$1=""; print "   ", $0}'
    done
    echo ""
    PROXY_BACKEND="socat"
elif [ "$HAPROXY_COUNT" -gt 0 ]; then
    echo "✅ Found HAProxy running"
    ps | grep "[h]aproxy"
    echo ""
    PROXY_BACKEND="haproxy"
else
    echo "❌ CRITICAL: No proxy processes found!"
    echo ""
    echo "   This is why HTTP/telnet doesn't work"
    echo ""
    echo "   Possible causes:"
    echo "   - Proxies failed to start during device discovery"
    echo "   - IPv6 bind failed"
    echo "   - Configuration error"
    echo ""
    echo "   Check gateway logs for proxy start errors:"
    echo "   tail -50 /var/log/ipv4-ipv6-gateway.log | grep -i 'proxy\|socat\|haproxy'"
    exit 1
fi

# Check listening ports
echo "5. Checking Listening Ports..."
echo "────────────────────────────────────────"

if command -v netstat >/dev/null 2>&1; then
    echo "IPv6 listening ports (netstat):"
    netstat -ln6 | grep -E 'LISTEN|Proto' || echo "  (No IPv6 listeners)"
elif command -v ss >/dev/null 2>&1; then
    echo "IPv6 listening ports (ss):"
    ss -ln6 | grep -E 'LISTEN|State' || echo "  (No IPv6 listeners)"
else
    echo "⚠️  Cannot check listening ports (netstat/ss not available)"
fi
echo ""

# Check if port 80 and 23 are listening on device IPv6
if command -v nc >/dev/null 2>&1; then
    echo "Testing local connectivity to proxies:"
    echo ""

    if timeout 2 nc -6 -z -v "$IPV6" 80 2>&1 | grep -q "succeeded\|open"; then
        echo "  ✅ Port 80 is listening on [$IPV6]"
    else
        echo "  ❌ Port 80 NOT listening on [$IPV6]"
        echo "     This is the problem! HTTP proxy isn't bound correctly"
    fi

    if timeout 2 nc -6 -z -v "$IPV6" 23 2>&1 | grep -q "succeeded\|open"; then
        echo "  ✅ Port 23 is listening on [$IPV6]"
    else
        echo "  ❌ Port 23 NOT listening on [$IPV6]"
        echo "     This is the problem! Telnet proxy isn't bound correctly"
    fi
fi
echo ""

# Check recent gateway logs
echo "6. Recent Gateway Logs (Proxy-related)..."
echo "────────────────────────────────────────"

if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    echo "Last 30 lines with 'proxy', 'socat', or 'IPv6':"
    tail -50 /var/log/ipv4-ipv6-gateway.log | grep -iE 'proxy|socat|ipv6.*start|bind' | tail -30
else
    echo "⚠️  Log file not found at /var/log/ipv4-ipv6-gateway.log"
fi
echo ""

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "Device: $MAC"
echo "  LAN IPv4: $IPV4"
echo "  WAN IPv6: $IPV6"
echo "  Status:   $STATUS"
echo ""

if [ "$SOCAT_COUNT" -gt 0 ] || [ "$HAPROXY_COUNT" -gt 0 ]; then
    echo "Proxy Status: ✅ Running ($PROXY_BACKEND)"
    echo ""
    echo "If HTTP still doesn't work from client:"
    echo "  1. Check firewall on gateway: ip6tables -L -n"
    echo "  2. Check routing: ip -6 route"
    echo "  3. Test from gateway: curl \"http://[$IPV6]/\""
    echo "  4. Check if device has HTTP service: curl \"http://$IPV4/\""
else
    echo "Proxy Status: ❌ NOT RUNNING"
    echo ""
    echo "To fix:"
    echo "  1. Check logs: tail -100 /var/log/ipv4-ipv6-gateway.log"
    echo "  2. Look for proxy start errors"
    echo "  3. Verify IPv6 is on eth0: ip -6 addr show eth0"
    echo "  4. Try restarting gateway service"
fi
echo ""
