#!/bin/bash
#
# Comprehensive IPv6 Services Test
# Tests IPv6 connectivity and proxy services for the connected device
#

set -e

echo "=========================================="
echo "IPv6 Services Test"
echo "=========================================="
echo ""

# Get device IPv6 from gateway API
echo "📡 Fetching device information from gateway..."
DEVICE_INFO=$(curl -s http://localhost:8000/devices 2>/dev/null)

if [ -z "$DEVICE_INFO" ]; then
    echo "❌ ERROR: Cannot reach gateway API at http://localhost:8000"
    echo "   Is the gateway service running?"
    exit 1
fi

# Extract first device's IPv6 (using Python for JSON parsing)
DEVICE_IPV6=$(echo "$DEVICE_INFO" | python3 -c "
import sys, json
devices = json.load(sys.stdin)
if devices:
    first_device = list(devices.values())[0]
    ipv6 = first_device.get('ipv6_address')
    if ipv6:
        print(ipv6)
" 2>/dev/null)

if [ -z "$DEVICE_IPV6" ]; then
    echo "❌ ERROR: No device with IPv6 found"
    echo ""
    echo "Available devices:"
    echo "$DEVICE_INFO" | python3 -m json.tool
    exit 1
fi

echo "✓ Found device IPv6: $DEVICE_IPV6"
echo ""

# Test 1: IPv6 Ping
echo "=========================================="
echo "Test 1: IPv6 Ping"
echo "=========================================="
echo "Testing: ping6 $DEVICE_IPV6 -c 4"
echo ""

if ping6 -c 4 "$DEVICE_IPV6" 2>&1 | grep -q "bytes from"; then
    echo "✅ IPv6 PING SUCCESS"
    ping6 -c 4 "$DEVICE_IPV6" | tail -2
else
    echo "❌ IPv6 PING FAILED"
    ping6 -c 4 "$DEVICE_IPV6" || true
fi
echo ""

# Test 2: IPv6 Telnet (Port 23)
echo "=========================================="
echo "Test 2: IPv6 Telnet Proxy (Port 23)"
echo "=========================================="
echo "Testing: telnet $DEVICE_IPV6 23"
echo ""

# Try to connect to telnet with timeout
if timeout 3 bash -c "echo 'quit' | nc -6 $DEVICE_IPV6 23" >/dev/null 2>&1; then
    echo "✅ IPv6 TELNET PORT 23 OPEN"
    echo "   Connection successful to [$DEVICE_IPV6]:23"
    echo ""
    echo "   Try manually:"
    echo "   telnet $DEVICE_IPV6 23"
elif nc -6 -z -v -w2 "$DEVICE_IPV6" 23 2>&1 | grep -q "succeeded\|open"; then
    echo "✅ IPv6 TELNET PORT 23 OPEN"
    echo "   Connection successful to [$DEVICE_IPV6]:23"
    echo ""
    echo "   Try manually:"
    echo "   telnet $DEVICE_IPV6 23"
else
    echo "❌ IPv6 TELNET PORT 23 FAILED"
    echo "   Cannot connect to [$DEVICE_IPV6]:23"
    echo ""
    echo "   Possible causes:"
    echo "   - Socat/HAProxy proxy not running"
    echo "   - Device doesn't have telnet service"
    echo "   - Firewall blocking connection"
fi
echo ""

# Test 3: IPv6 HTTP (Port 80)
echo "=========================================="
echo "Test 3: IPv6 HTTP Proxy (Port 80)"
echo "=========================================="
echo "Testing: curl -6 \"http://[$DEVICE_IPV6]:80/\""
echo ""

# Try HTTP request with timeout
HTTP_RESPONSE=$(curl -6 -s -m 5 "http://[$DEVICE_IPV6]:80/" 2>&1 || echo "FAILED")

if echo "$HTTP_RESPONSE" | grep -qE "<!DOCTYPE|<html|<HTML|HTTP"; then
    echo "✅ IPv6 HTTP PORT 80 SUCCESS"
    echo "   Got HTTP response from [$DEVICE_IPV6]:80"
    echo ""
    echo "   Response preview:"
    echo "$HTTP_RESPONSE" | head -5
    echo "   ..."
    echo ""
    echo "   Try in browser:"
    echo "   http://[$DEVICE_IPV6]/"
elif echo "$HTTP_RESPONSE" | grep -q "Connection refused"; then
    echo "⚠️  IPv6 HTTP PORT 80 REFUSED"
    echo "   Port is open but connection refused"
    echo "   Device may not have HTTP service running"
elif echo "$HTTP_RESPONSE" | grep -q "timed out\|timeout"; then
    echo "❌ IPv6 HTTP PORT 80 TIMEOUT"
    echo "   Connection timed out"
    echo "   - Check if socat/HAProxy proxy is running"
    echo "   - Check firewall rules"
else
    echo "❌ IPv6 HTTP PORT 80 FAILED"
    echo "   Cannot connect to [$DEVICE_IPV6]:80"
    echo ""
    echo "   Error: $HTTP_RESPONSE"
fi
echo ""

# Test 4: Check Proxy Processes
echo "=========================================="
echo "Test 4: Proxy Process Status"
echo "=========================================="
echo ""

# Check for socat processes
SOCAT_COUNT=$(ps aux | grep -c "[s]ocat.*TCP6-LISTEN" || echo "0")
if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo "✅ Found $SOCAT_COUNT socat IPv6 proxy processes"
    echo ""
    echo "   Active socat proxies:"
    ps aux | grep "[s]ocat.*TCP6-LISTEN" | awk '{print "   - PID " $2 ": " $11 " " $12 " " $13 " " $14}' || true
else
    echo "⚠️  No socat IPv6 proxies found"

    # Check for HAProxy instead
    if ps aux | grep -q "[h]aproxy"; then
        echo "   (Using HAProxy instead of socat)"
        HAPROXY_PID=$(ps aux | grep "[h]aproxy" | awk '{print $2}' | head -1)
        echo "   - HAProxy PID: $HAPROXY_PID"
    else
        echo "   ❌ No proxy processes found!"
        echo "   The gateway may not have started proxies yet"
    fi
fi
echo ""

# Test 5: Gateway Logs
echo "=========================================="
echo "Test 5: Recent Gateway Logs"
echo "=========================================="
echo ""
echo "Recent proxy-related log entries:"
echo "────────────────────────────────────────"

if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    tail -20 /var/log/ipv4-ipv6-gateway.log | grep -i "proxy\|ipv6" || echo "(No recent proxy logs)"
else
    echo "⚠️  Log file not found at /var/log/ipv4-ipv6-gateway.log"
    echo "   Gateway may be logging elsewhere or not running"
fi
echo ""

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "Device IPv6: $DEVICE_IPV6"
echo ""
echo "Services to test manually:"
echo "  - IPv6 Ping:   ping6 $DEVICE_IPV6"
echo "  - IPv6 Telnet: telnet $DEVICE_IPV6 23"
echo "  - IPv6 HTTP:   curl \"http://[$DEVICE_IPV6]/\""
echo "  - Browser:     http://[$DEVICE_IPV6]/"
echo ""
echo "=========================================="
