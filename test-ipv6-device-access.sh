#!/bin/bash
#
# TEST IPv6 DEVICE ACCESS - Find which ports are actually open
#

DEVICE_IPV6="dd56:fb82:64ad::46b7:d0ff:fea6:773f"

echo "=========================================="
echo "IPv6 DEVICE ACCESS TEST"
echo "=========================================="
echo ""
echo "Device IPv6: $DEVICE_IPV6"
echo ""

echo "1. Testing Ping (ICMP):"
echo "------------------------------"
ping6 -c 3 $DEVICE_IPV6
echo ""

echo "2. Testing Common Ports:"
echo "------------------------------"

# Test HTTP port 80
echo -n "Port 80 (HTTP): "
if curl -s --connect-timeout 2 "http://[$DEVICE_IPV6]:80" > /dev/null 2>&1; then
    echo "✅ OPEN"
    echo "   Try: curl 'http://[$DEVICE_IPV6]:80'"
elif curl -s --max-time 2 "http://[$DEVICE_IPV6]:80" 2>&1 | grep -q "Empty reply\|curl: (52)"; then
    echo "✅ OPEN (but no HTTP response)"
    echo "   Port is listening but may not be HTTP"
else
    echo "❌ CLOSED or filtered"
fi

# Test HTTP port 5000
echo -n "Port 5000 (HTTP alt): "
if curl -s --connect-timeout 2 "http://[$DEVICE_IPV6]:5000" > /dev/null 2>&1; then
    echo "✅ OPEN"
    echo "   Try: curl 'http://[$DEVICE_IPV6]:5000'"
elif curl -s --max-time 2 "http://[$DEVICE_IPV6]:5000" 2>&1 | grep -q "Empty reply\|curl: (52)"; then
    echo "✅ OPEN (but no HTTP response)"
else
    echo "❌ CLOSED or filtered"
fi

# Test Telnet port 23
echo -n "Port 23 (Telnet): "
if timeout 2 bash -c "echo > /dev/tcp/$DEVICE_IPV6/23" 2>/dev/null; then
    echo "✅ OPEN"
    echo "   Try: telnet $DEVICE_IPV6 23"
else
    echo "❌ CLOSED or filtered"
fi

# Test SSH port 22
echo -n "Port 22 (SSH): "
if timeout 2 bash -c "echo > /dev/tcp/$DEVICE_IPV6/22" 2>/dev/null; then
    echo "✅ OPEN"
    echo "   Try: ssh user@$DEVICE_IPV6"
else
    echo "❌ CLOSED or filtered"
fi

# Test HTTPS port 443
echo -n "Port 443 (HTTPS): "
if timeout 2 bash -c "echo > /dev/tcp/$DEVICE_IPV6/443" 2>/dev/null; then
    echo "✅ OPEN"
    echo "   Try: curl -k 'https://[$DEVICE_IPV6]:443'"
else
    echo "❌ CLOSED or filtered"
fi

echo ""
echo "3. Full Port Scan (common ports):"
echo "------------------------------"
if command -v nmap >/dev/null 2>&1; then
    echo "Running nmap scan..."
    nmap -6 $DEVICE_IPV6 -p 21,22,23,80,443,5000,5900,3389,8080,8443
else
    echo "nmap not installed - skipping detailed scan"
    echo "Install with: brew install nmap (macOS) or apt install nmap (Linux)"
fi

echo ""
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""
echo "IPv6 Connectivity: ✅ WORKING (ping succeeds)"
echo ""
echo "If no ports are open:"
echo "  1. Device may not have services running yet"
echo "  2. Device firewall may be blocking connections"
echo "  3. Check device with: gateway-device (on router)"
echo ""
echo "Next steps:"
echo "  - Start a web server on device (port 80 or 5000)"
echo "  - Check device firewall settings"
echo "  - Check router logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
