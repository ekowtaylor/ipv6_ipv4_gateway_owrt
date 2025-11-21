#!/bin/sh
#
# DIAGNOSE WHY IPv6 HTTP FAILS BUT IPv4 WORKS
# Check if device web server is listening on IPv6
#

echo "=========================================="
echo "IPv6 vs IPv4 WEB SERVER DIAGNOSTIC"
echo "=========================================="
echo ""

# Get device info
DEVICE_LAN_IP=""
DEVICE_WAN_IP=""
DEVICE_IPV6=""

if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"lan_ipv4"' | cut -d'"' -f4)
    DEVICE_WAN_IP=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"wan_ipv4"' | cut -d'"' -f4)
    DEVICE_IPV6=$(cat /etc/ipv4-ipv6-gateway/device.json | grep '"ipv6_addresses"' -A 5 | grep '"' | head -1 | cut -d'"' -f2)
fi

echo "Device Information:"
echo "------------------------------"
echo "LAN IPv4:  ${DEVICE_LAN_IP:-NOT FOUND}"
echo "WAN IPv4:  ${DEVICE_WAN_IP:-NOT FOUND}"
echo "IPv6:      ${DEVICE_IPV6:-NOT FOUND}"
echo ""

if [ -z "$DEVICE_LAN_IP" ]; then
    echo "ERROR: No device configured"
    exit 1
fi

echo "1. Test IPv4 Connectivity (from router to device):"
echo "------------------------------"
echo "Testing HTTP on port 5000..."
curl -v --connect-timeout 5 http://${DEVICE_LAN_IP}:5000 2>&1 | head -15
echo ""

if [ -n "$DEVICE_IPV6" ]; then
    echo "2. Test IPv6 Connectivity (from router to device):"
    echo "------------------------------"
    echo "Ping device IPv6..."
    ping6 -c 3 $DEVICE_IPV6
    echo ""

    echo "Testing HTTP on port 5000 via IPv6..."
    curl -v --connect-timeout 5 http://[${DEVICE_IPV6}]:5000 2>&1 | head -15
    echo ""
fi

echo "3. Check what the device is listening on:"
echo "------------------------------"
echo "Attempting SSH to device to check listening ports..."
echo "(This will fail if device doesn't have SSH or if auth fails)"
echo ""

# Try to SSH and check netstat (won't work without credentials)
echo "Try this command ON THE DEVICE itself:"
echo "  netstat -tuln | grep :5000"
echo ""
echo "Or if device has 'ss' command:"
echo "  ss -tuln | grep :5000"
echo ""
echo "Expected output if listening on IPv4 only:"
echo "  tcp  0  0  0.0.0.0:5000  0.0.0.0:*  LISTEN"
echo "  tcp  0  0  127.0.0.1:5000  0.0.0.0:*  LISTEN"
echo ""
echo "Expected output if listening on IPv6 also:"
echo "  tcp  0  0  :::5000  :::*  LISTEN"
echo "  tcp6 0  0  :::5000  :::*  LISTEN"
echo ""

echo "4. Common Causes:"
echo "------------------------------"
echo "If IPv4 works but IPv6 doesn't:"
echo ""
echo "CAUSE 1: Web server only bound to IPv4"
echo "  - Server config specifies IPv4 address (0.0.0.0 or 127.0.0.1)"
echo "  - Server not configured for dual-stack (::0)"
echo "  - Fix: Update server to listen on :: (all IPv6) or 0.0.0.0 (all IPv4+IPv6)"
echo ""
echo "CAUSE 2: Device firewall blocking IPv6"
echo "  - iptables/ip6tables rules blocking incoming IPv6"
echo "  - Fix: Allow port 5000 in device firewall"
echo ""
echo "CAUSE 3: Device not accepting IPv6 connections"
echo "  - sysctl net.ipv6.conf.all.disable_ipv6=1"
echo "  - Fix: Enable IPv6 on device"
echo ""

echo "=========================================="
echo "SOLUTION"
echo "=========================================="
echo ""
echo "To fix IPv6 HTTP access, ON THE DEVICE:"
echo ""
echo "Option 1: Configure web server for dual-stack"
echo "------------------------------"
echo "Flask/Python:"
echo "  app.run(host='::', port=5000)  # Listen on IPv6"
echo ""
echo "Node.js/Express:"
echo "  app.listen(5000, '::', () => {...})  # Listen on IPv6"
echo ""
echo "Apache/nginx:"
echo "  listen [::]:5000 ipv6only=off;  # Listen on both IPv4 and IPv6"
echo ""
echo "Option 2: Disable device firewall (temporary test)"
echo "------------------------------"
echo "  iptables -F  # Flush IPv4 rules"
echo "  ip6tables -F  # Flush IPv6 rules"
echo ""
echo "Option 3: Add IPv6 firewall rule on device"
echo "------------------------------"
echo "  ip6tables -A INPUT -p tcp --dport 5000 -j ACCEPT"
echo ""
