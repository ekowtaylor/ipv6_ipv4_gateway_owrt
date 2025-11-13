#!/bin/bash
#
# Emergency IPv6 Proxy Fix Script (Single-Device Mode)
# Fixes socat binding issue and restarts proxies
#

set -e

echo "=================================="
echo "IPv6 Proxy Emergency Fix"
echo "Single-Device Mode"
echo "=================================="
echo ""

# Auto-detect device info from device.json (single-device mode)
if [ -f /etc/ipv4-ipv6_gateway/device.json ]; then
    DEVICE_IPV6=$(cat /etc/ipv4-ipv6-gateway/device.json | grep -o '"wan_ipv6": "[^"]*' | head -1 | cut -d'"' -f4)
    DEVICE_IPV4=$(cat /etc/ipv4-ipv6-gateway/device.json | grep -o '"lan_ipv4": "[^"]*' | head -1 | cut -d'"' -f4)
fi

# Fallback to defaults if not found
DEVICE_IPV6="${DEVICE_IPV6:-2620:10d:c050:100:46b7:d0ff:fea6:6dfc}"
DEVICE_IPV4="${DEVICE_IPV4:-192.168.1.128}"

echo "Device WAN IPv6: $DEVICE_IPV6"
echo "Device LAN IPv4: $DEVICE_IPV4"
echo ""

# Step 1: Kill old socat processes
echo "[1/6] Killing old socat processes..."
killall socat 2>/dev/null || true
sleep 2

# Step 2: Ensure IPv6 is on eth0
echo "[2/6] Configuring IPv6 on eth0..."
ip -6 addr add "$DEVICE_IPV6/64" dev eth0 2>/dev/null || echo "  (Already exists)"

# Step 3: Enable Proxy NDP
echo "[3/6] Enabling Proxy NDP..."
ip -6 neigh add proxy "$DEVICE_IPV6" dev eth0 2>/dev/null || echo "  (Already exists)"

# Step 4: Fix firewall
echo "[4/6] Configuring IPv6 firewall..."
ip6tables -P INPUT ACCEPT 2>/dev/null || true
ip6tables -P FORWARD ACCEPT 2>/dev/null || true

# Step 5: Start socat with CORRECT syntax (NO BRACKETS, NO SOURCE BINDING!)
echo "[5/6] Starting socat proxies with FIXED syntax..."
echo "  Note: No source IP binding - kernel auto-selects for proper routing"

# HTTP proxy (port 80)
socat -d -d \
  TCP6-LISTEN:80,bind=$DEVICE_IPV6,fork,reuseaddr \
  TCP4:$DEVICE_IPV4:80 \
  >> /var/log/ipv4-ipv6-gateway.log 2>&1 &

# Telnet proxy (port 23)
socat -d -d \
  TCP6-LISTEN:23,bind=$DEVICE_IPV6,fork,reuseaddr \
  TCP4:$DEVICE_IPV4:23 \
  >> /var/log/ipv4-ipv6-gateway.log 2>&1 &

sleep 2

# Step 6: Verify
echo "[6/6] Verifying socat processes..."
SOCAT_COUNT=$(ps | grep socat | grep -v grep | wc -l)

if [ "$SOCAT_COUNT" -ge 2 ]; then
    echo ""
    echo "✓ SUCCESS! Found $SOCAT_COUNT socat processes running"
    echo ""
    ps | grep socat | grep -v grep
    echo ""
    echo "=================================="
    echo "FIXED! Test from remote host:"
    echo "  curl -6 http://[$DEVICE_IPV6]"
    echo "  telnet $DEVICE_IPV6 23"
    echo "=================================="
else
    echo ""
    echo "✗ ERROR: socat did not start properly"
    echo ""
    echo "Check logs:"
    echo "  tail -50 /var/log/ipv4-ipv6-gateway.log"
    echo ""
    echo "Manual start command:"
    echo "  socat -d -d TCP6-LISTEN:80,bind=$DEVICE_IPV6,fork,reuseaddr TCP4:$DEVICE_IPV4:80 &"
fi
