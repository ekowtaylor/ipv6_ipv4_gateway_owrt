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
STATE_FILE="/etc/ipv4-ipv6-gateway/device.json"

if [ -f "$STATE_FILE" ]; then
    DEVICE_IPV6=$(grep -o '"wan_ipv6": "[^"]*' "$STATE_FILE" | head -1 | cut -d'"' -f4)
    DEVICE_IPV4=$(grep -o '"lan_ipv4": "[^"]*' "$STATE_FILE" | head -1 | cut -d'"' -f4)
fi

# Validate that we got valid values, exit if not
if [ -z "$DEVICE_IPV6" ] || [ -z "$DEVICE_IPV4" ]; then
    echo "ERROR: Cannot determine device IPs from $STATE_FILE"
    echo ""
    echo "Please ensure the gateway service has configured a device first:"
    echo "  /etc/init.d/ipv4-ipv6-gateway status"
    echo "  cat $STATE_FILE"
    exit 1
fi

echo "Device WAN IPv6: $DEVICE_IPV6"
echo "Device LAN IPv4: $DEVICE_IPV4"
echo ""

# Step 1: Kill old socat processes (IPv6 proxies only, not all socat!)
echo "[1/6] Killing old IPv6 proxy socat processes..."
pkill -f "socat.*TCP6-LISTEN" 2>/dev/null || true
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
