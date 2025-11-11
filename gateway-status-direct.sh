#!/bin/sh
#
# Direct gateway status check (no REST API needed)
# Works from console/KVM without network
#

DEVICES_FILE="/etc/ipv4-ipv6-gateway/devices.json"
PID_FILE="/var/run/ipv4-ipv6-gateway.pid"

echo "========================================="
echo "Gateway Service Status"
echo "========================================="
echo ""

# Check if service is running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Service Status: RUNNING (PID: $PID)"
    else
        echo "Service Status: STOPPED (stale PID file)"
    fi
else
    if ps | grep -v grep | grep -q "ipv4_ipv6_gateway.py"; then
        PID=$(ps | grep -v grep | grep "ipv4_ipv6_gateway.py" | awk '{print $1}')
        echo "Service Status: RUNNING (PID: $PID, no PID file)"
    else
        echo "Service Status: STOPPED"
    fi
fi
echo ""

# Check interfaces
echo "Network Interfaces:"
if ip link show eth0 >/dev/null 2>&1; then
    ETH0_STATE=$(ip link show eth0 | grep -o 'state [A-Z]*' | awk '{print $2}')
    echo "  eth0 (WAN): $ETH0_STATE"

    # Show eth0 addresses
    ETH0_IPV4=$(ip -4 addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    ETH0_IPV6=$(ip -6 addr show eth0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print $2}' | head -1)
    [ -n "$ETH0_IPV4" ] && echo "    IPv4: $ETH0_IPV4"
    [ -n "$ETH0_IPV6" ] && echo "    IPv6: $ETH0_IPV6"
else
    echo "  eth0 (WAN): NOT FOUND"
fi

if ip link show eth1 >/dev/null 2>&1; then
    ETH1_STATE=$(ip link show eth1 | grep -o 'state [A-Z]*' | awk '{print $2}')
    echo "  eth1 (LAN): $ETH1_STATE"

    # Show eth1 addresses
    ETH1_IPV4=$(ip -4 addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    [ -n "$ETH1_IPV4" ] && echo "    IPv4: $ETH1_IPV4"
else
    echo "  eth1 (LAN): NOT FOUND"
fi
echo ""

# Check device store
echo "Device Store:"
if [ -f "$DEVICES_FILE" ]; then
    # Count devices
    DEVICE_COUNT=$(cat "$DEVICES_FILE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d))' 2>/dev/null || echo "0")
    echo "  Total devices: $DEVICE_COUNT"

    if [ "$DEVICE_COUNT" -gt 0 ]; then
        # Count by status
        ACTIVE=$(cat "$DEVICES_FILE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.values() if v.get("status")=="active"))' 2>/dev/null || echo "0")
        DISCOVERING=$(cat "$DEVICES_FILE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.values() if v.get("status")=="discovering"))' 2>/dev/null || echo "0")
        FAILED=$(cat "$DEVICES_FILE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.values() if v.get("status")=="failed"))' 2>/dev/null || echo "0")

        echo "    Active: $ACTIVE"
        echo "    Discovering: $DISCOVERING"
        echo "    Failed: $FAILED"
    fi

    echo ""
    echo "  Last updated: $(stat -c %y "$DEVICES_FILE" 2>/dev/null || stat -f %Sm "$DEVICES_FILE" 2>/dev/null || echo "unknown")"
else
    echo "  No devices file found"
fi
echo ""

# Check logs
echo "Recent Log Entries:"
if [ -f "/var/log/ipv4-ipv6-gateway.log" ]; then
    tail -5 /var/log/ipv4-ipv6-gateway.log
else
    echo "  No log file found"
fi
echo ""

echo "========================================="
echo "Use 'gateway-devices-direct' to list all devices"
echo "Use 'tail -f /var/log/ipv4-ipv6-gateway.log' for live logs"
echo "========================================="
