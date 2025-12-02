#!/bin/sh
# Troubleshooting script for deployment issues
# Run this on the OpenWrt router

echo "======================================================================"
echo "IPv4/IPv6 Gateway - Deployment Troubleshooting"
echo "======================================================================"
echo ""

# Check service status
echo "1. Checking service status..."
if /etc/init.d/ipv4-ipv6-gateway status 2>/dev/null; then
    echo "   ✓ Service is running"
else
    echo "   ✗ Service is NOT running"
    echo "   Try: /etc/init.d/ipv4-ipv6-gateway start"
fi
echo ""

# Check log file
echo "2. Checking log file..."
if [ -f /var/log/ipv4-ipv6-gateway.log ]; then
    echo "   ✓ Log file exists"
    log_size=$(wc -l < /var/log/ipv4-ipv6-gateway.log)
    echo "   Log lines: $log_size"

    if [ "$log_size" -eq 0 ]; then
        echo "   ⚠ Log file is EMPTY"
        echo ""
        echo "   Possible causes:"
        echo "   - Service not actually running (check process)"
        echo "   - Python script crashed immediately"
        echo "   - Permission issues"
    else
        echo ""
        echo "   Last 20 lines of log:"
        echo "   -------------------------------------------"
        tail -20 /var/log/ipv4-ipv6-gateway.log | sed 's/^/   /'
        echo "   -------------------------------------------"
    fi
else
    echo "   ✗ Log file NOT found at /var/log/ipv4-ipv6-gateway.log"
    echo "   This means the service never started properly"
fi
echo ""

# Check if Python process is running
echo "3. Checking Python process..."
if ps | grep -v grep | grep "ipv4_ipv6_gateway.py" > /dev/null; then
    echo "   ✓ Python gateway process is running:"
    ps | grep -v grep | grep "ipv4_ipv6_gateway.py" | sed 's/^/   /'
else
    echo "   ✗ Python gateway process NOT running"
    echo ""
    echo "   Try starting manually to see errors:"
    echo "   cd /opt/ipv4-ipv6-gateway"
    echo "   python3 ipv4_ipv6_gateway.py"
fi
echo ""

# Check network interfaces
echo "4. Checking network interfaces..."
echo "   WAN (eth0):"
ip link show eth0 2>/dev/null | sed 's/^/     /' || echo "     ✗ eth0 not found"

echo ""
echo "   LAN (eth1):"
ip link show eth1 2>/dev/null | sed 's/^/     /' || echo "     ✗ eth1 not found"
echo ""

# Check ARP table
echo "5. Checking ARP table for devices on LAN..."
arp_devices=$(ip neigh show dev eth1 2>/dev/null | grep -v "192.168.1.1" | wc -l)
if [ "$arp_devices" -gt 0 ]; then
    echo "   ✓ Found $arp_devices device(s) in ARP:"
    ip neigh show dev eth1 | grep -v "192.168.1.1" | sed 's/^/   /'
else
    echo "   ⚠ No devices found in ARP table"
    echo ""
    echo "   Is your RF attenuator:"
    echo "   - Connected to eth1 (LAN port)?"
    echo "   - Powered on?"
    echo "   - Configured for DHCP or static IP 192.168.1.100-110?"
fi
echo ""

# Check DHCP server
echo "6. Checking DHCP leases..."
if [ -f /tmp/dhcp.leases ]; then
    lease_count=$(wc -l < /tmp/dhcp.leases)
    if [ "$lease_count" -gt 0 ]; then
        echo "   ✓ Active DHCP leases:"
        cat /tmp/dhcp.leases | sed 's/^/   /'
    else
        echo "   ⚠ No DHCP leases found"
    fi
else
    echo "   ⚠ DHCP leases file not found"
fi
echo ""

# Check dependencies
echo "7. Checking required dependencies..."
for cmd in python3 ip iptables udhcpc odhcp6c socat; do
    if command -v $cmd >/dev/null 2>&1; then
        echo "   ✓ $cmd: $(command -v $cmd)"
    else
        echo "   ✗ $cmd: NOT FOUND"
    fi
done
echo ""

# Check file permissions
echo "8. Checking file permissions..."
if [ -d /opt/ipv4-ipv6-gateway ]; then
    echo "   ✓ Gateway directory exists"
    echo "   Files:"
    ls -lah /opt/ipv4-ipv6-gateway/*.py 2>/dev/null | sed 's/^/   /' || echo "     ✗ No Python files found"
else
    echo "   ✗ Gateway directory NOT found at /opt/ipv4-ipv6-gateway"
    echo "   Run: ./install.sh --full-auto"
fi
echo ""

# Check state directory
echo "9. Checking state directory..."
if [ -d /etc/ipv4-ipv6-gateway ]; then
    echo "   ✓ State directory exists"
    if [ -f /etc/ipv4-ipv6-gateway/device.json ]; then
        echo "   ✓ Device state file exists:"
        cat /etc/ipv4-ipv6-gateway/device.json | sed 's/^/   /'
    else
        echo "   ℹ No device state (no device configured yet)"
    fi
else
    echo "   ✗ State directory NOT found"
    mkdir -p /etc/ipv4-ipv6-gateway
    echo "   Created: /etc/ipv4-ipv6-gateway"
fi
echo ""

# Summary
echo "======================================================================"
echo "TROUBLESHOOTING SUMMARY"
echo "======================================================================"
echo ""
echo "Common issues and fixes:"
echo ""
echo "1. Service running but no logs:"
echo "   → Check if Python script has syntax errors"
echo "   → Run manually: cd /opt/ipv4-ipv6-gateway && python3 ipv4_ipv6_gateway.py"
echo ""
echo "2. No device detected:"
echo "   → Verify device is connected to eth1 (LAN port)"
echo "   → Check if device has IP: ip neigh show dev eth1"
echo "   → Ping device from router: ping 192.168.1.100"
echo ""
echo "3. Log file empty:"
echo "   → Service may have crashed immediately"
echo "   → Check: logread | grep gateway"
echo "   → Check system log: tail -100 /var/log/messages"
echo ""
echo "4. Missing dependencies:"
echo "   → Run: opkg update && opkg install python3 ip-full iptables socat odhcp6c"
echo ""
echo "Need more help? Check:"
echo "  - Full logs: cat /var/log/ipv4-ipv6-gateway.log"
echo "  - System logs: logread"
echo "  - Manual test: cd /opt/ipv4-ipv6-gateway && python3 ipv4_ipv6_gateway.py"
echo ""
