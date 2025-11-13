#!/bin/sh
# Quick test to see why device isn't being detected
# Run this ON THE ROUTER

echo "========================================"
echo "Device Detection Debug"
echo "========================================"
echo ""

echo "1. Interface Status:"
echo "-------------------"
ip link show eth1 2>/dev/null || echo "ERROR: eth1 not found!"
echo ""

echo "2. eth1 IP Address:"
echo "-------------------"
ip addr show eth1 2>/dev/null | grep "inet " || echo "ERROR: No IP on eth1"
echo ""

echo "3. ARP Table (eth1):"
echo "-------------------"
ip neigh show dev eth1
echo ""

echo "4. Raw ARP Table:"
echo "-------------------"
cat /proc/net/arp | grep eth1
echo ""

echo "5. DHCP Leases:"
echo "-------------------"
cat /tmp/dhcp.leases 2>/dev/null || echo "No DHCP leases"
echo ""

echo "6. dnsmasq Running:"
echo "-------------------"
ps | grep dnsmasq | grep -v grep || echo "dnsmasq NOT running!"
echo ""

echo "7. Force ARP Population:"
echo "-------------------"
echo "Pinging 192.168.1.100-110..."
for i in $(seq 100 110); do
    ping -c 1 -W 1 192.168.1.$i > /dev/null 2>&1 &
done
sleep 3
echo ""

echo "8. ARP After Ping:"
echo "-------------------"
ip neigh show dev eth1
echo ""

echo "9. Test ARP Parsing:"
echo "-------------------"
ip neigh show dev eth1 | while read line; do
    echo "Line: $line"
    echo "  IP: $(echo $line | awk '{print $1}')"
    echo "  MAC: $(echo $line | awk '{print $3}')"
    echo "  State: $(echo $line | awk '{print $5}')"
    echo ""
done
echo ""

echo "10. Gateway Service Status:"
echo "-------------------"
/etc/init.d/ipv4-ipv6-gateway status 2>/dev/null || echo "Service not installed"
echo ""

echo "11. Recent Gateway Logs:"
echo "-------------------"
tail -20 /var/log/ipv4-ipv6-gateway.log 2>/dev/null || echo "No log file"
echo ""

echo "========================================"
echo "DIAGNOSIS:"
echo "========================================"
if ip link show eth1 > /dev/null 2>&1; then
    echo "✓ eth1 exists"
else
    echo "✗ eth1 NOT FOUND - check interface names"
fi

if ip addr show eth1 2>/dev/null | grep -q "192.168.1.1"; then
    echo "✓ eth1 has gateway IP 192.168.1.1"
else
    echo "✗ eth1 doesn't have 192.168.1.1 - check network config"
fi

ARP_COUNT=$(ip neigh show dev eth1 | grep -v "192.168.1.1" | wc -l)
if [ $ARP_COUNT -gt 0 ]; then
    echo "✓ Found $ARP_COUNT device(s) in ARP table"
else
    echo "✗ No devices in ARP table - check if device is connected"
fi

if ps | grep -v grep | grep -q dnsmasq; then
    echo "✓ dnsmasq is running"
else
    echo "✗ dnsmasq NOT running - device can't get DHCP"
fi

echo ""
echo "If you see devices above but gateway doesn't detect them,"
echo "run the service manually to see debug output:"
echo ""
echo "  /etc/init.d/ipv4-ipv6-gateway stop"
echo "  cd /opt/ipv4-ipv6-gateway"
echo "  python3 ipv4_ipv6_gateway.py"
echo ""
