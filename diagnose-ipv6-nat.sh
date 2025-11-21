#!/bin/sh
#
# Quick IPv6 NAT Firewall Diagnostic
# Run this on your router to check nftables/ip6tables status
#

echo "═══════════════════════════════════════════"
echo "IPv6 NAT FIREWALL DIAGNOSTIC"
echo "═══════════════════════════════════════════"
echo ""

# Check OpenWrt version
echo "1. OpenWrt Version:"
cat /etc/openwrt_release | grep DISTRIB_RELEASE
echo ""

# Check if nft command exists
echo "2. nft command:"
if command -v nft >/dev/null 2>&1; then
    echo "   ✓ nft command found at: $(which nft)"
    nft --version
else
    echo "   ✗ nft command NOT found"
fi
echo ""

# Check if ip6tables command exists
echo "3. ip6tables command:"
if command -v ip6tables >/dev/null 2>&1; then
    echo "   ✓ ip6tables command found at: $(which ip6tables)"
    ip6tables --version
else
    echo "   ✗ ip6tables command NOT found"
fi
echo ""

# Check kernel modules
echo "4. Kernel modules (nftables):"
lsmod | grep -E "nft_nat|nf_nat" | head -5
echo ""

echo "5. Kernel modules (ip6tables):"
lsmod | grep -E "ip6t_|ip6_tables" | head -5
echo ""

# Try nftables
echo "6. Testing nftables (modern):"
if nft list table ip6 nat >/dev/null 2>&1; then
    echo "   ✓ nftables ip6 nat table exists"
    nft list table ip6 nat | head -20
elif nft list tables 2>/dev/null | grep -q "ip6"; then
    echo "   ⚠ nftables works but ip6 nat table missing"
    echo "   Available tables:"
    nft list tables
else
    echo "   ✗ nftables not working"
    nft list tables 2>&1
fi
echo ""

# Try ip6tables
echo "7. Testing ip6tables (legacy):"
if ip6tables -t nat -L >/dev/null 2>&1; then
    echo "   ✓ ip6tables NAT works"
    ip6tables -t nat -L POSTROUTING -n | head -10
else
    echo "   ✗ ip6tables NAT not working"
    ip6tables -t nat -L 2>&1 | head -5
fi
echo ""

# Check gateway service
echo "8. Gateway service status:"
if /etc/init.d/ipv4-ipv6-gateway status >/dev/null 2>&1; then
    echo "   ✓ Service is running"
else
    echo "   ✗ Service is NOT running"
fi
echo ""

# Check recent logs
echo "9. Recent gateway logs (IPv6 NAT detection):"
grep -i "ipv6 nat\|nftables\|ip6tables" /var/log/ipv4-ipv6-gateway.log | tail -10
echo ""

echo "═══════════════════════════════════════════"
echo "DIAGNOSTIC COMPLETE"
echo "═══════════════════════════════════════════"
