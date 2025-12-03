#!/bin/sh
#
# FIX IPv6 NAT SUPPORT - Install and verify IPv6 NAT functionality
# This enables IPv6→IPv4 proxy (socat) to work properly
#

echo "=========================================="
echo "IPv6 NAT SUPPORT FIX"
echo "=========================================="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run as root"
    exit 1
fi

# Step 1: Check current IPv6 NAT status
echo "Step 1: Checking current IPv6 NAT status..."
echo "------------------------------"
echo ""

IPV6_NAT_WORKING=false

# Try modern nftables with fw4 table first (OpenWrt 21+)
if command -v nft >/dev/null 2>&1; then
    echo "✓ nft command found"

    # Check for fw4 table (modern OpenWrt)
    if nft list table inet fw4 >/dev/null 2>&1; then
        echo "✓ nftables fw4 table found (OpenWrt 21+)"
        IPV6_NAT_WORKING=true
        FIREWALL_TYPE="nftables-fw4"
    # Fall back to legacy ip6 nat table (OpenWrt 20-21)
    elif nft list table ip6 nat >/dev/null 2>&1; then
        echo "✓ nftables ip6 nat table found (OpenWrt 20-21)"
        IPV6_NAT_WORKING=true
        FIREWALL_TYPE="nftables"
    else
        echo "✗ nftables found but no fw4 or ip6 nat table"
    fi
else
    echo "✗ nft command not found"
fi

# Try ip6tables (legacy)
if [ "$IPV6_NAT_WORKING" = "false" ]; then
    if command -v ip6tables >/dev/null 2>&1; then
        echo "✓ ip6tables command found"
        if ip6tables -t nat -L >/dev/null 2>&1; then
            echo "✓ ip6tables IPv6 NAT is available"
            IPV6_NAT_WORKING=true
            FIREWALL_TYPE="ip6tables"
        else
            echo "✗ ip6tables found but NAT table not accessible"
            echo "   Error: $(ip6tables -t nat -L 2>&1)"
        fi
    else
        echo "✗ ip6tables command not found"
    fi
fi

echo ""

if [ "$IPV6_NAT_WORKING" = "true" ]; then
    echo "✅ IPv6 NAT is already working ($FIREWALL_TYPE)"
    echo ""
    echo "The gateway should be able to start socat processes."
    echo "If socat is still not running, check:"
    echo "  - Gateway service logs: tail -f /var/log/ipv4-ipv6-gateway.log"
    echo "  - Restart gateway: /etc/init.d/ipv4-ipv6-gateway restart"
    exit 0
fi

echo "❌ IPv6 NAT is NOT working"
echo ""

# Step 2: Install IPv6 NAT packages
echo "Step 2: Installing IPv6 NAT packages..."
echo "------------------------------"
echo ""

echo "Updating package list..."
opkg update
echo ""

# Try different kernel module packages (varies by OpenWrt version)
echo "Installing IPv6 NAT kernel modules..."
IPV6_NAT_INSTALLED=false

for pkg in kmod-ipt-nat6 kmod-nf-nat6; do
    echo "  Trying: $pkg..."
    if opkg install "$pkg" 2>/dev/null; then
        echo "  ✓ Installed: $pkg"
        IPV6_NAT_INSTALLED=true
        IPV6_NAT_PACKAGE="$pkg"
        break
    else
        echo "  ✗ Not available: $pkg"
    fi
done

if [ "$IPV6_NAT_INSTALLED" = "false" ]; then
    echo ""
    echo "❌ CRITICAL: IPv6 NAT kernel modules are NOT available!"
    echo ""
    echo "This means:"
    echo "  - Your OpenWrt version doesn't support IPv6 NAT"
    echo "  - Your kernel doesn't have CONFIG_NF_NAT_IPV6=y"
    echo "  - Your hardware uses a minimal kernel"
    echo ""
    echo "SOLUTIONS:"
    echo "  1. Upgrade to OpenWrt 21.02 or newer"
    echo "  2. Compile custom kernel with CONFIG_NF_NAT_IPV6=y"
    echo "  3. Use different hardware with full kernel support"
    echo ""
    echo "IMPACT:"
    echo "  ✓ Your device WILL have dual-stack internet (IPv4 + IPv6)"
    echo "  ✗ External IPv6 clients CANNOT connect to device services"
    echo "  ✗ No socat processes will run"
    echo ""
    exit 1
fi

echo ""
echo "Installing ip6tables userspace tools..."
if opkg install ip6tables-mod-nat 2>/dev/null; then
    echo "  ✓ Installed: ip6tables-mod-nat"
elif opkg install ip6tables 2>/dev/null; then
    echo "  ✓ Installed: ip6tables (basic)"
else
    echo "  ⚠ ip6tables installation failed (might already be installed)"
fi

echo ""

# Step 3: Load kernel modules
echo "Step 3: Loading IPv6 NAT kernel modules..."
echo "------------------------------"
echo ""

modprobe nf_nat 2>/dev/null && echo "  ✓ Loaded: nf_nat" || echo "  ↻ nf_nat already loaded"
modprobe ip6table_nat 2>/dev/null && echo "  ✓ Loaded: ip6table_nat" || echo "  ↻ ip6table_nat already loaded"
modprobe nf_conntrack 2>/dev/null && echo "  ✓ Loaded: nf_conntrack" || echo "  ↻ nf_conntrack already loaded"

echo ""

# Step 4: Verify IPv6 NAT is working
echo "Step 4: Verifying IPv6 NAT functionality..."
echo "------------------------------"
echo ""

IPV6_NAT_WORKING=false

# Try nftables first
if command -v nft >/dev/null 2>&1; then
    # Check for fw4 table first (modern OpenWrt)
    if nft list table inet fw4 >/dev/null 2>&1; then
        echo "✅ nftables fw4 table is FUNCTIONAL"
        IPV6_NAT_WORKING=true
        FIREWALL_TYPE="nftables-fw4"
    # Fall back to ip6 nat table
    elif nft list table ip6 nat >/dev/null 2>&1; then
        echo "✅ nftables ip6 nat table is FUNCTIONAL"
        IPV6_NAT_WORKING=true
        FIREWALL_TYPE="nftables"
    else
        # Try to create the table
        echo "  Attempting to create nftables ip6 nat table..."
        if nft add table ip6 nat 2>/dev/null; then
            echo "  ✓ Created ip6 nat table"
            nft add chain ip6 nat POSTROUTING "{ type nat hook postrouting priority 100 ; }" 2>/dev/null
            echo "  ✓ Created POSTROUTING chain"

            if nft list table ip6 nat >/dev/null 2>&1; then
                echo "✅ nftables ip6 nat table is now FUNCTIONAL"
                IPV6_NAT_WORKING=true
                FIREWALL_TYPE="nftables"
            fi
        fi
    fi
fi

# Fall back to ip6tables
if [ "$IPV6_NAT_WORKING" = "false" ]; then
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -t nat -L >/dev/null 2>&1; then
        echo "✅ ip6tables IPv6 NAT is FUNCTIONAL"
        IPV6_NAT_WORKING=true
        FIREWALL_TYPE="ip6tables"
    fi
fi

echo ""

if [ "$IPV6_NAT_WORKING" = "false" ]; then
    echo "❌ IPv6 NAT installation FAILED"
    echo ""
    echo "Packages were installed but IPv6 NAT is still not functional."
    echo "This likely means:"
    echo "  - Kernel doesn't support IPv6 NAT"
    echo "  - Router reboot required"
    echo "  - Incompatible OpenWrt version"
    echo ""
    echo "Try rebooting the router: reboot"
    exit 1
fi

# Step 5: Save package info for uninstaller
echo "Step 5: Saving installation info..."
mkdir -p /etc/ipv4-ipv6-gateway
echo "$IPV6_NAT_PACKAGE" > /etc/ipv4-ipv6-gateway/ipv6_nat_package.txt
echo "ip6tables-mod-nat" >> /etc/ipv4-ipv6-gateway/ipv6_nat_package.txt
echo "  ✓ Installation info saved"
echo ""

# Step 6: Restart gateway service
echo "Step 6: Restarting gateway service..."
echo "------------------------------"
echo ""

if [ -x /etc/init.d/ipv4-ipv6-gateway ]; then
    echo "Restarting gateway service to enable IPv6 proxy..."
    /etc/init.d/ipv4-ipv6-gateway restart
    sleep 5
    echo "  ✓ Gateway service restarted"
else
    echo "  ⚠ Gateway service not found - you'll need to restart it manually"
fi

echo ""

# Step 7: Verify socat processes
echo "Step 7: Verifying socat processes..."
echo "------------------------------"
echo ""

sleep 3  # Give socat time to start

SOCAT_COUNT=$(ps aux | grep -c "[s]ocat.*TCP6-LISTEN")
if [ "$SOCAT_COUNT" -gt 0 ]; then
    echo "✅ SUCCESS: Found $SOCAT_COUNT socat process(es) running!"
    echo ""
    echo "Active socat proxies:"
    ps aux | grep "[s]ocat" | grep -v grep
    echo ""
else
    echo "⚠ No socat processes found yet"
    echo ""
    echo "This could mean:"
    echo "  - Device not yet configured (no device connected)"
    echo "  - Device has no IPv6 address"
    echo "  - Gateway still initializing (wait 30 seconds)"
    echo ""
    echo "Check gateway logs:"
    echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
fi

echo ""
echo "=========================================="
echo "IPv6 NAT FIX COMPLETE"
echo "=========================================="
echo ""
echo "Status: IPv6 NAT is now functional ($FIREWALL_TYPE)"
echo ""
echo "Next steps:"
echo "  1. Connect device to eth1 (if not already connected)"
echo "  2. Wait 30 seconds for auto-configuration"
echo "  3. Check status: gateway-status"
echo "  4. Verify socat: ps aux | grep socat"
echo "  5. View logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
echo "Test IPv6 proxy:"
echo "  From external IPv6 client:"
echo "  curl 'http://[<router-ipv6>]:8080'"
echo ""
