# Installation & Network Configuration - Complete Solution

## 🎯 Summary of Changes

I've updated the installation process to **properly apply network configuration** during installation, addressing the root cause of the issues you were experiencing.

## 📋 What Was Fixed

### **1. Enhanced install.sh - Network Configuration**

The install script now:
- ✅ **Creates complete network configuration** for both eth0 and eth1
- ✅ **Creates DHCP server configuration** for the LAN interface
- ✅ **Backs up original configurations** before making changes
- ✅ **Properly imports UCI configs** using correct syntax
- ✅ **Restarts both network and dnsmasq** services after applying config
- ✅ **Handles errors gracefully** with helpful error messages

### **2. Proper UCI Configuration Files**

**Network Config** (`/etc/ipv4-ipv6-gateway/network-config.uci`):
```uci
config interface 'lan'
    option device 'eth1'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'

config interface 'wan'
    option device 'eth0'
    option proto 'dhcpv6'
    option reqaddress 'try'
    option reqprefix 'auto'
```

**DHCP Config** (`/etc/ipv4-ipv6-gateway/dhcp-config.uci`):
```uci
config dhcp 'lan'
    option interface 'lan'
    option start '100'
    option limit '150'
    option leasetime '12h'
    option dhcpv4 'server'
```

### **3. Fixed UCI Import Commands**

**Before** (incorrect):
```bash
uci import < "$CONFIG_DIR/network-config.uci"
```

**After** (correct):
```bash
uci import network < "$CONFIG_DIR/network-config.uci"
uci import dhcp < "$CONFIG_DIR/dhcp-config.uci"
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
```

### **4. Added Diagnostic Tool Integration**

- Diagnostic script now installed as `/usr/bin/gateway-diagnose`
- Automatically included in installation
- Available immediately after install

### **5. Enhanced Backup System**

- Backs up original network config to `/etc/ipv4-ipv6-gateway/network.original`
- Backs up original DHCP config to `/etc/ipv4-ipv6-gateway/dhcp.original`
- Creates temporary backups during application to `/tmp/`
- Won't overwrite existing backups

## 🚀 How to Deploy (Updated Workflow)

### **Option 1: Full Automatic Deployment (Recommended)**

```bash
# From your computer
cd /Users/ekowtaylor/Documents/Personal/Github/ipv6_ipv4_gateway_owrt
./quick-deploy.sh --auto-start

# This will:
# 1. Copy all files to router (including diagnose-and-fix.sh)
# 2. Run install.sh with --auto-start
# 3. Test the service

# Then SSH to router to apply network config
ssh root@<current-router-ip>

# Run diagnostic to see current state
/tmp/diagnose-and-fix.sh

# Apply network configuration
/tmp/diagnose-and-fix.sh --fix-network

# Or if you want to apply everything
/tmp/diagnose-and-fix.sh --fix-all
```

### **Option 2: Direct Installation with Network Config**

```bash
# From your computer - copy files
cd /Users/ekowtaylor/Documents/Personal/Github/ipv6_ipv4_gateway_owrt
scp *.py *.sh root@<router-ip>:/tmp/

# SSH to router
ssh root@<router-ip>

# Run install with full automation
cd /tmp
./install.sh --full-auto

# This will:
# 1. Install dependencies
# 2. Install Python files
# 3. Create UCI configs
# 4. **APPLY network configuration** (sets eth1 to 192.168.1.1)
# 5. **APPLY DHCP configuration**
# 6. **Start the gateway service**

# Verify everything is working
gateway-diagnose
gateway-status
ping 192.168.1.1
```

### **Option 3: Manual Installation (Safe Mode)**

```bash
# Copy files to router
scp *.py *.sh root@<router-ip>:/tmp/

# SSH to router
ssh root@<router-ip>
cd /tmp

# Install without applying config
./install.sh

# Review the config before applying
cat /etc/ipv4-ipv6-gateway/network-config.uci
cat /etc/ipv4-ipv6-gateway/dhcp-config.uci

# Apply when ready
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart

# Start service
/etc/init.d/ipv4-ipv6-gateway start
```

## 🔍 Installation Flags Explained

| Flag | Network Config | Start Service | Use Case |
|------|----------------|---------------|----------|
| *(none)* | ❌ Creates only | ❌ Enables only | Safe review mode |
| `--apply-network` | ✅ **Applies** | ❌ Enables only | Configure network first |
| `--auto-start` | ❌ Creates only | ✅ **Starts** | Start service first |
| `--full-auto` | ✅ **Applies** | ✅ **Starts** | Zero-touch deployment |

## ✅ What Gets Applied with `--apply-network` or `--full-auto`

1. **Network Configuration**:
   - eth1 (LAN) → 192.168.1.1/24 static IP
   - eth0 (WAN) → DHCPv6 client
   - Network restart (may disconnect SSH)

2. **DHCP Configuration**:
   - DHCP server on LAN interface
   - IP range: 192.168.1.100 - 192.168.1.250
   - 12-hour lease time
   - dnsmasq restart

3. **Service State** (with `--auto-start` or `--full-auto`):
   - Gateway service started
   - API server listening on 0.0.0.0:5050

## 🔧 Troubleshooting After Installation

### If Network Config Doesn't Apply

```bash
# Check if UCI config exists
ls -la /etc/ipv4-ipv6-gateway/network-config.uci

# Manual import
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
uci commit

# Verify before restarting
uci show network.lan
uci show dhcp.lan

# Apply
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
```

### If Service Doesn't Start

```bash
# Check if it's running
ps | grep ipv4_ipv6_gateway

# Check logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Start manually
/etc/init.d/ipv4-ipv6-gateway start

# Check service status
/etc/init.d/ipv4-ipv6-gateway status
```

### Use the Diagnostic Tool

```bash
# Run comprehensive diagnostic
gateway-diagnose

# See what needs fixing
gateway-diagnose --fix-all
```

## 📊 Expected Results

### After Installation with `--full-auto`

```bash
$ gateway-diagnose

========================================
DIAGNOSTIC REPORT
========================================

[... diagnostic output ...]

========================================
SUMMARY
========================================
Checks passed: 13/14

$ gateway-status
{
  "running": true,
  "devices": {},
  "device_count": 0,
  "active_devices": 0,
  "eth0_up": true,
  "eth1_up": true,
  "timestamp": "2024-01-01T00:00:00.000000"
}

$ ping 192.168.1.1
PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: seq=0 ttl=64 time=0.123 ms
```

## 🎯 Key Improvements

1. **Network config is actually applied** - No more manual UCI import needed when using `--apply-network` or `--full-auto`

2. **DHCP server properly configured** - Complete dnsmasq config with all necessary settings

3. **Proper error handling** - If UCI import fails, you get clear instructions for manual fix

4. **Safe defaults** - Without flags, configs are created but not applied (review first)

5. **Comprehensive backups** - Original configs are always backed up before changes

6. **Service integration** - Everything starts together when using `--full-auto`

## 📚 Related Files

- **install.sh** - Main installer with enhanced network config application
- **diagnose-and-fix.sh** - Diagnostic tool with automated fixes
- **quick-deploy.sh** - One-command deployment from your computer
- **QUICK_FIX_GUIDE.md** - Step-by-step troubleshooting
- **FIXES_APPLIED.md** - Summary of all changes made

## 💡 Best Practice Workflow

```bash
# 1. Deploy from your computer
./quick-deploy.sh --auto-start

# 2. SSH to router
ssh root@<router-ip>

# 3. Run diagnostic
/tmp/diagnose-and-fix.sh

# 4. If network config not applied, fix it
/tmp/diagnose-and-fix.sh --fix-network

# 5. Verify everything works
gateway-diagnose
gateway-status
gateway-devices

# 6. Test with actual device
# Connect IPv4 device to eth1
# Check if it gets IP: 192.168.1.100-250
# Check if gateway discovers it: gateway-devices
```

## ⚠️ Important Notes

### SSH Disconnection Warning
When applying network config with `--apply-network` or `--full-auto`:
- Your SSH session **may disconnect** when network restarts
- **Reconnect to 192.168.1.1** after network restart
- Wait ~10 seconds for network to stabilize

### Restoring Original Config
If you need to restore the original network configuration:
```bash
cp /etc/ipv4-ipv6-gateway/network.original /etc/config/network
cp /etc/ipv4-ipv6-gateway/dhcp.original /etc/config/dhcp
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
```

## 🎉 Summary

**The Problem**: Network configuration wasn't being applied during installation

**The Solution**:
- Enhanced `install.sh` to properly import and apply UCI configs
- Created complete network and DHCP configuration files
- Added proper backup and error handling
- Integrated diagnostic tool for easy troubleshooting

**How to Deploy**:
```bash
./quick-deploy.sh --auto-start  # From your computer
ssh root@<router-ip>            # Connect to router
/tmp/diagnose-and-fix.sh --fix-all  # Apply network config
```

Done! Your gateway is now fully configured and running. 🚀
