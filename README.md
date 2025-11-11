# IPv4↔IPv6 Dual-Stack Gateway - Complete Guide

**Flexible dual-stack gateway with per-device MAC registration for NanoPi R5C running OpenWrt**

A Python-based service that automatically discovers devices on eth1, learns their MAC addresses, spoofs them on eth0 to request DHCP (v4 and/or v6), and maintains transparent connectivity through IPv4, IPv6, or dual-stack networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Deployment](#-deployment)
- [Port Forwarding](#-port-forwarding)
- [Configuration](#️-configuration)
- [Monitoring](#-monitoring--management)
- [Troubleshooting](#-troubleshooting)
- [Advanced Topics](#-advanced-topics)

---

## 🎯 Overview

This gateway service provides **flexible dual-stack support** with **per-device MAC registration** on upstream firewalls. It automatically adapts to whatever network eth0 is connected to (IPv4, IPv6, or both) while providing a consistent IPv4 DHCP experience for devices on eth1.

### Use Case

Perfect for scenarios where:
- You have **hundreds of IPv4 devices** that need to connect through **firewall-protected networks**
- Device **MACs must be pre-registered** on the network firewall (IPv4, IPv6, or both)
- The upstream network could be **IPv4-only, IPv6-only, or dual-stack**
- You need a **zero-configuration solution** for end devices

**Real-world example:** Deploying legacy IoT devices or mobile devices to networks with strict firewall policies that only allow pre-registered MAC addresses.

### Network Topology

```
[Devices] ←→ eth1 (LAN) ←→ NanoPi Gateway ←→ eth0 (WAN) ←→ [Firewall] ←→ [Network]
          192.168.1.0/24    (MAC Spoofing)    DHCP v4/v6      (MAC Check)    IPv4/IPv6/Both
```

---

## 🚀 Quick Start

### Prerequisites

- **Hardware**: NanoPi R5C (or similar dual-NIC router)
- **OS**: OpenWrt (or any Linux with Python 3.7+)
- **Network**: IPv4, IPv6, or dual-stack network with firewall
- **Your Computer**: Bash shell, SSH access to router

### One-Command Deployment

```bash
# Clone or download this repository
cd /path/to/ipv6_ipv4_gateway_owrt

# Deploy to router (replace with your router's IP)
scp ipv4_ipv6_gateway.py gateway_config.py gateway_api_server.py \
    install.sh diagnose-and-fix.sh \
    gateway-status-direct.sh gateway-devices-direct.sh \
    setup-port-forwarding.sh \
    root@<router-ip>:/tmp/

# SSH and install
ssh root@<router-ip>
cd /tmp
chmod +x install.sh
./install.sh --full-auto
```

**What this does:**
1. ✅ Installs dependencies (Python, odhcp6c, udhcpc, iptables, etc.)
2. ✅ Installs the gateway service
3. ✅ Creates dual-stack network configuration
4. ✅ Applies network config
5. ✅ Starts the service
6. ✅ Installs helper commands (`gateway-status`, `gateway-port-forward`, etc.)

### Verify Installation

```bash
# Run comprehensive diagnostic
gateway-diagnose

# Check status
gateway-status-direct

# View logs
tail -f /var/log/ipv4-ipv6-gateway.log
```

---

## ✨ Features

### Core Capabilities
- **🌐 Dual-Stack Support**: Works with IPv4-only, IPv6-only, or dual-stack WAN networks
- **🔍 Automatic Discovery**: Monitors ARP table to discover devices as they connect
- **🎭 MAC Spoofing**: Spoofs device MACs on eth0 to request DHCPv4 and/or DHCPv6
- **🔄 Robust DHCP**: 10 retries for DHCPv4, 5 for DHCPv6 with exponential backoff
- **🔀 Transparent NAT**: Uses OpenWrt's native NAT for IPv4 traffic
- **🌉 464XLAT Ready**: Can use 464XLAT for IPv4↔IPv6 translation when needed

### Management & Monitoring
- **💾 Persistent Storage**: Device mappings saved to JSON with automatic backups
- **📊 REST API**: Monitor status and devices via HTTP endpoints (port 5050)
- **🔄 Auto-Recovery**: Automatic retry with exponential backoff, survives reboots
- **📝 Comprehensive Logging**: Detailed logs for troubleshooting
- **🛠️ CLI Tools**: Helper scripts for quick status checks
- **🔍 Diagnostic Tool**: Built-in diagnostic and automated fix capabilities
- **🌐 Port Forwarding**: Access IPv4 device services from IPv6 network (and vice versa)

### Console/KVM Support
- **🖥️ Direct Commands**: CLI tools that work without network (perfect for console access)
- **✅ No API Required**: `gateway-status-direct` and `gateway-devices-direct` work offline

---

## 🔄 How It Works

### Device Connection Flow

#### 1. **Device connects to eth1** (LAN)
```
iPhone → eth1
```

#### 2. **DHCP assigns LAN IP** (from gateway's dnsmasq)
```
iPhone gets 192.168.1.100
```

#### 3. **Gateway discovers MAC** (via ARP monitoring)
```
Detected: aa:bb:cc:dd:ee:ff
```

#### 4. **Gateway detects WAN protocols**
```
eth0 has: IPv4 ✓, IPv6 ✓  (dual-stack example)
```

#### 5. **Gateway spoofs MAC and requests DHCPv4** (if available)
```
eth0 MAC → aa:bb:cc:dd:ee:ff
udhcpc requests IPv4
Firewall sees registered MAC → allows
Gateway gets: 10.1.2.50 (10 retries with backoff)
```

#### 6. **Gateway spoofs MAC and requests DHCPv6** (if available)
```
eth0 MAC → aa:bb:cc:dd:ee:ff
odhcp6c requests IPv6
Firewall sees registered MAC → allows
Gateway gets: 2001:db8::1234 (5 retries with backoff)
```

#### 7. **Device fully configured**
```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ipv4_address": "192.168.1.100",      // LAN IPv4
  "ipv4_wan_address": "10.1.2.50",      // WAN IPv4
  "ipv6_address": "2001:db8::1234",     // WAN IPv6
  "status": "active"
}
```

### Supported Network Types

| Network Type | Detection | Behavior |
|--------------|-----------|----------|
| **IPv4-Only** | IPv4 ✓, IPv6 ✗ | Requests DHCPv4 only |
| **IPv6-Only** | IPv4 ✗, IPv6 ✓ | Requests DHCPv6 only |
| **Dual-Stack** | IPv4 ✓, IPv6 ✓ | Requests both protocols |

---

## 📦 Deployment

### Full Installation

```bash
# 1. Copy all files to router
scp ipv4_ipv6_gateway.py gateway_config.py gateway_api_server.py \
    install.sh diagnose-and-fix.sh \
    gateway-status-direct.sh gateway-devices-direct.sh \
    setup-port-forwarding.sh \
    root@<router-ip>:/tmp/

# 2. SSH to router
ssh root@<router-ip>
cd /tmp

# 3. Run full auto install
chmod +x install.sh
./install.sh --full-auto
```

### ⚠️ CRITICAL: Register Device MACs

**Before devices can obtain WAN addresses, their MACs must be registered with the upstream firewall!**

This is YOUR responsibility - the gateway cannot do this.

### Verify Installation

```bash
# Run comprehensive diagnostic
gateway-diagnose

# Check service status
gateway-status-direct

# Watch live logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Expected log sequence:
# [INFO] New device discovered: aa:bb:cc:dd:ee:ff (IPv4: 192.168.1.100)
# [INFO] Started discovery thread for aa:bb:cc:dd:ee:ff
# [INFO] Will attempt - DHCPv4: True, DHCPv6: True
# [INFO] Requesting DHCPv4 for aa:bb:cc:dd:ee:ff
# [DEBUG] DHCPv4 attempt 1/10
# [DEBUG] DHCPv4 request succeeded
# [INFO] Successfully obtained IPv4 10.1.2.50 for aa:bb:cc:dd:ee:ff
```

---

## 🌐 Port Forwarding

Access services on IPv4 devices from IPv6 network (or vice versa) using built-in port forwarding.

### Quick Setup

```bash
# Find device IP
gateway-devices-direct
# Shows: "ipv4_address": "192.168.1.100"

# Setup port forwarding for common ports
gateway-port-forward quick-device 192.168.1.100
```

**This creates:**
- Gateway:8080 → Device:80 (HTTP)
- Gateway:2323 → Device:23 (Telnet)
- Gateway:8443 → Device:443 (HTTPS)
- Gateway:2222 → Device:22 (SSH)

### Access from Client

**Dual-Stack or IPv4 Client:**
```bash
# HTTP
curl http://192.168.1.1:8080
# Opens device's web interface

# Telnet
telnet 192.168.1.1 2323
```

**IPv6-Only Client:**
```bash
# First, get gateway's IPv6 address:
ssh root@192.168.1.1 "ip -6 addr show eth0 | grep inet6 | grep -v fe80"
# Output: inet6 2001:db8::1/64

# Access via IPv6:
curl http://[2001:db8::1]:8080
telnet 2001:db8::1 2323
```

### Manual Port Forwarding

```bash
# Add specific ports:
gateway-port-forward add 8080 192.168.1.100 80   # HTTP
gateway-port-forward add 2323 192.168.1.100 23   # Telnet

# List active forwards:
gateway-port-forward list

# Remove a forward:
gateway-port-forward remove 8080 192.168.1.100 80
```

### IPv6-Only Clients

For IPv6-only clients to access IPv4 devices, use the IPv6 port forwarding script:

```bash
# Copy to gateway:
scp setup-ipv6-port-forwarding.sh root@192.168.1.1:/tmp/

# Enable IPv6 port forwarding:
ssh root@192.168.1.1
cd /tmp
chmod +x setup-ipv6-port-forwarding.sh
./setup-ipv6-port-forwarding.sh enable 192.168.1.100

# This sets up:
# - IPv6 firewall rules
# - NAT64 (if Tayga available)
# - Port forwards

# Access from IPv6 client:
curl http://[<gateway-ipv6>]:8080
```

---

## ⚙️ Configuration

### DHCP Retry Settings

The gateway uses robust retry logic optimized for upstream firewall MAC registration lag:

```python
# /opt/ipv4-ipv6-gateway/gateway_config.py

# DHCPv4 (Critical - more retries)
DHCPV4_TIMEOUT = 15           # 15 seconds per attempt
DHCPV4_RETRY_COUNT = 10       # 10 attempts (handles MAC registration lag)
DHCPV4_RETRY_DELAY = 5        # Exponential backoff from 5s

# DHCPv6 (Optional - fewer retries)
DHCPV6_TIMEOUT = 10           # 10 seconds per attempt
DHCPV6_RETRY_COUNT = 5        # 5 attempts
DHCPV6_RETRY_DELAY = 5        # Exponential backoff from 5s
```

**Worst case timing:**
- DHCPv4: ~2.5 minutes (enough for firewall registration)
- DHCPv6: ~1 minute (optional protocol)

### Network Configuration

```uci
# eth1 (LAN) - IPv4 devices side
config interface 'lan'
    option device 'eth1'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'

# eth0 (WAN) - Dual-stack
config interface 'wan'
    option device 'eth0'
    option proto 'dhcp'          # DHCPv4

config interface 'wan6'
    option device 'eth0'
    option proto 'dhcpv6'        # DHCPv6
    option reqaddress 'try'
    option reqprefix 'auto'
```

### Firewall Configuration

NAT/masquerading enabled automatically:

```uci
config zone 'wan'
    option masq '1'              # NAT enabled
    option mtu_fix '1'

config forwarding
    option src 'lan'
    option dest 'wan'
```

---

## 📊 Monitoring & Management

### CLI Tools

```bash
# API-based (requires network):
gateway-status              # Overall status
gateway-devices             # List all devices
gateway-devices active      # Active devices only

# Direct (works without network, perfect for console/KVM):
gateway-status-direct       # Status without API
gateway-devices-direct      # Devices without API

# Management:
gateway-diagnose            # Full diagnostic
gateway-diagnose --fix-all  # Apply all fixes
gateway-port-forward        # Port forwarding management
```

### REST API

The gateway provides a REST API on port 5050:

```bash
# Health check
curl http://192.168.1.1:5050/health

# Gateway status
curl http://192.168.1.1:5050/status

# List all devices
curl http://192.168.1.1:5050/devices

# Filter by status
curl http://192.168.1.1:5050/devices?status=active
```

### Service Management

**OpenWrt (init.d):**
```bash
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway stop
/etc/init.d/ipv4-ipv6-gateway restart
/etc/init.d/ipv4-ipv6-gateway status

# Enable/disable auto-start
/etc/init.d/ipv4-ipv6-gateway enable
/etc/init.d/ipv4-ipv6-gateway disable
```

---

## 🔍 Troubleshooting

### Quick Diagnostic

**Always start with the diagnostic tool:**

```bash
# Run comprehensive diagnostic (14 checks)
gateway-diagnose

# Apply fixes automatically
gateway-diagnose --fix-all
```

### Common Issues

#### 1. Device Not Getting DHCP on LAN

**Symptom:** Device connected to eth1 doesn't get 192.168.1.x address

**Fix:**
```bash
# Check if dnsmasq is running
ps | grep dnsmasq

# Check eth1 has correct IP
ip addr show eth1 | grep "inet "
# Should show: inet 192.168.1.1/24

# Apply network fix
gateway-diagnose --fix-network
```

#### 2. MAC Not Getting WAN Address

**Symptom:** Device discovered but no WAN IPv4/IPv6 assigned

**Cause:** MAC not registered with firewall (most common)

**Fix:**
```bash
# 1. REGISTER THE MAC WITH YOUR FIREWALL!
#    This is YOUR responsibility - the gateway cannot do this

# 2. Check logs for DHCP errors
tail -50 /var/log/ipv4-ipv6-gateway.log | grep ERROR

# 3. Verify protocols detected
gateway-status-direct

# 4. Wait for retries
# With 10 DHCPv4 retries, it may take up to 2.5 minutes
# This allows time for firewall MAC registration to propagate
```

#### 3. Gateway Service Won't Start

**Fix:**
```bash
# Check for errors
/etc/init.d/ipv4-ipv6-gateway start

# View logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Run diagnostic
gateway-diagnose --fix-all
```

#### 4. Port Forwarding Not Working

**Symptom:** Can't access device services from network

**Check client type:**
```bash
# On your client:
ip addr show | grep -E "inet |inet6"

# If you see both → Dual-stack (use IPv4)
# If only inet6 → IPv6-only (need IPv6 port forwarding)
# If only inet → IPv4-only (use IPv4)
```

**For dual-stack or IPv4 clients:**
```bash
# Check forwards are active
gateway-port-forward list

# Test from gateway
curl http://192.168.1.1:8080

# Test from client
curl http://192.168.1.1:8080
```

**For IPv6-only clients:**
```bash
# Use IPv6 port forwarding script
./setup-ipv6-port-forwarding.sh enable 192.168.1.100

# Access via IPv6
curl http://[<gateway-ipv6>]:8080
```

#### 5. Console/KVM Access

**Symptom:** Can't check status from console (network not available)

**Solution:** Use direct commands:
```bash
# These work without network:
gateway-status-direct
gateway-devices-direct
tail -f /var/log/ipv4-ipv6-gateway.log
```

---

## 🔧 Advanced Topics

### File Structure

```
/opt/ipv4-ipv6-gateway/           # Service installation
├── ipv4_ipv6_gateway.py          # Main service
├── gateway_config.py             # Configuration
└── gateway_api_server.py         # REST API server

/etc/ipv4-ipv6-gateway/           # Configuration directory
├── devices.json                  # Device mappings (persistent)
├── network-config.uci            # Network config template
├── dhcp-config.uci               # DHCP config template
└── firewall-config.uci           # Firewall config template

/usr/bin/                         # Helper scripts
├── gateway-status                # API-based status
├── gateway-status-direct         # Direct status (no API)
├── gateway-devices               # API-based devices
├── gateway-devices-direct        # Direct devices (no API)
├── gateway-diagnose              # Diagnostic tool
└── gateway-port-forward          # Port forwarding
```

### Security Considerations

#### API Access

By default, the API listens on `0.0.0.0:5050` (all interfaces).

**To restrict to localhost:**
```python
# Edit /opt/ipv4-ipv6-gateway/gateway_config.py
API_HOST = '127.0.0.1'  # Localhost only
```

**⚠️ WARNING**: The API has no authentication. Only expose to trusted networks.

#### MAC Spoofing

This service spoofs MAC addresses to request DHCP. Ensure:
- You have authorization to use MAC spoofing on your network
- Your firewall is configured to expect this behavior
- Device MACs are properly registered

### Performance Tuning

```python
# Edit /opt/ipv4-ipv6-gateway/gateway_config.py

# Faster discovery (uses more CPU)
ARP_MONITOR_INTERVAL = 5        # Check every 5s

# Slower discovery (uses less CPU)
ARP_MONITOR_INTERVAL = 30       # Check every 30s

# Adjust timeouts for slower networks
DHCPV4_TIMEOUT = 20             # Increase from 15s
DHCPV4_RETRY_COUNT = 15         # More retries for very slow networks

# Increase max devices
MAX_DEVICES = 2000              # Default: 1000
```

### Uninstallation

```bash
# Basic uninstall (leaves network config unchanged)
bash uninstall.sh

# Uninstall AND restore original network config
bash uninstall.sh --restore-network
```

---

## 🎯 Important Fixes Included

This version includes **three critical bug fixes**:

### Fix #1: DHCPv4 IP Application
- **Problem**: udhcpc succeeded but IP not applied to eth0
- **Solution**: Removed `-s /bin/true` flag from udhcpc command
- ✅ **Status**: Fixed

### Fix #2: Protocol Detection
- **Problem**: Protocol detection checked if eth0 had addresses (chicken-egg problem)
- **Solution**: Always attempt both DHCPv4 and DHCPv6 based on availability
- ✅ **Status**: Fixed

### Fix #3: Thread Debugging
- **Problem**: Thread creation failures were silent
- **Solution**: Added comprehensive logging for thread lifecycle
- ✅ **Status**: Fixed

### Enhanced Retry Configuration
- **DHCPv4**: 3 → 10 retries (handles firewall MAC registration lag)
- **DHCPv4 timeout**: 10s → 15s (slower servers)
- **DHCPv6**: 3 → 5 retries (reasonable for optional protocol)
- ✅ **Total max time**: ~2.5 minutes per device (robust for slow networks)

---

## ✅ Pre-Deployment Checklist

- [ ] **Register device MACs with firewall** ⚠️ CRITICAL
- [ ] Deploy gateway to router
- [ ] Verify network config applied (`ip addr show`)
- [ ] Verify service running (`gateway-status-direct`)
- [ ] Connect test device to eth1
- [ ] Verify device discovered (`gateway-devices-direct`)
- [ ] Wait for DHCP (up to 2.5 min for DHCPv4 with retries)
- [ ] Verify WAN addresses obtained (check logs)
- [ ] Test connectivity (ping from device)
- [ ] (Optional) Setup port forwarding for device services

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| **Deploy** | `./install.sh --full-auto` |
| **Status** | `gateway-status-direct` |
| **Devices** | `gateway-devices-direct` |
| **Logs** | `tail -f /var/log/ipv4-ipv6-gateway.log` |
| **Diagnose** | `gateway-diagnose` |
| **Fix All** | `gateway-diagnose --fix-all` |
| **Port Forward** | `gateway-port-forward quick-device <ip>` |
| **Restart** | `/etc/init.d/ipv4-ipv6-gateway restart` |

---

## 🎉 What's Included

✅ **IPv4-only networks**
✅ **IPv6-only networks**
✅ **Dual-stack networks**
✅ **Per-device MAC registration**
✅ **Automatic protocol detection**
✅ **Robust DHCP retry logic** (10 retries DHCPv4, 5 retries DHCPv6)
✅ **Transparent NAT**
✅ **Port forwarding** (IPv4 ↔ IPv6)
✅ **REST API monitoring**
✅ **Console/KVM support** (direct commands)
✅ **Comprehensive logging**
✅ **Diagnostic tools**
✅ **Auto-recovery**
✅ **All critical bugs fixed**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OpenWrt** project for the excellent embedded Linux distribution
- **odhcp6c** for DHCPv6 client functionality
- **udhcpc** (busybox) for DHCPv4 client functionality
- **464XLAT** for IPv4/IPv6 translation

---

**Made with ❤️ for flexible dual-stack networking with MAC-based firewall registration**
