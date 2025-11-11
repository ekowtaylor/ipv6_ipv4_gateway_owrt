# IPv4↔IPv6 Dual-Stack Gateway - Complete Guide

**Flexible dual-stack gateway with per-device MAC registration for NanoPi R5C running OpenWrt**

A Python-based service that automatically discovers devices on eth1, learns their MAC addresses, spoofs them on eth0 to request DHCP (v4 and/or v6), and maintains transparent connectivity through IPv4, IPv6, or dual-stack networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Use Case](#-use-case)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [How It Works](#-how-it-works)
- [Supported Networks](#-supported-network-types)
- [Deployment](#-deployment)
- [Usage](#-usage)
- [Configuration](#️-configuration)
- [Monitoring](#-monitoring--management)
- [Troubleshooting](#-troubleshooting)
- [Advanced Topics](#-advanced-topics)

---

## 🎯 Overview

This gateway service provides **flexible dual-stack support** with **per-device MAC registration** on upstream firewalls. It automatically adapts to whatever network eth0 is connected to (IPv4, IPv6, or both) while providing a consistent IPv4 DHCP experience for devices on eth1.

### Key Requirement

**Device MACs must be pre-registered with the upstream firewall** to obtain DHCP addresses. The gateway spoofs each device's MAC on eth0 to trigger firewall registration before assigning addresses.

---

## 🎯 Use Case

Perfect for scenarios where:
- You have **hundreds of IPv4 devices** that need to connect through **firewall-protected networks**
- Device **MACs must be pre-registered** on the network firewall (IPv4, IPv6, or both)
- The upstream network could be **IPv4-only, IPv6-only, or dual-stack**
- You need a **zero-configuration solution** for end devices
- You're deploying to environments where manual configuration isn't feasible

**Real-world example:** Deploying legacy IoT devices or mobile devices to networks with strict firewall policies that only allow pre-registered MAC addresses.

---

## ✨ Features

### Gateway Capabilities
- **🌐 Dual-Stack Support**: Works with IPv4-only, IPv6-only, or dual-stack WAN networks
- **🔍 Automatic Discovery**: Monitors ARP table to discover devices as they connect
- **🎭 MAC Spoofing**: Spoofs device MACs on eth0 to request DHCPv4 and/or DHCPv6
- **🔄 Protocol Detection**: Automatically detects available protocols (IPv4/IPv6) on WAN
- **📡 DHCP Dual Client**: Requests both DHCPv4 and DHCPv6 based on WAN availability
- **🔀 Transparent NAT**: Uses OpenWrt's native NAT for IPv4 traffic
- **🌉 464XLAT Ready**: Can use 464XLAT for IPv4↔IPv6 translation when needed

### Management & Monitoring
- **💾 Persistent Storage**: Device mappings saved to JSON with automatic backups
- **📊 REST API**: Monitor status and devices via HTTP endpoints (port 5050)
- **🔄 Auto-Recovery**: Automatic retry with exponential backoff, survives reboots
- **📝 Comprehensive Logging**: Detailed logs for troubleshooting
- **🛠️ CLI Tools**: Helper scripts for quick status checks
- **🔍 Diagnostic Tool**: Built-in diagnostic and automated fix capabilities

---

## 📐 Architecture

### Network Topology

```
[Devices] ←→ eth1 (LAN) ←→ NanoPi Gateway ←→ eth0 (WAN) ←→ [Firewall] ←→ [Network]
          192.168.1.0/24    (MAC Spoofing)    DHCP v4/v6      (MAC Check)    IPv4/IPv6/Both
```

### The Complete Flow

```
IPv4 Device → eth1 → Gateway (learns MAC) → eth0 (spoofs MAC) → Firewall → Network
             (192.168.1.x)                   (requests DHCP)   (checks MAC)  (IPv4/IPv6/both)
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Gateway Service                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ARP Monitor   │  │DHCPv4Manager │  │DHCPv6Manager │          │
│  │(eth1)        │  │(eth0)        │  │(eth0)        │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
│         └─────────────────┴──────────────────┘                   │
│                           │                                       │
│                  ┌────────▼────────┐                             │
│                  │ Device Mapping  │                             │
│                  │    Storage      │                             │
│                  └─────────────────┘                             │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              REST API Server (port 5050)              │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Hardware**: NanoPi R5C (or similar dual-NIC router)
- **OS**: OpenWrt (or any Linux with Python 3.7+)
- **Network**: IPv4, IPv6, or dual-stack network with firewall
- **Your Computer**: Bash shell, SSH access to router

### Automated Deployment

**Recommended method** - Deploy in one command:

```bash
# Clone or download this repository
cd /path/to/ipv6_ipv4_gateway_owrt

# Deploy to router (replace with your router's IP)
./quick-deploy.sh root@<router-ip> --full-auto
```

**What this does:**
1. ✅ Copies all files to router
2. ✅ Installs dependencies (Python, odhcp6c, udhcpc, iptables, etc.)
3. ✅ Installs the gateway service
4. ✅ Creates dual-stack network configuration
5. ✅ Applies network config
6. ✅ Starts the service

### Manual Installation

```bash
# 1. Copy files to router
scp *.py *.sh root@<router-ip>:/tmp/

# 2. SSH to router
ssh root@<router-ip>
cd /tmp

# 3. Run installation with full automation
./install.sh --full-auto

# 4. Verify installation
gateway-diagnose
```

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
Gateway gets: 10.1.2.50
```

#### 6. **Gateway spoofs MAC and requests DHCPv6** (if available)
```
eth0 MAC → aa:bb:cc:dd:ee:ff
odhcp6c requests IPv6
Firewall sees registered MAC → allows
Gateway gets: 2001:db8::1234
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

#### 8. **Traffic flows transparently**
- Device sends to 192.168.1.1 (gateway)
- Gateway NATs through appropriate WAN address(es)
- Response returns to device seamlessly

### Discovery Process Diagram

```
Device Connects
       │
       ▼
ARP Monitoring (10s interval)
       │
       ▼
New MAC Detected
       │
       ▼
Detect WAN Protocols
       │
       ├────────────┬────────────┐
       │            │            │
  IPv4 Available  IPv6 Available Both
       │            │            │
       ▼            ▼            ▼
  Request DHCPv4  Request DHCPv6  Request Both
       │            │            │
       ▼            ▼            ▼
  Get IPv4 WAN   Get IPv6 WAN   Get Both
       │            │            │
       └────────────┴────────────┘
                    │
                    ▼
            Device Active
                    │
                    ▼
          NAT Traffic Flow
```

---

## 🌐 Supported Network Types

### ✅ IPv4-Only Network
```
eth0 connected to IPv4-only network
↓
Gateway detects: IPv4 ✓, IPv6 ✗
↓
Requests DHCPv4 only (spoofs MAC)
↓
Device gets WAN IPv4 address
↓
Traffic uses IPv4 NAT
```

**Use case:** Traditional enterprise networks, older ISPs

### ✅ IPv6-Only Network
```
eth0 connected to IPv6-only network
↓
Gateway detects: IPv4 ✗, IPv6 ✓
↓
Requests DHCPv6 only (spoofs MAC)
↓
Device gets WAN IPv6 address
↓
Traffic uses IPv6 (464XLAT for IPv4 apps)
```

**Use case:** Modern ISPs, mobile networks, IPv6-native deployments

### ✅ Dual-Stack Network (Most Common)
```
eth0 connected to dual-stack network
↓
Gateway detects: IPv4 ✓, IPv6 ✓
↓
Requests BOTH DHCPv4 AND DHCPv6 (spoofs MAC)
↓
Device gets both WAN IPv4 + IPv6 addresses
↓
Traffic uses both protocols (prefer IPv4)
```

**Use case:** Modern enterprise networks, ISPs with transition strategy

---

## 📦 Deployment

### Step 1: Deploy to Router

```bash
# On your development machine:
./quick-deploy.sh root@<router-ip> --full-auto
```

This automatically:
- Copies all files
- Installs dependencies
- Configures dual-stack network
- Starts service

### Step 2: Verify Installation

```bash
# SSH to router
ssh root@<router-ip>

# Run comprehensive diagnostic
gateway-diagnose

# Expected output:
#  ✓ eth1 has 192.168.1.1/24
#  ✓ Gateway service is running
#  ✓ API server responding
#  ✓ All checks passed
```

### Step 3: Register Device MACs ⚠️ CRITICAL

**Before devices can obtain WAN addresses, their MACs must be registered with the upstream firewall!**

```bash
# This is YOUR responsibility - register each device MAC
# with your firewall/network administrator before deployment

# Example MACs to register:
# - aa:bb:cc:dd:ee:01
# - aa:bb:cc:dd:ee:02
# - aa:bb:cc:dd:ee:03
```

### Step 4: Connect Test Device

```bash
# Connect a device to eth1 physical port
# Watch logs in real-time:
tail -f /var/log/ipv4-ipv6-gateway.log

# Expected log output:
# [INFO] New device discovered: aa:bb:cc:dd:ee:ff (IPv4: 192.168.1.100)
# [INFO] WAN protocols detected - IPv4: True, IPv6: True
# [INFO] Requesting DHCPv4 for aa:bb:cc:dd:ee:ff (WAN has IPv4)
# [INFO] Successfully obtained IPv4 10.1.2.50 for MAC aa:bb:cc:dd:ee:ff
# [INFO] Requesting DHCPv6 for aa:bb:cc:dd:ee:ff (WAN has IPv6)
# [INFO] Successfully obtained IPv6 2001:db8::1234 for MAC aa:bb:cc:dd:ee:ff
# [INFO] Device aa:bb:cc:dd:ee:ff successfully configured - IPv4: 10.1.2.50, IPv6: 2001:db8::1234
```

### Step 5: Test Connectivity

```bash
# From your test device (connected to eth1):

# Test LAN connectivity
ping 192.168.1.1

# Test external IPv4 (if WAN has IPv4)
ping 8.8.8.8

# Test external IPv6 (if WAN has IPv6)
ping6 2001:4860:4860::8888

# All should work!
```

---

## 📖 Usage

### Check Gateway Status

```bash
# Quick status check
gateway-status

# Example output:
{
  "running": true,
  "device_count": 5,
  "active_devices": 3,
  "eth0_up": true,
  "eth1_up": true,
  "devices": {...}
}
```

### List Devices

```bash
# List all devices
gateway-devices

# List active devices only
gateway-devices active

# List inactive devices
gateway-devices inactive

# Example output:
{
  "total": 3,
  "devices": [
    {
      "mac_address": "aa:bb:cc:dd:ee:01",
      "ipv4_address": "192.168.1.100",
      "ipv4_wan_address": "10.1.2.50",
      "ipv6_address": "2001:db8::1234",
      "status": "active",
      "discovered_at": "2024-01-01T12:00:00",
      "last_seen": "2024-01-01T12:05:00"
    }
  ]
}
```

### Monitor Logs

```bash
# Real-time logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Search for specific MAC
grep "aa:bb:cc:dd:ee:ff" /var/log/ipv4-ipv6-gateway.log

# Check for errors
grep -i error /var/log/ipv4-ipv6-gateway.log

# Watch device discovery
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i discover
```

### Diagnostic Tool

```bash
# Run comprehensive diagnostic (14 checks)
gateway-diagnose

# Apply network configuration fix
gateway-diagnose --fix-network

# Restart gateway service
gateway-diagnose --fix-service

# Apply all fixes automatically
gateway-diagnose --fix-all
```

**What it checks:**
- ✅ Network configuration (eth0/eth1)
- ✅ IP address assignments
- ✅ DHCP server status
- ✅ Gateway service status
- ✅ API server connectivity
- ✅ Firewall and forwarding settings

---

## ⚙️ Configuration

### Network Configuration

The installer creates dual-stack network config at `/etc/ipv4-ipv6-gateway/network-config.uci`:

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

**Apply changes:**
```bash
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci commit
/etc/init.d/network restart
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

### Service Settings

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Network interfaces
ETH0_INTERFACE = 'eth0'  # WAN (network side)
ETH1_INTERFACE = 'eth1'  # LAN (devices side)

# Monitoring intervals
ARP_MONITOR_INTERVAL = 10       # Check for new devices every 10s
DEVICE_MONITOR_INTERVAL = 30    # Update status every 30s

# DHCPv4 settings
DHCPV4_TIMEOUT = 10             # Wait 10s for DHCPv4 response
DHCPV4_RETRY_COUNT = 3          # Retry 3 times on failure
DHCPV4_RETRY_DELAY = 5          # Initial delay: 5s

# DHCPv6 settings
DHCPV6_TIMEOUT = 10             # Wait 10s for DHCPv6 response
DHCPV6_RETRY_COUNT = 3          # Retry 3 times on failure
DHCPV6_RETRY_DELAY = 5          # Initial delay: 5s

# API Server
API_ENABLED = True
API_HOST = '0.0.0.0'            # Bind to all interfaces
API_PORT = 5050
```

---

## 📊 Monitoring & Management

### CLI Tools

```bash
gateway-status              # Overall status
gateway-devices             # List all devices
gateway-devices active      # Active devices only
gateway-diagnose            # Full diagnostic
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

# Get specific device by MAC
curl http://192.168.1.1:5050/devices/aa:bb:cc:dd:ee:01

# Export device mappings (admin)
curl -X POST http://192.168.1.1:5050/admin/export > backup.json

# Clear device cache (admin)
curl -X POST http://192.168.1.1:5050/admin/clear-cache \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'
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
# Run comprehensive diagnostic
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

# Check DHCP leases
cat /tmp/dhcp.leases

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
gateway-status | grep -A2 eth0

# 4. Test DHCP manually
# For IPv4:
udhcpc -i eth0 -n -q -f
# For IPv6:
odhcp6c -P 0 eth0
```

#### 3. Gateway Service Won't Start

**Symptom:** Service fails to start or crashes

**Fix:**
```bash
# Check for errors
/etc/init.d/ipv4-ipv6-gateway start

# View logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Run diagnostic
gateway-diagnose --fix-all

# Check dependencies
opkg list-installed | grep python3
opkg list-installed | grep odhcp6c
opkg list-installed | grep busybox  # includes udhcpc
```

#### 4. API Not Responding

**Symptom:** API endpoints return connection refused

**Fix:**
```bash
# Test API connectivity
curl -v http://127.0.0.1:5050/health
curl -v http://192.168.1.1:5050/health

# Check if API is listening
netstat -tlnp | grep 5050

# Check service is running
ps | grep ipv4_ipv6_gateway

# Check logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i api
```

#### 5. Only IPv4 or IPv6 Working (Not Both)

**Symptom:** Devices only get one type of WAN address

**This is expected behavior!** The gateway adapts to WAN network:

```bash
# Check what's available on WAN
ip addr show eth0

# If you see only IPv4 addresses:
# → Gateway will only request DHCPv4

# If you see only IPv6 addresses:
# → Gateway will only request DHCPv6

# If you see both:
# → Gateway will request both DHCPv4 and DHCPv6
```

---

## 🔧 Advanced Topics

### File Structure

```
/opt/ipv4-ipv6-gateway/           # Service installation
├── ipv4_ipv6_gateway.py          # Main service (dual-stack!)
├── gateway_config.py             # Configuration
└── gateway_api_server.py         # REST API server

/etc/ipv4-ipv6-gateway/           # Configuration directory
├── devices.json                  # Device mappings (persistent)
├── network-config.uci            # Network config template
├── dhcp-config.uci               # DHCP config template
└── firewall-config.uci           # Firewall config template

/var/log/                         # Logs
└── ipv4-ipv6-gateway.log         # Service logs

/usr/bin/                         # Helper scripts
├── gateway-status                # Quick status check
├── gateway-devices               # List devices
└── gateway-diagnose              # Diagnostic tool

/etc/init.d/                      # Service scripts
└── ipv4-ipv6-gateway             # Init.d script
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

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Faster discovery (uses more CPU)
ARP_MONITOR_INTERVAL = 5        # Check every 5s

# Slower discovery (uses less CPU)
ARP_MONITOR_INTERVAL = 30       # Check every 30s

# Adjust timeouts
DHCPV4_TIMEOUT = 15             # Slower networks
DHCPV6_TIMEOUT = 15

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

## ✅ Pre-Deployment Checklist

- [ ] **Register device MACs with firewall** ⚠️ CRITICAL
- [ ] Deploy gateway to router (`./quick-deploy.sh`)
- [ ] Verify network config applied (`ip addr show`)
- [ ] Verify service running (`gateway-status`)
- [ ] Connect test device to eth1
- [ ] Verify device discovered (`gateway-devices`)
- [ ] Verify WAN addresses obtained (check logs)
- [ ] Test connectivity (ping from device)

---

## 🎉 What's Included

The gateway is **fully functional** and supports:

✅ **IPv4-only networks**
✅ **IPv6-only networks**
✅ **Dual-stack networks**
✅ **Per-device MAC registration**
✅ **Automatic protocol detection**
✅ **Dual DHCP (v4 + v6)**
✅ **Transparent NAT**
✅ **464XLAT ready**
✅ **REST API monitoring**
✅ **Comprehensive logging**
✅ **Diagnostic tools**
✅ **Auto-recovery**

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Deploy | `./quick-deploy.sh root@<ip> --full-auto` |
| Status | `gateway-status` |
| Devices | `gateway-devices` |
| Logs | `tail -f /var/log/ipv4-ipv6-gateway.log` |
| Diagnose | `gateway-diagnose` |
| Restart | `/etc/init.d/ipv4-ipv6-gateway restart` |
| API | `http://192.168.1.1:5050/status` |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

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

## 📞 Support

- **Issues**: Open an issue on GitHub
- **Logs**: Check `/var/log/ipv4-ipv6-gateway.log` for detailed error messages
- **Diagnostic**: Run `gateway-diagnose` for automated troubleshooting

---

**Made with ❤️ for flexible dual-stack networking with MAC-based firewall registration**
