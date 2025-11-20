# Simple IPv4↔IPv6 Gateway - Single Device Mode

**Simplified dual-stack gateway for NanoPi R5C running OpenWrt**

A lightweight Python service that automatically discovers ONE IPv4 device on eth1, spoofs its MAC on eth0, and requests DHCPv4/DHCPv6 to enable dual-stack connectivity.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

---

## 🎯 Overview

This is a **simplified version** of the dual-stack gateway designed for:
- **Single device support** - handles exactly ONE device at a time
- **No HTTP API server** - uses direct shell scripts for monitoring
- **Simplified architecture** - easier to debug and maintain
- **Auto-discovery** - automatically detects device on LAN

### Use Case

Perfect for scenarios where:
- You have **one IPv4 device** that needs dual-stack WAN access
- Device **MAC must be pre-registered** on upstream firewall
- Upstream network is **IPv4, IPv6, or dual-stack**
- You want a **simple, reliable solution** without complex APIs

### Network Topology

```
[Device] ←→ eth1 (LAN) ←→ Gateway ←→ eth0 (WAN) ←→ [Firewall] ←→ [Network]
         192.168.1.x    MAC Spoofing   DHCP v4/v6     MAC Check    IPv4/IPv6
```

---

## 🚀 Quick Start

### Prerequisites

- **Hardware**: NanoPi R5C (or similar dual-NIC router)
- **OS**: OpenWrt with Python 3.7+
- **Network**: Dual-stack network with MAC-based firewall

### One-Command Installation

```bash
# Copy files to router
scp ipv4_ipv6_gateway.py gateway_config.py \
    gateway-status-direct.sh gateway-devices-direct.sh install.sh \
    root@<router-ip>:/tmp/

# SSH and install
ssh root@<router-ip>
cd /tmp
chmod +x install.sh
./install.sh --full-auto
```

**What this does:**
1. ✅ Installs dependencies (Python, odhcp6c, udhcpc, etc.)
2. ✅ Installs simplified gateway service
3. ✅ Creates dual-stack network configuration
4. ✅ Starts the service
5. ✅ Installs helper commands: `gateway-status`, `gateway-device`

### Verify Installation

```bash
# Check status
gateway-status

# Check device info
gateway-device

# View logs
tail -f /var/log/ipv4-ipv6-gateway.log
```

---

## ✨ Features

### Core Capabilities
- **🌐 Dual-Stack Support**: Works with IPv4-only, IPv6-only, or dual-stack WAN
- **🔍 Auto-Discovery**: Monitors ARP table to discover device
- **🎭 MAC Spoofing**: Spoofs device MAC on eth0 for DHCP requests
- **🔄 Robust DHCP**: 10 retries for DHCPv4, 5 for DHCPv6
- **🌐 SLAAC Support**: Tries SLAAC first, falls back to DHCPv6
- **💾 Persistent State**: Device state saved to JSON
- **📝 Comprehensive Logging**: Detailed logs for troubleshooting

### Simplifications from Complex Version
- ❌ No HTTP API server on port 5050
- ❌ No multi-device tracking
- ❌ No HAProxy/socat proxying
- ❌ No WAN network monitoring
- ❌ No port forwarding automation
- ✅ Single device only
- ✅ Direct shell scripts for monitoring
- ✅ **Much simpler codebase** (600 lines vs 4200 lines)

---

## 🔄 How It Works

### Device Connection Flow

1. **Device connects to eth1** → Gets `192.168.1.x` via DHCP
2. **Gateway discovers MAC** via ARP monitoring
3. **Gateway spoofs MAC** on eth0 (WAN interface)
4. **Requests DHCPv4** → Firewall sees registered MAC → Allows
5. **Requests DHCPv6** → Tries SLAAC first, falls back to DHCPv6
6. **Device is active** → State saved to JSON

#### Example Flow

```
Device connects → MAC: aa:bb:cc:dd:ee:ff
                  LAN IPv4: 192.168.1.100

Gateway spoofs MAC on eth0

DHCPv4 request → WAN IPv4: 10.1.2.50
DHCPv6/SLAAC  → WAN IPv6: 2001:db8::1234

Device is active!
```

---

## 📦 Installation

### Full Installation

```bash
# 1. Copy files
scp ipv4_ipv6_gateway.py gateway_config.py \
    gateway-status-direct.sh gateway-devices-direct.sh install.sh \
    root@<router-ip>:/tmp/

# 2. SSH to router
ssh root@<router-ip>
cd /tmp

# 3. Install
chmod +x install.sh
./install.sh --full-auto
```

### Installation Options

```bash
./install.sh                    # Safe mode (no auto-start/network)
./install.sh --auto-start       # Install and start service
./install.sh --apply-network    # Install and apply network config
./install.sh --full-auto        # Do everything automatically
```

### ⚠️ CRITICAL: Register Device MAC

**Before device can get WAN addresses, MAC must be registered with firewall!**

This is YOUR responsibility - the gateway cannot do this.

---

## 📊 Monitoring

### Commands

```bash
# View gateway and device status
gateway-status

# View device configuration only
gateway-device

# View live logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Service control
/etc/init.d/ipv4-ipv6-gateway start|stop|restart
```

### Example Output

```
==========================================
GATEWAY STATUS (Single Device Mode)
==========================================

Service: RUNNING

Device Configuration:
--------------------
MAC:         aa:bb:cc:dd:ee:ff
LAN IPv4:    192.168.1.100
WAN IPv4:    10.1.2.50
WAN IPv6:    2001:db8::1234
Status:      active
Last Update: 2024-01-15T10:35:00
```

---

## 🔧 Configuration

### DHCP Settings

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# DHCPv4 (Critical)
DHCPV4_TIMEOUT = 15           # 15 seconds per attempt
DHCPV4_RETRY_COUNT = 10       # 10 attempts
DHCPV4_RETRY_DELAY = 5        # Exponential backoff from 5s

# DHCPv6 (Optional)
DHCPV6_TIMEOUT = 10           # 10 seconds per attempt
DHCPV6_RETRY_COUNT = 5        # 5 attempts
DHCPV6_RETRY_DELAY = 5        # Exponential backoff from 5s

# ARP Monitoring
ARP_MONITOR_INTERVAL = 10     # Check for devices every 10s
```

After changes:
```bash
/etc/init.d/ipv4-ipv6-gateway restart
```

---

## 🔍 Troubleshooting

### Device Not Getting DHCP on LAN

```bash
# Check dnsmasq is running
ps | grep dnsmasq

# Check eth1 IP
ip addr show eth1
# Should show: inet 192.168.1.1/24
```

### MAC Not Getting WAN Address

**Most common cause: MAC not registered with firewall!**

```bash
# 1. Register MAC with your upstream firewall first!

# 2. Check logs for DHCP errors
tail -50 /var/log/ipv4-ipv6-gateway.log | grep ERROR

# 3. Check service is running
gateway-status

# 4. Wait for retries (up to 2.5 minutes for DHCPv4)
```

### Service Won't Start

```bash
# Check for errors
/etc/init.d/ipv4-ipv6-gateway start

# View logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Check Python is installed
which python3
python3 --version
```

---

## 🗂️ File Structure

```
/opt/ipv4-ipv6-gateway/           # Service installation
├── ipv4_ipv6_gateway.py          # Main service (simplified - 573 lines)
└── gateway_config.py             # Configuration

/etc/ipv4-ipv6-gateway/           # Config directory
├── current_device.json           # Current device state
└── original_wan_mac.txt          # Original MAC backup

/usr/bin/
├── gateway-status                # Status command
└── gateway-device                # Device info command

/var/log/
└── ipv4-ipv6-gateway.log        # Service logs
```

---

## 🔒 Security

### MAC Spoofing

This service spoofs MAC addresses. Ensure:
- You have authorization to use MAC spoofing
- Your firewall expects this behavior
- Device MAC is properly registered

### No API Server

Unlike complex versions, this simplified version has:
- ✅ No HTTP API server on port 5050
- ✅ No network-exposed attack surface
- ✅ Direct shell scripts only

---

## 📈 Performance

### Resource Usage

- **CPU**: Minimal (checks ARP every 10s)
- **Memory**: ~20MB (Python + simple logic)
- **Network**: DHCP requests only when device connects
- **Disk**: <1MB for code + state

### Scaling

- **Devices**: Exactly ONE at a time
- **Concurrent**: Not supported (by design)

---

## ⚙️ Advanced

### Change Device

To switch to a different device:

```bash
# 1. Disconnect current device from eth1
# 2. Connect new device
# 3. Service will auto-discover and configure
# 4. Old device state will be overwritten
```

### View Device State

```bash
# View raw JSON state
cat /etc/ipv4-ipv6-gateway/current_device.json

# Pretty print
cat /etc/ipv4-ipv6-gateway/current_device.json | python3 -m json.tool
```

### Uninstall

```bash
# Stop service
/etc/init.d/ipv4-ipv6-gateway stop

# Disable auto-start
/etc/init.d/ipv4-ipv6-gateway disable

# Remove files
rm -rf /opt/ipv4-ipv6-gateway
rm -rf /etc/ipv4-ipv6-gateway
rm -f /usr/bin/gateway-status
rm -f /usr/bin/gateway-device
rm -f /etc/init.d/ipv4-ipv6-gateway
```

---

## 📄 License

MIT License

---

## 🙏 Acknowledgments

- **OpenWrt** - Excellent embedded Linux distribution
- **odhcp6c** - DHCPv6 client
- **udhcpc** - DHCPv4 client (busybox)

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| **Install** | `./install.sh --full-auto` |
| **Status** | `gateway-status` |
| **Device Info** | `gateway-device` |
| **Logs** | `tail -f /var/log/ipv4-ipv6-gateway.log` |
| **Restart** | `/etc/init.d/ipv4-ipv6-gateway restart` |
| **Stop** | `/etc/init.d/ipv4-ipv6-gateway stop` |
| **Start** | `/etc/init.d/ipv4-ipv6-gateway start` |

---

## 🎯 Comparison: Simple vs Complex Version

| Feature | Simple (This Version) | Complex (Original) |
|---------|----------------------|-------------------|
| **Lines of Code** | 573 | 4,230 |
| **Devices Supported** | 1 | 1000+ |
| **HTTP API Server** | ❌ No | ✅ Yes (port 5050) |
| **Port Forwarding** | ❌ No | ✅ Yes (HAProxy/socat) |
| **WAN Monitoring** | ❌ No | ✅ Yes |
| **Multi-threading** | Minimal | Extensive |
| **Memory Usage** | ~20MB | ~50-100MB |
| **Complexity** | Low | High |
| **Debugging** | Easy | Complex |
| **Setup Time** | 5 minutes | 15-30 minutes |
| **Recommended For** | Single device, testing | Production, multiple devices |

---

**Made with ❤️ for simple, reliable dual-stack networking**
