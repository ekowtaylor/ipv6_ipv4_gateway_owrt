# Simple IPv4↔IPv6 Gateway - Single Device Mode

**Simplified dual-stack gateway for NanoPi R5C running OpenWrt**

A lightweight Python service that automatically discovers ONE IPv4 device on eth1, spoofs its MAC on eth0, and requests DHCPv4/DHCPv6 to enable dual-stack connectivity.

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
scp ipv4_ipv6_gateway_simple.py gateway_config.py \
    gateway-status-simple.sh install-simple.sh \
    root@<router-ip>:/tmp/

# SSH and install
ssh root@<router-ip>
cd /tmp
chmod +x install-simple.sh
./install-simple.sh --full-auto
```

**What this does:**
1. ✅ Installs dependencies (Python, odhcp6c, udhcpc, etc.)
2. ✅ Installs simplified gateway service
3. ✅ Creates dual-stack network configuration
4. ✅ Starts the service
5. ✅ Installs helper command: `gateway-status`

### Verify Installation

```bash
# Check status
gateway-status

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

### Simplifications from Full Version
- ❌ No HTTP API server on port 5050
- ❌ No multi-device tracking
- ❌ No HAProxy/socat proxying (optional feature removed for simplicity)
- ❌ No WAN network monitoring
- ✅ Single device only
- ✅ Direct shell scripts for monitoring
- ✅ Much simpler codebase

---

## 🔄 How It Works

### Device Connection Flow

#### 1. **Device connects to eth1** (LAN)
```
iPhone → eth1
```

#### 2. **DHCP assigns LAN IP**
```
Device gets 192.168.1.100 (from dnsmasq)
```

#### 3. **Gateway discovers MAC** (via ARP)
```
Detected: aa:bb:cc:dd:ee:ff
```

#### 4. **Gateway spoofs MAC on WAN**
```
eth0 MAC → aa:bb:cc:dd:ee:ff
```

#### 5. **Gateway requests DHCPv4**
```
udhcpc on eth0
Firewall sees registered MAC → allows
Gateway gets: 10.1.2.50
```

#### 6. **Gateway requests DHCPv6**
```
Tries SLAAC first (3 seconds)
Falls back to odhcp6c if needed
Gateway gets: 2001:db8::1234
```

#### 7. **Device fully configured**
```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ipv4_address": "192.168.1.100",
  "ipv4_wan_address": "10.1.2.50",
  "ipv6_address": "2001:db8::1234",
  "status": "active"
}
```

---

## 📦 Installation

### Manual Installation

```bash
# 1. Copy files
scp ipv4_ipv6_gateway_simple.py gateway_config.py \
    gateway-status-simple.sh install-simple.sh \
    root@<router-ip>:/tmp/

# 2. SSH to router
ssh root@<router-ip>
cd /tmp

# 3. Install
chmod +x install-simple.sh
./install-simple.sh --full-auto
```

### ⚠️ CRITICAL: Register Device MAC

**Before device can get WAN addresses, MAC must be registered with firewall!**

This is YOUR responsibility - the gateway cannot do this.

---

## 📊 Monitoring

### Check Status

```bash
# View current device status
gateway-status

# View live logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Service control
/etc/init.d/ipv4-ipv6-gateway start|stop|restart
```

### Example Status Output

```
=========================================
 Simple Gateway Status
=========================================

✓ Service Status: RUNNING
  PID: 1234

Device Configuration:
-------------------
  MAC Address:    aa:bb:cc:dd:ee:ff
  Status:         active
  LAN IPv4:       192.168.1.100
  WAN IPv4:       10.1.2.50
  WAN IPv6:       2001:db8::1234
  Discovered:     2024-01-15T10:30:00
  Last Seen:      2024-01-15T10:35:00

Network Interfaces:
-------------------
eth0 (WAN):
  MAC: aa:bb:cc:dd:ee:ff (spoofed)
  IPv4: 10.1.2.50
  IPv6: 2001:db8::1234

eth1 (LAN):
  MAC: xx:xx:xx:xx:xx:xx
  IPv4: 192.168.1.1
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
# 1. Register MAC with your upstream firewall

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
├── ipv4_ipv6_gateway.py          # Main service (simplified)
└── gateway_config.py             # Configuration

/etc/ipv4-ipv6-gateway/           # Config directory
├── current_device.json           # Current device state
└── original_wan_mac.txt          # Original MAC backup

/usr/bin/
└── gateway-status                # Status command

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

Unlike the full version, this simplified version has:
- ✅ No HTTP API server on port 5050
- ✅ No network-exposed attack surface
- ✅ Direct shell scripts only

---

## 📈 Performance

### Resource Usage

- **CPU**: Minimal (checks ARP every 10s)
- **Memory**: ~20MB (Python + simple logic)
- **Network**: DHCP requests only when device connects

### Scaling

- **Devices**: Exactly ONE at a time
- **For multiple devices**: Use the full version instead

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

### Manual MAC Configuration

If you want to manually set the device MAC:

```bash
# Stop service
/etc/init.d/ipv4-ipv6-gateway stop

# Edit state file
vi /etc/ipv4-ipv6-gateway/current_device.json

# Update MAC, then restart
/etc/init.d/ipv4-ipv6-gateway start
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
| **Install** | `./install-simple.sh --full-auto` |
| **Status** | `gateway-status` |
| **Logs** | `tail -f /var/log/ipv4-ipv6-gateway.log` |
| **Restart** | `/etc/init.d/ipv4-ipv6-gateway restart` |
| **Stop** | `/etc/init.d/ipv4-ipv6-gateway stop` |
| **Start** | `/etc/init.d/ipv4-ipv6-gateway start` |

---

**Made with ❤️ for simple, reliable dual-stack networking**
