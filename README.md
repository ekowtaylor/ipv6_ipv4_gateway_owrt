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
- **🌐 **NEW: SLAAC Support**: Full support for IPv6 SLAAC (Stateless Address Autoconfiguration) + DHCPv6
- **🔀 Transparent NAT**: Uses OpenWrt's native NAT for IPv4 traffic
- **🌉 464XLAT Ready**: Can use 464XLAT for IPv4↔IPv6 translation when needed
- **🔄 WAN Network Auto-Detection**: Automatically detects WAN network changes and re-requests DHCP for all devices

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

**Automatic port forwarding with dual backend IPv6→IPv4 proxying for seamless access!**

When a device is discovered and successfully configured, the gateway automatically sets up port forwarding:

- **IPv4**: From gateway WAN to device LAN IP (NAT/DNAT via iptables)
- **IPv6→IPv4**: From IPv6 clients to IPv4-only devices (HAProxy or socat proxy)

### Why MAC Spoofing is Essential 🔑

**The IPv4 device connected on the LAN needs its MAC pre-registered on the IPv6 network.**

This gateway uses MAC spoofing to enable IPv6 connectivity for IPv4-only devices:

1. **Network Context**: The network is mostly IPv6-only with limited IPv4 support
2. **MAC Registration Requirement**: The upstream IPv6 network requires MAC addresses to be pre-registered
3. **The Solution**: The gateway spoofs the IPv4 device's MAC address on the WAN interface (eth0) to:
   - Request DHCPv6 lease for the device
   - Register the device's MAC on the IPv6 network
   - Enable IPv6 connectivity for the IPv4-only device
4. **Result**: The IPv4-only device gains IPv6 capabilities through the gateway's proxy

**Without MAC spoofing**: The IPv4 device would be invisible to the IPv6 network and unable to communicate.

### IPv6→IPv4 Proxy Backends

The gateway supports **two proxy backends** for IPv6→IPv4 connectivity:

| Backend | Type | Best For | Key Features |
|---------|------|----------|--------------|
| **socat** (default) | Lightweight | Simple setups, resource-constrained | Low memory, minimal overhead |
| **HAProxy** | Production-grade | Complex protocols, troubleshooting | Stats page, health checks, advanced logging |

**Switch backends** by editing `/opt/ipv4-ipv6-gateway/gateway_config.py`:
```python
# Use socat (lightweight, default)
IPV6_PROXY_BACKEND = "socat"

# OR use HAProxy (production-grade)
IPV6_PROXY_BACKEND = "haproxy"
```

Then restart: `/etc/init.d/ipv4-ipv6-gateway restart`

### Automatic Port Forwarding (Default)

By default, when a device connects and gets configured, these ports are automatically forwarded:

| Gateway Port | Device Port | Service | Access Method |
|--------------|-------------|---------|---------------|
| 8080 | 80 or 5000 | HTTP | Both IPv4 and IPv6 WAN |
| 2323 | 23 | Telnet | Both IPv4 and IPv6 WAN |

**Port Remapping Rationale**: Gateway ports are remapped to avoid conflicts with OpenWrt services:
- OpenWrt LuCI web UI runs on port 80
- OpenWrt SSH runs on port 22
- Device services are accessible on non-conflicting ports (8080, 2323)

**This happens automatically for both IPv4 and IPv6 clients - no manual setup needed!** ✨

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         NETWORK ARCHITECTURE                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  LAN SIDE (192.168.1.x)                    WAN SIDE (Internet)               │
│  ═══════════════════                       ══════════════════                │
│                                                                               │
│  ┌─────────────┐                           ┌──────────────┐                 │
│  │   Device    │  LAN IP: 192.168.1.128    │  IPv6 Router │                 │
│  │ (IPv4-only) │◄──────────┐               │  & Firewall  │                 │
│  │             │            │               └──────▲───────┘                 │
│  └─────────────┘            │                      │                         │
│                             │                      │                         │
│                    ┌────────▼────────┐             │                         │
│                    │  NanoPi Gateway │             │                         │
│                    │   192.168.1.1   │             │                         │
│                    ├─────────────────┤             │                         │
│                    │  eth1 (LAN)     │             │                         │
│                    │  eth0 (WAN)     │◄────────────┘                         │
│                    └─────────────────┘                                       │
│                           │ MAC Spoofing                                     │
│                           │ Spoofs device MAC                                │
│                           │ Gets IPv6: 2620:...:6dfc                         │
│                           │                                                  │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                      HOW SERVICES ARE ACCESSIBLE                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  FROM LAN (devices on 192.168.1.x):                                          │
│  ════════════════════════════════════                                        │
│                                                                               │
│    OpenWrt LuCI:    http://192.168.1.1:80        ┌──────────────────┐       │
│    OpenWrt SSH:     ssh root@192.168.1.1:22      │  Gateway Itself  │       │
│    OpenWrt Telnet:  telnet 192.168.1.1:23        │  (if enabled)    │       │
│                                                   └──────────────────┘       │
│                                                                               │
│    Device HTTP:     http://192.168.1.128:80      ┌──────────────────┐       │
│    Device Telnet:   telnet 192.168.1.128:23      │  Device Direct   │       │
│                                                   │  (LAN access)    │       │
│                                                   └──────────────────┘       │
│                                                                               │
│  FROM WAN via IPv4:                                                          │
│  ═══════════════════                                                         │
│                                                                               │
│    OpenWrt LuCI:    ✗ NOT ACCESSIBLE                                         │
│    OpenWrt SSH:     ✗ NOT ACCESSIBLE                                         │
│    OpenWrt Telnet:  ✗ NOT ACCESSIBLE                                         │
│    (Security: Gateway services only on LAN)                                  │
│                                                                               │
│    Device HTTP:     http://100.124.66.225:8080   ┌──────────────────┐       │
│    Device Telnet:   telnet 100.124.66.225:2323   │  Via iptables    │       │
│                     (Port forwards via NAT)       │  Port Forward    │       │
│                                                   └──────────────────┘       │
│                                                                               │
│  FROM WAN via IPv6:                                                          │
│  ═══════════════════                                                         │
│                                                                               │
│    OpenWrt LuCI:    ✗ NOT ACCESSIBLE                                         │
│    OpenWrt SSH:     ✗ NOT ACCESSIBLE                                         │
│    (LuCI only listens on LAN IPv4: 192.168.1.1)                              │
│                                                                               │
│    Device HTTP:     http://[2620:...:6dfc]:8080  ┌──────────────────┐       │
│    Device Telnet:   telnet 2620:...:6dfc 2323    │  Via socat/HAProxy│      │
│                     (Proxy on device's IPv6)      │  Bound to device │       │
│                                                   │  specific IPv6   │       │
│                                                   └──────────────────┘       │
│                                                                               │
│  KEY POINT:                                                                  │
│  ──────────                                                                  │
│  • Device IPv6 (2620:...:6dfc) ≠ Gateway IPv6                                │
│  • Gateway spoofs device MAC to get device's IPv6                            │
│  • Proxy binds to DEVICE'S IPv6, not gateway's IPv6                          │
│  • This prevents port conflicts between LuCI and device services             │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### How It Works

#### **IPv4 Port Forwarding (NAT)**
```
IPv4 Client → Gateway WAN:8080 → NAT (iptables) → Device LAN:80
Example: curl http://100.124.66.225:8080  # Gateway WAN IPv4
```

#### **IPv6→IPv4 Proxying (HAProxy/socat) - Device-Specific Binding!** ⭐
```
IPv6 Client → Device's IPv6:8080 → HAProxy/socat (on gateway) → Device LAN:80
Example: curl http://[2620:10d:c050:100:46b7:d0ff:fea6:6dfc]:8080
```

**🎯 Key Architecture Feature:**

Each device gets its **OWN unique IPv6 address**, and HAProxy/socat binds to that specific address:

- **Device 1**: IPv6 `2620:10d:c050:100:46b7:d0ff:fea6:6dfc` → HAProxy binds to this IPv6
- **Device 2**: IPv6 `2620:10d:c050:100:1234:5678:abcd:ef00` → HAProxy binds to this IPv6
- **Result**: Both devices can use the same ports (8080, 2323, etc.) without conflict!

**How it works:**
1. Gateway discovers device MAC `44:b7:d0:a6:6d:fc`
2. Gateway spoofs that MAC on eth0 and requests DHCPv6
3. DHCPv6 server assigns unique IPv6: `2620:10d:c050:100:46b7:d0ff:fea6:6dfc`
4. HAProxy/socat binds to that **specific IPv6** (not to `:::` all addresses)
5. Clients connect directly to the device's IPv6 → proxy forwards to device's IPv4

**Key Differences:**
- **IPv4 NAT**: Device traffic goes through iptables NAT
- **IPv6→IPv4 Proxy**: HAProxy/socat proxies IPv6 connections to IPv4-only devices
- **Device-Specific Binding**: Each device's proxy listens on its unique IPv6 address

**Why needed?** Most devices are IPv4-only and have no IPv6 stack. The IPv6 address
obtained via MAC spoofing is assigned to the gateway's eth0, not to the device itself.
HAProxy/socat bridges IPv6 clients → IPv4-only devices transparently by binding to each
device's unique IPv6 address and forwarding to the device's LAN IPv4.

### Access from Client

**From WAN network (IPv4 client):**
```bash
# Get gateway's WAN IPv4
gateway-devices-direct
# Shows gateway WAN IPv4: 100.124.66.225

# Telnet to device (automatic port forward)
telnet 100.124.66.225 2323  # Gateway WAN IPv4:2323 → Device LAN:23

# HTTP access (works for device port 80 or 5000)
curl http://100.124.66.225:8080  # Gateway WAN IPv4:8080 → Device LAN:80 or 5000
```

**From WAN network (IPv6 client):**
```bash
# Get device's WAN IPv6 (obtained by spoofing device MAC)
gateway-devices-direct
# Shows: "ipv6_address": "2620:10d:c050:100:46b7:d0ff:fea6:6dfc"

# Access device via IPv6 → socat/HAProxy proxies to IPv4 device!
telnet 2620:10d:c050:100:46b7:d0ff:fea6:6dfc 2323      # → Device:23 ✅
curl http://[2620:10d:c050:100:46b7:d0ff:fea6:6dfc]:80  # → Device:80 ✅
ssh -p 22 user@2620:10d:c050:100:46b7:d0ff:fea6:6dfc   # → Device:22 ✅

# Note: This works even though device is IPv4-only!
# socat transparently proxies IPv6 → IPv4
```

**From LAN side (gateway itself):**
```bash
# Direct access using device's LAN IP
telnet 192.168.1.128 23
curl http://192.168.1.128:80
```

### HAProxy Stats Page (NEW!)

When using HAProxy backend, you get a **real-time stats dashboard**:

**Access:** `http://192.168.1.1:8404/stats`

**What you can see:**
- ✅ All active proxy connections
- ✅ Backend health status (up/down)
- ✅ Connection rates and throughput
- ✅ Session counts and queue depths
- ✅ Error rates and response codes

**Example screenshot:**
```
Statistics Report for HAProxy

Frontend: ipv6_http_8080
  Sessions: current=2, max=5, total=127
  Status: OPEN

Backend: ipv4_http_44_b7_d0_a6_6d_fc
  Server: device_44_b7_d0_a6_6d_fc
    Status: UP (check passed)
    Sessions: current=2, max=5, total=127
    Bytes: in=12.3 KB, out=45.6 KB
```

**Configuration:**
```python
# Enable/disable stats in gateway_config.py
HAPROXY_STATS_ENABLE = True     # Set to False to disable
HAPROXY_STATS_PORT = 8404       # Change port if needed
HAPROXY_STATS_URI = "/stats"    # Change URI if needed
```

### Backend Comparison

| Feature | socat | HAProxy |
|---------|-------|---------|
| **Memory** | ~2MB per proxy | ~10MB total (shared) |
| **CPU Usage** | Very low | Very low |
| **Protocol Handling** | Basic TCP + custom options | Advanced TCP/HTTP |
| **HTTP Keep-Alive** | Via `nodelay,keepalive,ignoreeof` | Native support |
| **Telnet Protocol** | Via `rawer,ignoreeof` | Native support |
| **Logging** | Minimal (stderr) | Detailed (stdout/syslog) |
| **Stats Dashboard** | ❌ None | ✅ Built-in web UI |
| **Health Checks** | ❌ None | ✅ Automatic |
| **Load Balancing** | ❌ No | ✅ Yes (multiple backends) |
| **Config Reload** | ❌ Restart required | ✅ Graceful reload |
| **Best For** | Simple setups, low resources | Production, debugging |

### Troubleshooting Proxies

#### Check Active Backend
```bash
tail /var/log/ipv4-ipv6-gateway.log | grep "Using"
# Shows: [INFO] Using HAProxy for IPv6→IPv4 proxying
# OR:    [INFO] Using socat for IPv6→IPv4 proxying
```

#### socat Not Working?
```bash
# Connection resets with socat? Switch to HAProxy:
vi /opt/ipv4-ipv6-gateway/gateway_config.py
# Change: IPV6_PROXY_BACKEND = "haproxy"
/etc/init.d/ipv4-ipv6-gateway restart

# Verify HAProxy started:
ps | grep haproxy
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i haproxy
```

#### HAProxy Not Working?
```bash
# Check HAProxy is installed
which haproxy
haproxy -v

# Validate config
haproxy -c -f /etc/haproxy/haproxy.cfg

# View detailed logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -iE "haproxy|proxy"

# Check stats page
curl http://192.168.1.1:8404/stats
```

#### Test Direct Access (Bypass Proxy)
```bash
# From gateway, test device directly (IPv4):
curl -v http://192.168.1.128:80/execute.php?STATUS
telnet 192.168.1.128 23

# If this works but proxy doesn't:
# 1. Check proxy process is running (ps | grep haproxy/socat)
# 2. Check logs for errors
# 3. Try switching backends
```

### Configuration

To customize automatic port forwarding, edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Enable/disable automatic port forwarding
ENABLE_AUTO_PORT_FORWARDING = True  # Set to False to disable

# Customize ports (gateway_port: device_port)
AUTO_PORT_FORWARDS = {
    8080: 80,      # HTTP
    2323: 23,      # Telnet
    8443: 443,     # HTTPS
    2222: 22,      # SSH
    5900: 5900,    # VNC
    3389: 3389,    # RDP
    # Add your own:
    # 8888: 8888,  # Custom service
}
```

After editing, restart the service:
```bash
/etc/init.d/ipv4-ipv6-gateway restart
```

### Manual Port Forwarding

You can still manually add port forwards using the command-line tool:

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

### WAN Network Auto-Detection (NEW!)

The gateway automatically detects when the WAN network changes and re-requests DHCP for all devices.

**How it works:**
1. Gateway monitors eth0 (WAN) every 15 seconds
2. Detects when IPv4 or IPv6 addresses change
3. Automatically clears all device WAN addresses
4. Triggers re-discovery for all active devices
5. Devices get new WAN IPs without manual intervention

**Configuration:**
```python
# Edit /opt/ipv4-ipv6-gateway/gateway_config.py

# Enable/disable WAN monitoring
ENABLE_WAN_MONITOR = True     # Set to False to disable

# Check interval
WAN_MONITOR_INTERVAL = 15     # Seconds between checks

# Wait before re-discovery
WAN_CHANGE_REDISCOVERY_DELAY = 5  # Seconds to wait after network change
```

**Example scenario:**
```bash
# 1. Device connected on Network A (192.168.8.x)
#    WAN IP: 192.168.8.128

# 2. Unplug eth0 from Network A
#    Plug into Network B (10.0.0.x)

# 3. Gateway automatically detects change:
# [WARNING] WAN network change detected!
# [WARNING]   IPv4 changed: ['192.168.8.128'] → ['10.0.0.50']
# [WARNING] WAN network changed - triggering device re-discovery
# [INFO] Cleared WAN addresses for aa:bb:cc:dd:ee:ff
# [INFO] Started re-discovery thread for aa:bb:cc:dd:ee:ff
# [INFO] Successfully obtained IPv4 10.0.0.51 for aa:bb:cc:dd:ee:ff
# [INFO] Device aa:bb:cc:dd:ee:ff successfully configured - IPv4: 10.0.0.51

# 4. Device now works on Network B with new IP!
#    WAN IP: 10.0.0.51
```

**This makes the gateway truly plug-and-play for WAN changes!** 🎉

### IPv6 SLAAC + DHCPv6 Support (NEW!)

The gateway now supports **both** IPv6 address assignment methods:

1. **SLAAC (Stateless Address Autoconfiguration)** - Uses Router Advertisements
2. **DHCPv6 (Stateful)** - Requests address from DHCPv6 server

**How it works:**
```bash
# For each device, the gateway:

1. Spoofs device MAC on eth0
2. Enables IPv6 on the interface
3. Waits for SLAAC (Router Advertisement) - 3 seconds
4. If SLAAC provides an address:
   ✅ Uses SLAAC address
   ✅ Tries DHCPv6 info-only for DNS/NTP (optional)

5. If SLAAC doesn't work:
   ✅ Falls back to full DHCPv6 request
   ✅ Uses DHCPv6-assigned address
```

**Why both?**

Many networks use different IPv6 deployment strategies:
- **SLAAC-only**: Network provides prefix via Router Advertisement
- **DHCPv6-only**: Network requires stateful DHCPv6
- **Both**: SLAAC for address, DHCPv6 for DNS/options

**The gateway handles all three automatically!** ✨

**Log examples:**

**SLAAC Success:**
```
[INFO] Requesting IPv6 for MAC: aa:bb:cc:dd:ee:ff (SLAAC + DHCPv6)
[DEBUG] Waiting for SLAAC (Router Advertisement)...
[INFO] Successfully obtained IPv6 2001:db8::1234 via SLAAC for MAC aa:bb:cc:dd:ee:ff (attempt 1)
[DEBUG] Attempting DHCPv6 for additional configuration...
```

**DHCPv6 Success:**
```
[INFO] Requesting IPv6 for MAC: aa:bb:cc:dd:ee:ff (SLAAC + DHCPv6)
[DEBUG] Waiting for SLAAC (Router Advertisement)...
[DEBUG] SLAAC didn't assign address, trying DHCPv6...
[DEBUG] DHCPv6 request succeeded
[INFO] Successfully obtained IPv6 2001:db8::5678 via DHCPv6 for MAC aa:bb:cc:dd:ee:ff (attempt 1)
```

**Configuration (usually no changes needed):**
```python
# /opt/ipv4-ipv6-gateway/gateway_config.py

# SLAAC wait time
# Increase if your network has slow Router Advertisements
# (Currently hardcoded to 3 seconds in _enable_ipv6_on_interface)

# DHCPv6 settings apply to fallback
DHCPV6_TIMEOUT = 10
DHCPV6_RETRY_COUNT = 5
```

**Troubleshooting:**

```bash
# Check if SLAAC is working
ip -6 addr show eth0
# Should show: inet6 2001:db8::xxx scope global (not fe80::)

# Check sysctl settings
sysctl net.ipv6.conf.eth0.accept_ra
sysctl net.ipv6.conf.eth0.autoconf
# Both should be: 1 or 2

# View logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i "slaac\|dhcpv6"
```

### Enhanced IPv6 Packet Handling (NEW! 🔥)

The gateway now includes **comprehensive IPv6 packet handling improvements** to prevent connection drops and packet loss issues commonly seen in IPv6 environments.

#### Problem Solved

**Common IPv6 issues:**
- ❌ Connections drop randomly
- ❌ Packets don't reach device
- ❌ Neighbor discovery fails
- ❌ Routes not established
- ❌ Firewall blocks traffic

**Root causes:**
- Missing proxy NDP configuration
- Incorrect sysctl settings for forwarding mode
- No connection tracking timeout tuning
- Missing IPv6 routes
- Firewall rules not configured

#### Solution Implemented

The gateway now automatically configures **25+ critical IPv6 settings** when enabling IPv6 on an interface:

**1. Core IPv6 Enablement:**
```bash
net.ipv6.conf.eth0.disable_ipv6 = 0
net.ipv6.conf.eth0.accept_ra = 2      # Accept RA even with forwarding
net.ipv6.conf.eth0.autoconf = 1
```

**2. Packet Handling & Stability:**
```bash
net.ipv6.conf.eth0.accept_dad = 0     # Disable DAD for faster setup
net.ipv6.conf.eth0.use_tempaddr = 0    # No temporary addresses
net.ipv6.conf.eth0.accept_redirects = 1
net.ipv6.conf.eth0.mtu = 1500          # Standard MTU
net.ipv6.conf.eth0.hop_limit = 64
```

**3. Neighbor Discovery Optimization:**
```bash
net.ipv6.conf.eth0.dad_transmits = 0              # Skip DAD
net.ipv6.conf.eth0.router_solicitations = 3       # RS retries
net.ipv6.conf.eth0.router_solicitation_delay = 1
net.ipv6.conf.eth0.router_solicitation_interval = 4
```

**4. Connection Tracking (Prevents Drops):**
```bash
net.netfilter.nf_conntrack_tcp_timeout_established = 7200  # 2 hours
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
```

**5. Neighbor Cache Scaling:**
```bash
net.ipv6.neigh.default.gc_thresh1 = 1024
net.ipv6.neigh.default.gc_thresh2 = 2048
net.ipv6.neigh.default.gc_thresh3 = 4096
```

**6. Enhanced Proxy NDP (5-Step Process):**

For each IPv6 address, the gateway now performs:
1. ✅ Enables global proxy_ndp sysctls
2. ✅ Adds proxy NDP entry for specific IPv6
3. ✅ Sends Neighbor Advertisement to all-nodes (ff02::1)
4. ✅ Pings default gateway directly if available
5. ✅ Adds explicit local route for IPv6
6. ✅ Adds ip6tables firewall rules (INPUT/FORWARD)

**Before (3 steps):**
```python
1. Enable proxy_ndp sysctl
2. Add NDP entry
3. Send 1 ping to ff02::1
```

**After (6 steps with redundancy):**
```python
1. Enable proxy_ndp + forwarding sysctls
2. Add NDP entry
3. Send 2 pings to ff02::1 (all-nodes)
4. Send ping to default gateway (if found)
5. Add local IPv6 route
6. Add ip6tables rules for this address
```

#### Benefits

✅ **No more connection drops** - Extended TCP timeout prevents premature termination
✅ **Faster address assignment** - DAD disabled for immediate use
✅ **Better neighbor discovery** - Multiple advertisement methods
✅ **Explicit routing** - Local routes ensure packet delivery
✅ **Firewall configured** - ip6tables rules allow traffic
✅ **Optimized cache** - Larger neighbor cache prevents eviction

#### Verification

```bash
# Check connection tracking timeouts
sysctl net.netfilter.nf_conntrack_tcp_timeout_established
# Should show: 7200 (2 hours)

# Check proxy NDP enabled
sysctl net.ipv6.conf.eth0.proxy_ndp
# Should show: 1

# Check neighbor cache
sysctl net.ipv6.neigh.default.gc_thresh3
# Should show: 4096

# View IPv6 routes
ip -6 route show table local | grep <device_ipv6>
# Should show local route for device's IPv6

# View ip6tables rules
ip6tables -L INPUT -n | grep <device_ipv6>
ip6tables -L FORWARD -n | grep <device_ipv6>
# Should show ACCEPT rules
```

#### Troubleshooting Still Seeing Drops?

```bash
# 1. Check if connection tracking table is full
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
# If count >= max, increase max:
echo 262144 > /proc/sys/net/netfilter/nf_conntrack_max

# 2. Monitor dropped packets
watch -n 1 'ip -6 -s -s neigh show'
# Look for FAILED or INCOMPLETE entries

# 3. Check gateway is responding to NDP
tcpdump -i eth0 -v icmp6
# Should see Neighbor Solicitation/Advertisement

# 4. Verify MTU not causing fragmentation
ping6 -M do -s 1472 <device_ipv6>
# Should work. If not, reduce MTU:
ip link set eth0 mtu 1280

# 5. Test direct connectivity
telnet <device_ipv6> 2323
# If this works but browser/app doesn't, it's an application issue
```


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

## 🔒 Code Quality & Security

This project has undergone comprehensive code review and all critical security and stability issues have been resolved.

### ✅ Critical Fixes Completed (P0 Priority)

All **10 critical (P0) issues** identified in code review have been fixed:

#### **1. Race Condition in Device Discovery** ✅
- **Location**: `ipv4_ipv6_gateway.py` (device discovery loop)
- **Issue**: Multiple threads could spawn discovery for the same MAC simultaneously
- **Impact**: Duplicate DHCP requests, corrupted device state, IPv6 address conflicts
- **Fix Applied**:
  - Device status set to "discovering" inside lock before thread spawn
  - Prevents duplicate discovery threads through atomic check-and-set
  - Added 3-attempt retry logic for thread spawning failures

#### **2. Resource Leak - Subprocess Cleanup** ✅
- **Location**: `ipv4_ipv6_gateway.py` (DHCPv6 manager)
- **Issue**: subprocess.Popen file descriptors leaked on exceptions
- **Impact**: File descriptor exhaustion after many DHCP requests → service failure
- **Fix Applied**:
  - Added `finally` block with proper process termination
  - Timeout handling with graceful termination → kill if needed
  - `wait()` called after kill to prevent zombie processes

#### **3. HAProxy Process Leak** ✅
- **Location**: `haproxy_manager.py` (reload function)
- **Issue**: Multiple HAProxy instances could run when reload called repeatedly
- **Impact**: Resource exhaustion, multiple processes consuming memory/CPU
- **Fix Applied**:
  - Enhanced process lifecycle management
  - Kills previous process before starting new one
  - Proper `wait()` after `kill()` to prevent zombies

#### **4. Unsafe File Copy in Install Script** ✅
- **Location**: `install.sh` (file installation)
- **Issue**: Files copied without existence validation
- **Impact**: Installation succeeds with missing files → service fails to start
- **Fix Applied**:
  - Validation loop checks all required files exist
  - Clear error messages with guidance if files missing
  - Added `set -u` to catch unbound variables

#### **5. Command Injection in Port Forwarding** ✅
- **Location**: `setup-port-forwarding.sh`
- **Issue**: Unquoted variables in iptables commands
- **Impact**: Security vulnerability - potential command injection, invalid iptables rules
- **Fix Applied**:
  - All variables quoted in shell commands
  - Port number validation (1-65535 range)
  - IPv4 address format validation
  - Applied to both add and remove functions

### 📊 Code Review Summary

**Total Issues Identified**: 55 across all files
- 🔴 **Critical (P0)**: 10 issues - **ALL FIXED** ✅
- 🟠 **High (P1)**: 24 issues - *Recommended for production*
- 🟡 **Medium/Low (P2-P3)**: 21 issues - *Nice to have*

### 🛡️ Security Enhancements

- **Thread Safety**: Race conditions eliminated with proper locking
- **Resource Management**: No subprocess or process leaks
- **Input Validation**: Port numbers and IP addresses validated
- **Variable Quoting**: All shell script variables properly quoted
- **Error Handling**: Comprehensive exception handling with cleanup

### 🏗️ Architecture Strengths

Despite issues found in review, the codebase has excellent fundamentals:
- ✅ **Well-organized**: Modular design with clear separation of concerns
- ✅ **Comprehensive**: Feature-complete with robust retry logic
- ✅ **Well-documented**: Extensive inline comments and README
- ✅ **Production-ready**: Core logic is sound with all critical bugs fixed

### 📈 Future Improvements

Lower priority improvements that could be made (P1-P3 issues):
- Enhanced MAC restoration guarantees in edge cases
- Additional timeout configurations for network operations
- Extended input validation across all API endpoints
- Performance optimizations for high device counts
- Additional logging verbosity levels

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
