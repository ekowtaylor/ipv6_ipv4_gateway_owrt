# IPv4↔IPv6 Dynamic Gateway

**Plug-and-play MAC learning gateway with DHCPv6 discovery for NanoPi R5C**

A Python-based service that automatically discovers IPv4 devices, learns their MAC addresses, requests IPv6 addresses via DHCPv6 (with MAC spoofing), and maintains transparent IPv4↔IPv6 translation using 464XLAT.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

---

## 📖 Table of Contents

- [Use Case](#-use-case)
- [Features](#-features)
- [Quick Start](#-quick-start)
  - [Automated Deployment](#automated-deployment)
  - [Manual Installation](#manual-installation)
- [Usage](#-usage)
- [Configuration](#️-configuration)
- [Troubleshooting](#-troubleshooting)
- [Advanced Topics](#-advanced-topics)

---

## 🎯 Use Case

Perfect for scenarios where:
- You have **hundreds of IPv4-only devices** that need to connect to **IPv6-only networks**
- Device **MACs must be pre-registered** on the IPv6 network firewall
- You need a **zero-configuration solution** for end devices
- You're deploying to environments where manual configuration isn't feasible

**Real-world example:** Deploying legacy IoT devices to a modern IPv6 infrastructure where the firewall only allows whitelisted MAC addresses.

---

## ✨ Features

- **🔍 Automatic Discovery**: Monitors ARP table to discover devices as they connect
- **🎭 MAC Spoofing**: Spoofs device MACs on IPv6 interface to request DHCPv6
- **🌐 464XLAT Translation**: Transparent IPv4↔IPv6 protocol conversion
- **💾 Persistent Storage**: Device mappings saved to JSON with automatic backups
- **📊 REST API**: Monitor status and devices via HTTP endpoints (port 5050)
- **🔄 Auto-Recovery**: Automatic retry with exponential backoff, survives reboots
- **📝 Comprehensive Logging**: Detailed logs for troubleshooting
- **🛠️ CLI Tools**: Helper scripts for quick status checks
- **🔍 Diagnostic Tool**: Built-in diagnostic and automated fix capabilities

### Architecture

```
[IPv4 Devices] ←→ eth1 (192.168.1.0/24) ← NanoPi R5C Gateway → eth0 (DHCPv6) ←→ [IPv6 Network]
                                          (Running this service)
```

**How it works:**
1. Device connects to eth1 (IPv4 side) and appears in ARP table
2. Service discovers MAC address automatically
3. Service spoofs MAC on eth0 (IPv6 side) and requests DHCPv6
4. IPv6 address assigned by DHCPv6 server (firewall sees pre-registered MAC)
5. 464XLAT handles IPv4↔IPv6 translation transparently
6. Device communicates over IPv6 network using IPv4 protocols

---

## 🚀 Quick Start

### Prerequisites

- **Hardware**: NanoPi R5C (or similar dual-NIC router)
- **OS**: OpenWrt (or any Linux with Python 3.7+)
- **Network**: IPv6 network with DHCPv6 server
- **Your Computer**: Bash shell, SSH access to router

### Automated Deployment

**Recommended method** - Deploy from your computer in one command:

```bash
# Clone or download this repository to your computer
cd /path/to/ipv6_ipv4_gateway_owrt

# Deploy to router (replace with your router's IP)
export ROUTER_IP=192.168.1.1
./quick-deploy.sh --auto-start

# SSH to router to apply network configuration
ssh root@$ROUTER_IP

# Run diagnostic to check status
/tmp/diagnose-and-fix.sh

# Apply network configuration (this will configure eth1 and eth0)
/tmp/diagnose-and-fix.sh --fix-network
# OR apply all fixes at once
/tmp/diagnose-and-fix.sh --fix-all

# Verify everything is working
gateway-diagnose
gateway-status
```

**What this does:**
1. ✅ Copies all files to router
2. ✅ Installs dependencies (Python, odhcp6c, iptables, etc.)
3. ✅ Installs the gateway service
4. ✅ Creates network configuration files
5. ✅ Starts the service (with `--auto-start`)
6. ✅ Applies network config when you run the diagnostic fix

### Manual Installation

If you prefer step-by-step control:

```bash
# 1. Copy files to router
scp *.py *.sh root@192.168.1.1:/tmp/

# 2. SSH to router
ssh root@192.168.1.1
cd /tmp

# 3. Choose installation mode:

# Option A: Full automatic (applies network config and starts service)
./install.sh --full-auto

# Option B: Apply network config only (manual start)
./install.sh --apply-network

# Option C: Auto-start service only (manual network config)
./install.sh --auto-start

# Option D: Safe mode (review before applying anything)
./install.sh

# 4. If you chose safe mode, manually apply network config:
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart

# 5. Start service (if not using --auto-start or --full-auto)
/etc/init.d/ipv4-ipv6-gateway start

# 6. Verify installation
gateway-status
```

### Installation Flags

| Flag | Network Config | Start Service | Use Case |
|------|----------------|---------------|----------|
| *(none)* | Creates only | Enables only | Safe review mode |
| `--apply-network` | ✅ **Applies** | Enables only | Configure network first |
| `--auto-start` | Creates only | ✅ **Starts** | Start service first |
| `--full-auto` | ✅ **Applies** | ✅ **Starts** | Zero-touch deployment |

---

## 📖 Usage

### Diagnostic Tool

**Check system health and apply fixes automatically:**

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
- ✅ IP address assignments (192.168.1.1)
- ✅ DHCP server status
- ✅ Gateway service status
- ✅ API server connectivity (port 5050)
- ✅ Firewall and forwarding settings

### Gateway Status

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

### Device Management

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
      "ipv6_address": "2001:db8::1",
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

### API Endpoints

The gateway provides a REST API on port 5050:

```bash
# Health check with detailed metrics
curl http://localhost:5050/health

# Full gateway status
curl http://localhost:5050/status

# List all devices
curl http://localhost:5050/devices

# Filter by status
curl http://localhost:5050/devices?status=active

# Get specific device by MAC
curl http://localhost:5050/devices/aa:bb:cc:dd:ee:01

# Export device mappings (admin)
curl -X POST http://localhost:5050/admin/export > backup.json

# Clear device cache (admin)
curl -X POST http://localhost:5050/admin/clear-cache \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'
```

### Service Management

**OpenWrt (init.d):**
```bash
# Start/stop/restart
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway stop
/etc/init.d/ipv4-ipv6-gateway restart

# Enable/disable auto-start
/etc/init.d/ipv4-ipv6-gateway enable
/etc/init.d/ipv4-ipv6-gateway disable

# Check status
/etc/init.d/ipv4-ipv6-gateway status
```

**Systemd (if available):**
```bash
# Start/stop/restart
systemctl start ipv4-ipv6-gateway
systemctl stop ipv4-ipv6-gateway
systemctl restart ipv4-ipv6-gateway

# Enable/disable auto-start
systemctl enable ipv4-ipv6-gateway
systemctl disable ipv4-ipv6-gateway

# Check status
systemctl status ipv4-ipv6-gateway
```

---

## ⚙️ Configuration

### Network Configuration

The installer creates network configuration at `/etc/ipv4-ipv6-gateway/network-config.uci`:

```uci
# eth1 (LAN) - IPv4 devices side
config interface 'lan'
    option device 'eth1'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'

# eth0 (WAN) - IPv6 network side
config interface 'wan'
    option device 'eth0'
    option proto 'dhcpv6'
    option reqaddress 'try'
    option reqprefix 'auto'
```

**Apply changes:**
```bash
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci commit
/etc/init.d/network restart
```

### DHCP Configuration

DHCP server configuration at `/etc/ipv4-ipv6-gateway/dhcp-config.uci`:

```uci
# DHCP server for LAN interface
config dhcp 'lan'
    option interface 'lan'
    option start '100'          # Start IP: 192.168.1.100
    option limit '150'          # Limit: 150 addresses
    option leasetime '12h'
    option dhcpv4 'server'
```

**Apply changes:**
```bash
uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
uci commit
/etc/init.d/dnsmasq restart
```

### Service Settings

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Network interfaces
ETH0_INTERFACE = 'eth0'  # IPv6 side (network)
ETH1_INTERFACE = 'eth1'  # IPv4 side (devices)

# Monitoring intervals
ARP_MONITOR_INTERVAL = 10       # Check for new devices every 10s
DEVICE_MONITOR_INTERVAL = 30    # Update status every 30s
DEVICE_STATUS_TIMEOUT = 300     # Mark inactive after 5 minutes

# DHCPv6 settings with retry
DHCPV6_TIMEOUT = 10             # Wait 10s for DHCPv6 response
DHCPV6_RETRY_COUNT = 3          # Retry 3 times on failure
DHCPV6_RETRY_DELAY = 5          # Initial delay: 5s (exponential backoff)

# API Server
API_ENABLED = True
API_HOST = '0.0.0.0'            # Bind to all interfaces (0.0.0.0)
API_PORT = 5050                 # API port

# Logging
LOG_LEVEL = 'INFO'              # INFO, DEBUG, WARNING, ERROR
LOG_FILE = '/var/log/ipv4-ipv6-gateway.log'
```

### Local Overrides

Create `/etc/ipv4-ipv6-gateway/config.py` for deployment-specific settings:

```python
# Override gateway_config.py settings here
LOG_LEVEL = 'DEBUG'
ARP_MONITOR_INTERVAL = 5
API_PORT = 8888
```

---

## 🔍 Troubleshooting

### Quick Diagnostic

**Always start with the diagnostic tool:**

```bash
# Run comprehensive diagnostic
gateway-diagnose

# See what's wrong and get fix suggestions
# Then apply fixes automatically
gateway-diagnose --fix-all
```

### Common Issues

#### 1. Ping to 192.168.1.1 Fails

**Symptom:** `ping 192.168.1.1` returns 100% packet loss

**Cause:** Network configuration not applied to eth1

**Fix:**
```bash
gateway-diagnose --fix-network
# OR manually:
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci commit
/etc/init.d/network restart
```

#### 2. Helper Scripts Can't Connect to API

**Symptom:** `gateway-status` returns "Failed to connect to API server"

**Cause:**
- Network config not applied (eth1 doesn't have 192.168.1.1)
- Service not running
- API server crashed

**Fix:**
```bash
# Check if service is running
ps | grep ipv4_ipv6_gateway

# Check if API is listening
netstat -tuln | grep 5050

# If service is running but API not accessible:
gateway-diagnose --fix-network

# If service is not running:
gateway-diagnose --fix-service
```

#### 3. Devices Not Being Discovered

**Symptom:** Connected devices don't appear in `gateway-devices`

**Cause:**
- ARP table not populated
- Device not getting DHCP lease
- Service not monitoring ARP

**Fix:**
```bash
# Check ARP table manually
ip neigh show dev eth1
# OR (if net-tools installed)
arp -i eth1 -n

# Ping device to force ARP entry
ping 192.168.1.100

# Check logs for discovery
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i discover

# Verify DHCP server is running
ps | grep dnsmasq
/etc/init.d/dnsmasq status

# Check DHCP leases
cat /tmp/dhcp.leases
```

#### 4. DHCPv6 Requests Failing

**Symptom:** Devices discovered but no IPv6 address assigned

**Cause:**
- eth0 not up or not configured for DHCPv6
- DHCPv6 server not responding
- MAC spoofing failed

**Fix:**
```bash
# Check eth0 status
ip link show eth0
ip -6 addr show eth0

# Test DHCPv6 manually
odhcp6c -P 0 eth0

# Check logs for DHCPv6 attempts
grep -i dhcpv6 /var/log/ipv4-ipv6-gateway.log

# Verify eth0 configuration
uci show network.wan
```

#### 5. Service Won't Start

**Symptom:** Service fails to start or immediately crashes

**Cause:**
- Missing dependencies
- Configuration errors
- Port 5050 already in use

**Fix:**
```bash
# Check dependencies
opkg list-installed | grep python3
opkg list-installed | grep odhcp6c

# Run service manually to see errors
python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py

# Check logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Check if port is in use
netstat -tlnp | grep 5050

# Reinstall dependencies
opkg update
opkg install python3 odhcp6c iptables ip-full
```

#### 6. API Not Responding

**Symptom:** API endpoints return connection refused or timeout

**Cause:**
- API not listening on expected interface
- Firewall blocking port 5050
- API server crashed

**Fix:**
```bash
# Test API connectivity
curl -v http://127.0.0.1:5050/health
curl -v http://192.168.1.1:5050/health

# Check if API is listening
netstat -tlnp | grep 5050
ss -tlnp | grep 5050

# Check API configuration
grep API_HOST /opt/ipv4-ipv6-gateway/gateway_config.py
# Should show: API_HOST = "0.0.0.0"

# Check firewall
iptables -L INPUT -n | grep 5050

# Check API logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i api
```

#### 7. SSH Disconnects During Network Config

**Symptom:** SSH session drops when applying network configuration

**Cause:** Normal behavior - network restart disconnects active connections

**Fix:**
```bash
# Wait 10-15 seconds for network to stabilize
# Reconnect to new IP
ssh root@192.168.1.1

# If you can't reconnect, router might have different IP
# Check router's physical display or connect via serial console
```

### Diagnostic Tool Details

The `gateway-diagnose` tool performs 14 comprehensive checks:

**Network Configuration:**
1. eth1 (LAN) configured with 192.168.1.1/24
2. eth1 runtime IP matches configuration
3. eth0 (WAN) configured for DHCPv6

**DHCP Server:**
4. DHCP server configured for LAN
5. dnsmasq (DHCP) is running

**Gateway Service:**
6. Service script exists
7. Service is enabled
8. Service process is running

**API Server:**
9. API server listening on port 5050
10. API accessible via 127.0.0.1:5050
11. API accessible via 192.168.1.1:5050

**Firewall & Forwarding:**
12. IPv4 forwarding enabled
13. IPv6 forwarding enabled
14. iptables FORWARD rules exist

### View Detailed Logs

```bash
# Last 50 lines
tail -50 /var/log/ipv4-ipv6-gateway.log

# Real-time monitoring
tail -f /var/log/ipv4-ipv6-gateway.log

# Filter for errors
grep -i error /var/log/ipv4-ipv6-gateway.log

# Filter for specific device
grep "aa:bb:cc:dd:ee:ff" /var/log/ipv4-ipv6-gateway.log

# System logs (OpenWrt)
logread | grep -i gateway
```

### Restore Original Configuration

If you need to restore the original network configuration:

```bash
# Restore network config
cp /etc/ipv4-ipv6-gateway/network.original /etc/config/network
cp /etc/ipv4-ipv6-gateway/dhcp.original /etc/config/dhcp
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
```

---

## 🔧 Advanced Topics

### Security Considerations

#### API Access

By default, the API listens on `0.0.0.0:5050` (all interfaces) for compatibility.

**To restrict to localhost only:**
```python
# Edit /opt/ipv4-ipv6-gateway/gateway_config.py
API_HOST = '127.0.0.1'  # Localhost only
```

**To enable remote access with firewall:**
```bash
# Add firewall rule to allow port 5050
iptables -A INPUT -p tcp --dport 5050 -j ACCEPT
```

**⚠️ WARNING**: The API has no authentication. Only expose to trusted networks.

#### MAC Spoofing

This service spoofs MAC addresses to request DHCPv6. Ensure:
- You have authorization to use MAC spoofing on your network
- Your IPv6 network firewall is configured to expect this behavior
- Device MACs are properly registered on the firewall

#### Firewall Configuration

```bash
# Allow forwarding between interfaces
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### File Structure

```
/opt/ipv4-ipv6-gateway/           # Service installation
├── ipv4_ipv6_gateway.py          # Main service
├── gateway_config.py             # Configuration
└── gateway_api_server.py         # REST API server

/etc/ipv4-ipv6-gateway/           # Configuration directory
├── devices.json                  # Device mappings (persistent)
├── devices.json.bak              # Automatic backup
├── network-config.uci            # Network config
├── dhcp-config.uci               # DHCP config
├── network.original              # Original network backup
├── dhcp.original                 # Original DHCP backup
└── config.py                     # Local overrides (optional)

/var/log/                         # Logs
└── ipv4-ipv6-gateway.log         # Service logs

/usr/bin/                         # Helper scripts
├── gateway-status                # Quick status check
├── gateway-devices               # List devices
└── gateway-diagnose              # Diagnostic tool

/etc/init.d/                      # Service scripts
└── ipv4-ipv6-gateway             # Init.d script (OpenWrt)

/etc/systemd/system/              # Systemd (if applicable)
└── ipv4-ipv6-gateway.service     # Systemd unit file
```

### Uninstallation

```bash
# Basic uninstall (leaves network config unchanged)
bash uninstall.sh

# Uninstall AND restore original network config
bash uninstall.sh --restore-network
```

**Safe uninstall**: Everything is backed up to a timestamped directory:
```
/root/ipv4-ipv6-gateway_backup_YYYYMMDD_HHMMSS/
```

### Testing & Verification

```bash
# Run comprehensive health check
bash verify.sh

# Manual testing workflow
/etc/init.d/ipv4-ipv6-gateway start
gateway-status
# Connect test device to eth1
tail -f /var/log/ipv4-ipv6-gateway.log
# Wait 10-15 seconds for discovery
gateway-devices
curl http://localhost:5050/devices
```

### Performance Tuning

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Faster discovery (uses more CPU)
ARP_MONITOR_INTERVAL = 5        # Check every 5s instead of 10s

# Slower discovery (uses less CPU)
ARP_MONITOR_INTERVAL = 30       # Check every 30s

# Adjust device timeout
DEVICE_STATUS_TIMEOUT = 600     # 10 minutes instead of 5

# Increase max devices
MAX_DEVICES = 2000              # Default: 1000
```

### Custom Integration

**Webhook notifications (example):**

```python
# Add to /etc/ipv4-ipv6-gateway/config.py
import requests

def on_device_discovered(device):
    """Called when new device is discovered"""
    webhook_url = "https://your-webhook.com/notify"
    requests.post(webhook_url, json={
        "mac": device.mac_address,
        "ipv4": device.ipv4_address,
        "ipv6": device.ipv6_address
    })
```

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
- **464XLAT** for IPv4/IPv6 translation

---

## 📞 Support

- **Issues**: Open an issue on GitHub
- **Logs**: Check `/var/log/ipv4-ipv6-gateway.log` for detailed error messages
- **Diagnostic**: Run `gateway-diagnose` for automated troubleshooting

---

## 🗺️ Roadmap

- [ ] Add web UI for monitoring
- [ ] Add authentication for API endpoints
- [ ] Add metrics/Prometheus exporter
- [ ] Add IPv6 prefix delegation support
- [ ] Add automatic failover for multiple IPv6 uplinks
- [ ] Add device grouping/tagging
- [ ] Add rate limiting for device discovery

---

**Made with ❤️ for making IPv4 devices work seamlessly on IPv6 networks**
