# IPv4↔IPv6 Dynamic Gateway

**Plug-and-play MAC learning gateway with DHCPv6 discovery for NanoPi R5C**

A Python-based service that automatically discovers IPv4 devices, learns their MAC addresses, requests IPv6 addresses via DHCPv6 (with MAC spoofing), and maintains transparent IPv4↔IPv6 translation using 464XLAT.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

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
- **🔄 Auto-Recovery**: Automatic retry on failures, survives reboots
- **📝 Comprehensive Logging**: Detailed logs for troubleshooting
- **🛠️ CLI Tools**: Helper scripts for quick status checks

---

## 🏗️ Architecture

```
[IPv4 Devices] ←→ eth1 ← NanoPi R5C Gateway → eth0 ←→ [IPv6 Network]
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

### Installation

```bash
# 1. SSH into your router
ssh root@192.168.1.1

# 2. Download the project (or SCP files to router)
# wget https://github.com/yourusername/ipv6_ipv4_gateway_owrt/archive/main.zip
# unzip main.zip && cd ipv6_ipv4_gateway_owrt-main

# 3. Run installer
bash install.sh

# 4. Configure network interfaces
uci import < /etc/ipv4-ipv6-gateway/network-config.uci
/etc/init.d/network restart

# 5. Start the service
/etc/init.d/ipv4-ipv6-gateway start

# 6. Check status
gateway-status
```

**That's it!** Plug in an IPv4 device and watch it get discovered automatically.

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
# All devices
gateway-devices

# Active devices only
gateway-devices active

# Inactive devices only
gateway-devices inactive
```

### Monitor Logs

```bash
# Real-time logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Search for specific MAC
grep "aa:bb:cc:dd:ee:ff" /var/log/ipv4-ipv6-gateway.log
```

### API Endpoints

```bash
# Health check
curl http://localhost:5050/health

# Full status
curl http://localhost:5050/status

# List all devices
curl http://localhost:5050/devices

# Get specific device
curl http://localhost:5050/devices/aa:bb:cc:dd:ee:01

# Export device mappings
curl -X POST http://localhost:5050/admin/export > backup.json

# Clear device cache
curl -X POST http://localhost:5050/admin/clear-cache \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'
```

---

## ⚙️ Configuration

### Network Interfaces

Edit `/etc/ipv4-ipv6-gateway/network-config.uci`:

```
config interface 'lan'
    option ifname 'eth1'         # IPv4 devices side
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'

config interface 'wan'
    option ifname 'eth0'         # IPv6 network side
    option proto 'dhcpv6'
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

# DHCPv6 settings
DHCPV6_TIMEOUT = 10             # Wait 10s for DHCPv6 response
DHCPV6_RETRY_COUNT = 3          # Retry 3 times on failure

# API Server
API_ENABLED = True
API_HOST = '127.0.0.1'          # Localhost only (secure)
API_PORT = 5050

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

## 🔧 Service Management

### Systemd (if available)

```bash
# Start/stop service
systemctl start ipv4-ipv6-gateway
systemctl stop ipv4-ipv6-gateway
systemctl restart ipv4-ipv6-gateway

# Enable/disable auto-start
systemctl enable ipv4-ipv6-gateway
systemctl disable ipv4-ipv6-gateway

# Check status
systemctl status ipv4-ipv6-gateway
```

### Init.d (OpenWrt)

```bash
# Start/stop service
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway stop
/etc/init.d/ipv4-ipv6-gateway restart

# Enable/disable auto-start
/etc/init.d/ipv4-ipv6-gateway enable
/etc/init.d/ipv4-ipv6-gateway disable

# Check status
/etc/init.d/ipv4-ipv6-gateway status
```

---

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check for Python errors
python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py

# Check logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Check if port is in use
netstat -tlnp | grep 5050
```

### Devices Not Discovered

```bash
# Check ARP table
arp -i eth1 -n

# Ping device to populate ARP
ping 192.168.1.100

# Check logs for discovery
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i discover
```

### IPv6 Not Being Requested

```bash
# Check eth0 is up
ip link show eth0

# Test DHCPv6 manually
odhcp6c -P 0 eth0

# Check assigned IPv6 addresses
ip -6 addr show eth0
```

### No API Response

```bash
# Test API connectivity
curl -v http://127.0.0.1:5050/health

# Check API is listening
netstat -tlnp | grep 5050

# Check API logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i api
```

For more troubleshooting tips, see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).

---

## 📁 File Structure

```
/opt/ipv4-ipv6-gateway/           # Service installation
├── ipv4_ipv6_gateway.py          # Main service
├── gateway_config.py             # Configuration
└── gateway_api_server.py         # REST API server

/etc/ipv4-ipv6-gateway/           # Configuration directory
├── devices.json                  # Device mappings (persistent)
├── devices.json.bak              # Automatic backup
├── network-config.uci            # Network config sample
└── config.py                     # Local overrides (optional)

/var/log/                         # Logs
└── ipv4-ipv6-gateway.log         # Service logs

/usr/bin/                         # Helper scripts
├── gateway-status                # Quick status check
└── gateway-devices               # List devices

/etc/init.d/                      # Service scripts
└── ipv4-ipv6-gateway             # Init.d script (OpenWrt)

/etc/systemd/system/              # Systemd (if applicable)
└── ipv4-ipv6-gateway.service     # Systemd unit file
```

---

## 🗑️ Uninstallation

```bash
# Basic uninstall (leaves network config unchanged)
bash uninstall.sh

# Uninstall AND restore original network config
bash uninstall.sh --restore-network
```

**Safe uninstall**: Everything is backed up to a timestamped directory before deletion:
```
/root/ipv4-ipv6-gateway_backup_YYYYMMDD_HHMMSS/
```

---

## 🧪 Testing & Verification

### Verification Script

```bash
# Run comprehensive health check
bash verify.sh

# Checks:
# - Service status (systemd/init.d)
# - Process presence
# - API health (/health, /status)
# - Network interfaces
# - Recent logs
```

### Manual Testing

```bash
# 1. Start service
/etc/init.d/ipv4-ipv6-gateway start

# 2. Check it's running
gateway-status

# 3. Connect test device to eth1

# 4. Watch discovery happen (10-15 seconds)
tail -f /var/log/ipv4-ipv6-gateway.log

# 5. Verify device appears
gateway-devices

# 6. Check API
curl http://localhost:5050/devices
```

---

## 🔐 Security Considerations

### API Access

By default, the API listens on `127.0.0.1:5050` (localhost only).

**To enable remote access:**

1. Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:
   ```python
   API_HOST = '0.0.0.0'  # Listen on all interfaces
   ```

2. Add firewall rule:
   ```bash
   iptables -A INPUT -p tcp --dport 5050 -j ACCEPT
   ```

3. **⚠️ WARNING**: The API has no authentication. Only expose to trusted networks.

### MAC Spoofing

This service spoofs MAC addresses to request DHCPv6. Ensure:
- You have authorization to use MAC spoofing on your network
- Your IPv6 network firewall is configured to expect this behavior
- Device MACs are properly registered on the firewall

### Firewall Configuration

```bash
# Allow forwarding between interfaces
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
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

- **Documentation**: See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed deployment instructions
- **Issues**: Open an issue on GitHub
- **Logs**: Check `/var/log/ipv4-ipv6-gateway.log` for detailed error messages

---

## 🗺️ Roadmap

- [ ] Add DHCP relay support (alternative to 464XLAT)
- [ ] Add web UI for monitoring
- [ ] Add authentication for API endpoints
- [ ] Add metrics/Prometheus exporter
- [ ] Add IPv6 prefix delegation support
- [ ] Add automatic failover for multiple IPv6 uplinks
- [ ] Add device grouping/tagging
- [ ] Add rate limiting for device discovery

---

**Made with ❤️ for making IPv4 devices work seamlessly on IPv6 networks**
