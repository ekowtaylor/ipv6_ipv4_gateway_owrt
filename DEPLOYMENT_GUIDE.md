# IPv4↔IPv6 Dynamic Gateway - Python Implementation
## NanoPi R5C with OpenWrt - Plug-and-Play Deployment

---

## Overview

This is a complete Python-based implementation of an IPv4↔IPv6 gateway that automatically:
- Discovers IPv4 devices connecting to eth0
- Learns their MAC addresses
- Spoofs those MACs on eth1 to request DHCPv6
- Discovers assigned IPv6 addresses
- Translates traffic between IPv4 and IPv6 transparently via 464XLAT
- Provides a REST API for monitoring and management

**Key advantage over shell scripts:** Maintainable, testable, extensible Python code your team can easily modify.

---

## Prerequisites

### Hardware
- NanoPi R5C Mini Router
- Power supply (USB-C)
- Two Ethernet cables
- Computer for SSH

### Network Setup
- eth0: Connected to IPv4 devices
- eth1: Connected to IPv6 network
- All device MACs pre-registered on IPv6 network firewall

### Knowledge
- Basic Linux/SSH
- Python familiarity helpful but not required
- Understanding of IPv4/IPv6 basics

---

## Quick Start (5 minutes)

### Step 1: Flash OpenWrt

```bash
# Download NanoPi R5C OpenWrt image from:
# https://downloads.openwrt.org/

# Flash using Balena Etcher or dd
# Boot the router
```

### Step 2: SSH into Router

```bash
ssh root@192.168.1.1
# (password is empty, just press Enter on first boot)
```

### Step 3: Download and Run Installer

```bash
# Clone the files to the router (via SCP or copy-paste)
# Then run:
bash /path/to/install.sh
```

### Step 4: Configure Network

```bash
# Apply network configuration
uci import < /etc/ipv4-ipv6-gateway/network-config.uci
/etc/init.d/network restart

# Verify interfaces are up
ifconfig eth0
ifconfig eth1
```

### Step 5: Start Service

```bash
# Using systemd (if available)
systemctl start ipv4-ipv6-gateway
systemctl status ipv4-ipv6-gateway

# Or using init.d
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway status
```

### Step 6: Test

```bash
# Check status
gateway-status

# Should show running service and discovered devices
# Plug in an IPv4 device to eth0
# Watch logs for discovery
tail -f /var/log/ipv4-ipv6-gateway.log

# After ~15 seconds, device should appear:
gateway-devices
```

---

## Architecture

```
┌─────────────────┐
│  IPv4 Devices   │
│  (any MAC)      │
└────────┬────────┘
         │ eth0 (IPv4)
         │
    ┌────▼──────────────────────┐
    │  NanoPi R5C Router        │
    │  ┌──────────────────────┐ │
    │  │ MAC Learning Daemon  │ │  Discovers device MAC
    │  │ (Python Service)     │ │  Stores in JSON
    │  └──────────────────────┘ │
    │  ┌──────────────────────┐ │
    │  │ DHCPv6 Manager       │ │  Spoofs MAC on eth1
    │  │ (odhcp6c wrapper)    │ │  Requests IPv6 address
    │  └──────────────────────┘ │
    │  ┌──────────────────────┐ │
    │  │ 464XLAT Translator   │ │  Converts IPv4↔IPv6
    │  │ (OpenWrt package)    │ │  Transparent to devices
    │  └──────────────────────┘ │
    │  ┌──────────────────────┐ │
    │  │ REST API Server      │ │  Port 8080
    │  │ (Monitoring)         │ │  Status, devices, export
    │  └──────────────────────┘ │
    │                            │
    └────┬──────────────────────┬┘
         │ eth1 (IPv6)          │
         │                      │
    ┌────▼────────────┐ ┌──────▼────┐
    │ IPv6 Network    │ │ IPv6 Admin │
    │ (e.g., 2001:... │ │ (sees MAC) │
    └─────────────────┘ └───────────┘
```

---

## File Structure

```
/opt/ipv4-ipv6-gateway/
├── ipv4_ipv6_gateway.py      # Main service
├── gateway_config.py          # Configuration
└── gateway_api_server.py      # REST API server

/etc/ipv4-ipv6-gateway/
├── devices.json               # Persistent device mappings
├── devices.json.bak           # Backup
└── network-config.uci         # Network settings

/etc/systemd/system/
└── ipv4-ipv6-gateway.service  # Systemd unit

/etc/init.d/
└── ipv4-ipv6-gateway          # Init.d script

/usr/local/bin/
├── gateway-status             # Quick status helper
└── gateway-devices            # List devices helper

/var/log/
└── ipv4-ipv6-gateway.log      # Service logs
```

---

## REST API Endpoints

### Health & Status

```bash
# Health check
curl http://localhost:8080/health
# Response: {"status": "ok"}

# Full gateway status
curl http://localhost:8080/status
# Response: {
#   "running": true,
#   "device_count": 5,
#   "active_devices": 3,
#   "devices": {...},
#   "eth0_up": true,
#   "eth1_up": true,
#   ...
# }
```

### Devices

```bash
# List all devices
curl http://localhost:8080/devices

# List only active devices
curl http://localhost:8080/devices?status=active

# List inactive devices
curl http://localhost:8080/devices?status=inactive

# Get specific device
curl http://localhost:8080/devices/aa:bb:cc:dd:ee:01

# Export all devices
curl -X POST http://localhost:8080/admin/export
```

### Helper Scripts

```bash
# Quick status (pretty-printed JSON)
gateway-status

# List devices
gateway-devices           # All devices
gateway-devices active    # Active only
gateway-devices inactive  # Inactive only
```

---

## Configuration

### Primary Configuration

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Network interfaces
ETH0_INTERFACE = 'eth0'  # IPv4 side
ETH1_INTERFACE = 'eth1'  # IPv6 side

# DHCPv6 settings
DHCPV6_TIMEOUT = 10      # seconds to wait for DHCPv6
DHCPV6_RETRY_COUNT = 3   # retry attempts

# Monitoring intervals
ARP_MONITOR_INTERVAL = 10       # Check for new devices every 10s
DEVICE_MONITOR_INTERVAL = 30    # Update status every 30s

# API Server
API_ENABLED = True
API_HOST = '127.0.0.1'
API_PORT = 8080

# Logging
LOG_LEVEL = 'INFO'  # INFO, DEBUG, WARNING, ERROR
```

### Override Configuration

Create `/etc/ipv4-ipv6-gateway/config.py` for local overrides:

```python
# Custom settings (overrides gateway_config.py)
LOG_LEVEL = 'DEBUG'
ARP_MONITOR_INTERVAL = 5
API_PORT = 8888
```

### Network Configuration

Edit network via UCI:

```bash
# View current config
uci show network

# Edit eth0 (IPv4 side)
uci set network.lan.ifname='eth0'
uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.1.1'
uci set network.lan.netmask='255.255.255.0'

# Edit eth1 (IPv6 side)
uci set network.wan.ifname='eth1'
uci set network.wan.proto='dhcpv6'

# Apply changes
uci commit network
/etc/init.d/network restart
```

---

## Logging & Monitoring

### View Logs

```bash
# Real-time logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Last 50 lines
tail -50 /var/log/ipv4-ipv6-gateway.log

# Search logs
grep "discovered" /var/log/ipv4-ipv6-gateway.log
grep "ERROR" /var/log/ipv4-ipv6-gateway.log
grep "MAC.*192.168" /var/log/ipv4-ipv6-gateway.log
```

### Service Status

```bash
# Using systemd
systemctl status ipv4-ipv6-gateway
systemctl is-active ipv4-ipv6-gateway

# Using init.d
/etc/init.d/ipv4-ipv6-gateway status

# Check if process running
ps aux | grep ipv4_ipv6_gateway
```

### Performance Monitoring

```bash
# Memory usage
free -h

# Check interface status
ip link show eth0
ip link show eth1

# Check IPv6 addresses
ip -6 addr show eth1

# Monitor active connections
netstat -an | grep ESTABLISHED | wc -l

# Check firewall rules
iptables -L -n
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check for Python errors
python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py

# Check systemd logs
journalctl -u ipv4-ipv6-gateway -n 50

# Check if port 8080 is in use
netstat -tlnp | grep 8080

# Restart service
systemctl restart ipv4-ipv6-gateway
```

### Devices Not Being Discovered

```bash
# Check eth0 is up and has IP
ifconfig eth0
ip addr show eth0

# Check ARP table
arp -i eth0 -n

# Check logs for "discovered" messages
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i "discover\|new"

# Manually ping an IPv4 device to populate ARP
ping 192.168.1.2
# Then check again:
arp -i eth0 -n
```

### IPv6 Not Being Requested

```bash
# Check eth1 is up
ifconfig eth1
ip link show eth1

# Check if odhcp6c is available
which odhcp6c

# Test DHCPv6 manually
odhcp6c -P 0 eth1

# Check IPv6 addresses on eth1
ip -6 addr show eth1

# Check API response
curl http://localhost:8080/devices
# Look for devices with "discovering" status
```

### No API Response

```bash
# Check if API server is running
netstat -tlnp | grep 8080

# Test connectivity
curl -v http://127.0.0.1:8080/health

# Check for API errors in logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i "api\|server"

# Try different port if 8080 is blocked
# Edit gateway_config.py and set API_PORT = 8888
```

### Translation Not Working

```bash
# Check 464XLAT status
ps aux | grep 464xlat
/etc/init.d/464xlat status

# Check forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv6/conf/all/forwarding

# Check firewall rules
iptables -L -v
ip6tables -L -v

# Test connectivity from device
# Plug in an IPv4 device and try:
# ping 8.8.8.8 (should work via IPv6 translation)

# Monitor packets
tcpdump -i eth0 -n
tcpdump -i eth1 -n
```

### Device JSON File Issues

```bash
# Backup and reset devices
cp /etc/ipv4-ipv6-gateway/devices.json /etc/ipv4-ipv6-gateway/devices.json.broken
echo '{}' > /etc/ipv4-ipv6-gateway/devices.json

# Restart service (will rediscover)
systemctl restart ipv4-ipv6-gateway
```

---

## Deployment Checklist

For each NanoPi R5C unit being deployed:

- [ ] Flash OpenWrt firmware
- [ ] SSH into device
- [ ] Download/copy install files
- [ ] Run `install.sh`
- [ ] Configure network interfaces
- [ ] Start service
- [ ] Verify service is running
- [ ] Connect test device to eth0
- [ ] Verify device discovered
- [ ] Check API endpoints
- [ ] Enable service to auto-start on boot
- [ ] Test after reboot
- [ ] Document unit serial number and deployment date

---

## Scaling to Hundreds of Devices

### Performance Tuning

```bash
# Increase connection tracking
echo 'net.netfilter.nf_conntrack_max=262144' >> /etc/sysctl.conf
sysctl -p

# Increase ARP cache
echo 'net.ipv4.neigh.default.gc_thresh3=65536' >> /etc/sysctl.conf
sysctl -p

# Tune 464XLAT if needed
# (edit OpenWrt 464xlat configuration)
```

### Monitoring Multiple Devices

```bash
# Script to monitor all active devices
#!/bin/bash
while true; do
    clear
    echo "Active Devices:"
    curl -s http://localhost:8080/devices?status=active | python3 -m json.tool
    sleep 5
done
```

### Bulk Export

```bash
# Export all device mappings to JSON file
curl -X POST http://localhost:8080/admin/export > devices_export.json

# Import to documentation/database
# Process with: jq '.devices | keys' devices_export.json
```

---

## Maintenance

### Regular Tasks

```bash
# Daily: Check service is running
systemctl status ipv4-ipv6-gateway

# Weekly: Review logs for errors
grep ERROR /var/log/ipv4-ipv6-gateway.log

# Monthly: Export device list
curl -X POST http://localhost:8080/admin/export > devices_$(date +%Y%m%d).json

# Quarterly: Test after reboot
reboot
# Verify service starts automatically
systemctl status ipv4-ipv6-gateway
```

### Updating

```bash
# Update the Python files
cp ipv4_ipv6_gateway.py /opt/ipv4-ipv6-gateway/
cp gateway_config.py /opt/ipv4-ipv6-gateway/
cp gateway_api_server.py /opt/ipv4-ipv6-gateway/

# Restart service
systemctl restart ipv4-ipv6-gateway

# Verify
systemctl status ipv4-ipv6-gateway
```

### Backups

Device mappings are automatically saved to:
```
/etc/ipv4-ipv6-gateway/devices.json
/etc/ipv4-ipv6-gateway/devices.json.bak
```

Export periodically:
```bash
curl -X POST http://localhost:8080/admin/export > backup_$(date +%s).json
```

---

## Development & Extension

### Adding Custom Logic

Edit `/opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py`:

```python
class GatewayService:
    # Add custom methods here
    
    def custom_hook_on_device_discovered(self, device):
        """Called when new device is discovered"""
        # Your custom logic
        pass
```

### Adding API Endpoints

Edit `/opt/ipv4-ipv6-gateway/gateway_api_server.py`:

```python
def do_GET(self):
    # Add new endpoint
    if path == '/custom/endpoint':
        self.handle_custom()

def handle_custom(self):
    """Custom endpoint handler"""
    self.send_json_response({'custom': 'data'})
```

### Testing Locally

```bash
# Run service in foreground with debug output
python3 ipv4_ipv6_gateway.py

# Test API in another terminal
curl http://localhost:8080/status
```

---

## Support & Resources

- **Logs:** `/var/log/ipv4-ipv6-gateway.log`
- **Config:** `/etc/ipv4-ipv6-gateway/`
- **API:** `http://localhost:8080/`
- **Source:** `/opt/ipv4-ipv6-gateway/`

For issues:
1. Check logs: `tail -f /var/log/ipv4-ipv6-gateway.log`
2. Check API: `curl http://localhost:8080/status`
3. Verify network: `ifconfig`, `ip -6 addr show`
4. Restart service: `systemctl restart ipv4-ipv6-gateway`

---

## Next Steps

1. **Deploy:** Run installer on your R5C units
2. **Register MACs:** Provide device MAC list to IPv6 network admin
3. **Configure:** Edit `/opt/ipv4-ipv6-gateway/gateway_config.py` as needed
4. **Monitor:** Use `gateway-status` and API endpoints
5. **Scale:** Deploy multiple units as needed
6. **Maintain:** Regular backups and log checks
