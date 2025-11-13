# IPv4↔IPv6 Dual-Stack Gateway

**Single-device gateway with MAC spoofing for NanoPi R5C running OpenWrt**

Automatically discovers a device on eth1, spoofs its MAC on eth0 to request DHCP (IPv4/IPv6), and provides transparent connectivity through IPv4-only, IPv6-only, or dual-stack networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-compatible-brightgreen.svg)](https://openwrt.org/)

## Key Features

- ✅ **Single-device mode** - Simple, no threading (71% less code than multi-device version)
- ✅ **Automatic discovery** - Detects device via ARP on eth1
- ✅ **MAC spoofing** - Requests DHCP using device MAC on eth0
- ✅ **Dual-stack** - Works with IPv4, IPv6, or both
- ✅ **Robust DHCP** - 10 retries IPv4, 5 retries IPv6 with exponential backoff
- ✅ **SLAAC + DHCPv6** - Full IPv6 support with automatic fallback
- ✅ **Port forwarding** - IPv4 NAT + IPv6→IPv4 proxying (socat/HAProxy)
- ✅ **WAN monitoring** - Auto-detects network changes and reconfigures
- ✅ **Console-safe** - Works without network (KVM/serial console)

## Network Topology

```
[Device] ←→ eth1 (LAN) ←→ Gateway ←→ eth0 (WAN) ←→ [Firewall] ←→ [Network]
      192.168.1.x      MAC Spoofing     DHCP v4/v6    MAC Check    IPv4/IPv6/Both
```

**Critical:** Device MAC must be registered with upstream firewall before it can obtain WAN addresses.

---

## Quick Start

### Prerequisites

- NanoPi R5C (or similar dual-NIC router)
- OpenWrt (or Linux with Python 3.7+)
- IPv4/IPv6/dual-stack network with MAC-based firewall
- Device MAC registered with firewall

### Installation

```bash
# 1. Clone repository
git clone <repo-url>
cd ipv6_ipv4_gateway_owrt

# 2. Deploy to router
./quick-deploy.sh
# Enter router IP when prompted (default: 192.168.1.1)
```

### Verify

```bash
# SSH to router
ssh root@192.168.1.1

# Check status
gateway-status-direct

# Watch logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Run diagnostics
gateway-diagnose
```

---

## How It Works

**Device Connection Flow:**

1. Device connects to eth1 → Gets 192.168.1.x from gateway DHCP
2. Gateway discovers device via ARP → Learns MAC address
3. Gateway spoofs MAC on eth0 → Requests DHCPv4/v6 from upstream
4. Upstream firewall checks MAC → Allows if registered
5. Gateway gets WAN IP(s) → Configures port forwarding
6. Device has transparent WAN access → IPv4 and/or IPv6

**Supported Network Types:**

| Network | Behavior |
|---------|----------|
| IPv4-only | Requests DHCPv4 only, NAT for device |
| IPv6-only | Requests SLAAC/DHCPv6, IPv6→IPv4 proxy with SNAT |
| Dual-stack | Requests both protocols, full dual-stack access |

---

## Configuration

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Network interfaces
WAN_INTERFACE = "eth0"
LAN_INTERFACE = "eth1"
LAN_GATEWAY_IP = "192.168.1.1"

# DHCP settings
DHCPV4_TIMEOUT = 15      # seconds per attempt
DHCPV4_RETRIES = 10      # total attempts
DHCPV6_TIMEOUT = 10
DHCPV6_RETRIES = 5

# Check interval
CHECK_INTERVAL = 15      # seconds between device checks

# Port forwarding (IPv4 NAT)
PORT_FORWARDS = {
    8080: 80,    # HTTP
    2323: 23,    # Telnet
    8443: 443,   # HTTPS
    2222: 22,    # SSH
}

# IPv6→IPv4 proxy ports
IPV6_PROXY_PORTS = {
    80: 80,      # HTTP (firewall must allow)
    23: 23,      # Telnet (firewall must allow)
}
```

---

## Port Forwarding

### Automatic Setup

When device connects, ports are automatically forwarded:

**IPv4 (NAT):**
```
Client → Gateway WAN:8080 → iptables DNAT → Device LAN:80
Example: curl http://10.1.2.50:8080
```

**IPv6 (Proxy with SNAT):**
```
Client → Gateway IPv6:80 → socat/HAProxy + SNAT → Device LAN:80
Example: curl http://[2001:db8::1234]:80
Device sees traffic from 192.168.1.1 (gateway LAN IP)
```

**Why SNAT is critical:** Without SNAT, device sees requests from IPv6 addresses and can't respond (no IPv6 routing). SNAT makes device see requests from gateway LAN IP, allowing proper response routing.

### Manual Port Forwarding

```bash
# Add custom port
gateway-port-forward add 9000 192.168.1.100 9000

# List forwards
gateway-port-forward list

# Remove forward
gateway-port-forward remove 8080
```

### Proxy Backends

| Backend | Memory | Use Case |
|---------|--------|----------|
| **socat** | ~2MB | Lightweight, simple setups |
| **HAProxy** | ~10MB | Production, stats dashboard, advanced logging |

Switch backends in `gateway_config.py`:
```python
IPV6_PROXY_BACKEND = "socat"  # or "haproxy"
```

HAProxy stats: `http://192.168.1.1:8404/stats`

---

## Management

### Service Control

```bash
# OpenWrt init.d
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway stop
/etc/init.d/ipv4-ipv6-gateway restart
/etc/init.d/ipv4-ipv6-gateway status

# Enable/disable auto-start
/etc/init.d/ipv4-ipv6-gateway enable
/etc/init.d/ipv4-ipv6-gateway disable
```

### CLI Commands

**Console-safe (work without network):**
```bash
gateway-status-direct       # Show device status
gateway-devices-direct      # Show device info
```

**With network:**
```bash
gateway-status              # Overall status
gateway-devices             # Device details
gateway-diagnose            # Run 14 diagnostic checks
gateway-diagnose --fix-all  # Auto-fix issues
gateway-port-forward        # Manage port forwards
```

### Monitoring

```bash
# Real-time logs
tail -f /var/log/ipv4-ipv6-gateway.log

# Filter by device MAC
grep "aa:bb:cc:dd:ee:ff" /var/log/ipv4-ipv6-gateway.log

# Check device state
cat /etc/ipv4-ipv6-gateway/device.json
```

---

## Troubleshooting

### Quick Diagnostic

```bash
# Run comprehensive check (14 tests)
gateway-diagnose

# Apply all fixes automatically
gateway-diagnose --fix-all
```

### Common Issues

**1. Device doesn't get WAN address**

Most common: MAC not registered with firewall (YOUR responsibility)

```bash
# Check logs for DHCP errors
tail -50 /var/log/ipv4-ipv6-gateway.log | grep ERROR

# Verify device discovered
gateway-status-direct

# Wait for retries (up to 2.5 minutes with 10 retries)
# This allows time for firewall MAC registration to propagate
```

**2. IPv6→IPv4 proxy not working**

Responses not getting back to IPv6 clients?

```bash
# Check ip6tables SNAT rules (critical for return traffic)
ip6tables -t nat -L POSTROUTING -n -v
# Should show SNAT rules for each proxy port

# Test from gateway
curl http://192.168.1.100:80

# Monitor traffic
tcpdump -i eth1 -n port 80
# Should see traffic FROM 192.168.1.1 TO device
# Device should respond TO 192.168.1.1
```

**3. Gateway service won't start**

```bash
# Check for errors
/etc/init.d/ipv4-ipv6-gateway start

# View logs
tail -50 /var/log/ipv4-ipv6-gateway.log

# Run diagnostic
gateway-diagnose --fix-all

# Check dependencies
which python3 udhcpc odhcp6c
```

**4. WAN network change not detected**

```bash
# Check WAN monitoring is enabled
grep MONITOR_WAN_CHANGES /opt/ipv4-ipv6-gateway/gateway_config.py
# Should be: True

# Manually trigger
/etc/init.d/ipv4-ipv6-gateway restart
```

### Diagnostic Scripts

```bash
diagnose-and-fix.sh              # Comprehensive diagnostic
diagnose-dhcp-requests.sh        # DHCP debugging
diagnose-ipv6-connectivity.sh    # IPv6 testing
diagnose-proxy-complete.sh       # Proxy testing
```

---

## Advanced Topics

### IPv6 SNAT Fix (Critical!)

**Problem:** IPv6→IPv4 proxy requests work, but responses don't come back.

**Root cause:** Device sees requests from IPv6 addresses it can't route to.

**Solution:** ip6tables SNAT makes device see requests from gateway LAN IP (192.168.1.1):

```bash
# SNAT rule (automatically applied by service)
ip6tables -t nat -A POSTROUTING \
  -d 192.168.1.100 \
  -p tcp --dport 80 \
  -j SNAT --to-source 192.168.1.1
```

**Flow with SNAT:**
1. IPv6 Client → Gateway IPv6:80
2. socat/HAProxy forwards to device with SNAT
3. Device sees request from 192.168.1.1
4. Device responds to 192.168.1.1
5. Gateway forwards response to IPv6 client
6. ✅ Full round trip works!

See `docs/IPv6_RETURN_PATH_FIX.md` for complete details.

### WAN Network Auto-Detection

Gateway automatically detects WAN network changes:

1. Monitors eth0 every 15 seconds
2. Detects IPv4/IPv6 address changes
3. Clears device WAN addresses
4. Triggers automatic re-discovery
5. Device gets new WAN IPs

Example:
```
Network A (192.168.8.x) → Unplug → Network B (10.0.0.x)
[WARNING] WAN network change detected!
[INFO] Started re-discovery for aa:bb:cc:dd:ee:ff
[INFO] Successfully obtained IPv4 10.0.0.51
```

### Performance Tuning

```python
# Edit gateway_config.py

# Faster discovery (more CPU)
CHECK_INTERVAL = 5

# Slower discovery (less CPU)
CHECK_INTERVAL = 30

# Adjust for slow networks
DHCPV4_TIMEOUT = 20
DHCPV4_RETRIES = 15
```

### Uninstallation

```bash
# Basic uninstall
bash uninstall.sh

# Uninstall + restore network config
bash uninstall.sh --restore-network
```

---

## Architecture

### Simplification Results

| Metric | Before (Multi-Device) | After (Single-Device) |
|--------|----------------------|----------------------|
| Lines of code | 2460 | 720 |
| Reduction | - | **71%** |
| Threads | 3 | 0 |
| Locks | 5 | 0 |
| Memory | ~25MB | ~15MB |
| CPU (idle) | ~2% | <1% |
| Complexity | High | Low |

### File Structure

```
/opt/ipv4-ipv6-gateway/      # Service installation
├── ipv4_ipv6_gateway.py     # Main service (600 lines)
├── gateway_config.py         # Configuration (120 lines)
├── gateway_api_server.py     # REST API (optional)
└── haproxy_manager.py        # HAProxy manager (optional)

/etc/ipv4-ipv6-gateway/      # Configuration
├── device.json               # Device state
├── network-config.uci        # Network template
├── dhcp-config.uci          # DHCP template
└── firewall-config.uci      # Firewall template

/usr/bin/                    # Helper scripts
├── gateway-status-direct    # Status (no API needed)
├── gateway-devices-direct   # Devices (no API needed)
├── gateway-diagnose         # Diagnostic tool
└── gateway-port-forward     # Port forwarding
```

---

## Documentation

- **README.md** (this file) - Quick reference guide
- **docs/IPv6_RETURN_PATH_FIX.md** - Critical IPv6 SNAT fix details
- **docs/OPTIMIZATIONS.md** - Further optimization recommendations
- **docs/COMPLETE_SUMMARY.md** - Full review and changes summary

---

## License

MIT License - See LICENSE file for details

---

## Credits

**Version:** 2.0 (Single-Device Optimized with IPv6 SNAT Fix)
**Last Updated:** 2024-11-13
**Hardware:** NanoPi R5C
**OS:** OpenWrt

For the complex multi-device version, see backup files:
- `ipv4_ipv6_gateway_complex.py.backup` (2130 lines)
- `gateway_config_complex.py.backup` (330 lines)
