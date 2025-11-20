# Gateway Scripts Reference - Simplified Single Device Mode

This document describes all the scripts in the simplified gateway system.

---

## 📦 Core Scripts

### `install.sh`
**Purpose**: Main installation script for the simplified gateway
**Usage**: `./install.sh [--full-auto|--auto-start|--apply-network]`
**What it does**:
- Installs Python 3 and dependencies (odhcp6c, udhcpc, ip-full, iptables)
- Copies gateway service to `/opt/ipv4-ipv6-gateway/`
- Installs monitoring commands (`gateway-status`, `gateway-device`)
- Creates init.d service
- Optionally configures network and starts service

---

### `uninstall.sh`
**Purpose**: Safely remove the gateway and restore system
**Usage**: `./uninstall.sh [--restore-network]`
**What it does**:
- Stops gateway service
- Restores original MAC address
- Backs up all configuration
- Removes installed files
- Optionally restores factory network config

---

## 📊 Monitoring Scripts

### `gateway-status-direct.sh`
**Purpose**: Show gateway status (installed as `gateway-status`)
**Usage**: `gateway-status`
**What it shows**:
- Service running status
- Current device MAC, IPs, status
- Network interface information
- Recent log entries

**Installed to**: `/usr/bin/gateway-status`

---

### `gateway-devices-direct.sh`
**Purpose**: Show device details (installed as `gateway-device`)
**Usage**: `gateway-device`
**What it shows**:
- Device MAC address
- LAN IPv4 address
- WAN IPv4/IPv6 addresses
- Discovery timestamp
- Last seen timestamp

**Installed to**: `/usr/bin/gateway-device`

---

## 🔍 Diagnostic Scripts

### `diagnose-and-fix.sh`
**Purpose**: Comprehensive diagnostics and auto-fix
**Usage**: `./diagnose-and-fix.sh`
**What it checks**:
- Service running status
- Network interface status
- DHCP client status
- Device connectivity
- Log files for errors

**Recommended**: Run when troubleshooting issues

---

### `diagnose-dhcp-requests.sh`
**Purpose**: Debug DHCP request/response issues
**Usage**: `./diagnose-dhcp-requests.sh`
**What it does**:
- Captures DHCP traffic on eth0 (WAN)
- Shows DHCPv4 and DHCPv6 messages
- Displays MAC addresses and options
- Useful for debugging firewall MAC blocking

---

### `diagnose-ipv6-connectivity.sh`
**Purpose**: Test IPv6 connectivity
**Usage**: `./diagnose-ipv6-connectivity.sh`
**What it checks**:
- IPv6 address on eth0
- IPv6 routing
- Ping to IPv6 gateway
- Ping to public IPv6 (e.g., google.com)
- IPv6 sysctl settings

---

### `diagnose-wan-connectivity.sh`
**Purpose**: Test WAN connectivity (IPv4 and IPv6)
**Usage**: `./diagnose-wan-connectivity.sh`
**What it checks**:
- eth0 (WAN) interface status
- IPv4 address and routing
- IPv6 address and routing
- Ping tests to public IPs
- DNS resolution

---

### `diagnose-ping.sh`
**Purpose**: Simple ping test for connectivity
**Usage**: `./diagnose-ping.sh`
**What it does**:
- Pings IPv4 gateway and public IPs
- Pings IPv6 gateway and public IPs
- Shows routing table

---

### `check-ipv6-addresses.sh`
**Purpose**: List all IPv6 addresses on all interfaces
**Usage**: `./check-ipv6-addresses.sh`
**What it shows**:
- All IPv6 addresses (link-local and global)
- Interface assignments
- IPv6 routing table

---

## 🛠️ Utility Scripts

### `capture-traffic.sh`
**Purpose**: Capture network traffic for debugging
**Usage**: `./capture-traffic.sh [interface] [filter]`
**What it does**:
- Uses tcpdump to capture packets
- Can filter by interface (eth0, eth1)
- Can filter by protocol (dhcp, icmp6, etc.)
- Saves to .pcap file for analysis

---

### `debug-connections.sh`
**Purpose**: Show active network connections
**Usage**: `./debug-connections.sh`
**What it shows**:
- Active TCP/UDP connections
- Listening ports
- Connection states
- NAT/firewall rules

---

### `monitor-connections.sh`
**Purpose**: Monitor connections in real-time
**Usage**: `./monitor-connections.sh`
**What it does**:
- Continuously monitors connections
- Updates every 2 seconds
- Shows new connections as they appear
- Useful for debugging device connectivity

---

### `test-device-detection.sh`
**Purpose**: Test device discovery mechanism
**Usage**: `./test-device-detection.sh`
**What it does**:
- Shows ARP table
- Lists devices on eth1 (LAN)
- Displays MAC addresses
- Useful for verifying device is visible

---

### `verify.sh`
**Purpose**: Verify installation and configuration
**Usage**: `./verify.sh`
**What it checks**:
- All required files installed
- Service enabled and running
- Network configuration
- Python dependencies
- Logs for errors

---

### `clean-reinstall.sh`
**Purpose**: Clean reinstall (uninstall + install)
**Usage**: `./clean-reinstall.sh`
**What it does**:
- Runs uninstall.sh
- Removes all traces
- Runs install.sh --full-auto
- Fresh clean install

---

### `quick-deploy.sh`
**Purpose**: Quick deployment to router
**Usage**: `./quick-deploy.sh <router-ip>`
**What it does**:
- SCPs files to router
- SSHs to router
- Runs install.sh --full-auto
- Shows status

---

### `pre-deployment-test.sh`
**Purpose**: Test before deploying
**Usage**: `./pre-deployment-test.sh`
**What it checks**:
- All required files present
- Python syntax valid
- Script syntax valid
- Configuration valid
- No obvious errors

---

### `manual-network-fix.sh`
**Purpose**: Manually fix network configuration
**Usage**: `./manual-network-fix.sh`
**What it does**:
- Resets network configuration
- Configures eth0 (WAN) and eth1 (LAN)
- Restarts network services
- Useful if network gets misconfigured

---

## 🗑️ Scripts Removed (Not Needed in Simple Mode)

The following scripts were removed because they're not needed in single-device mode:

- ❌ `setup-ipv6-port-forwarding.sh` - No proxy in simple version
- ❌ `setup-port-forwarding.sh` - No automatic port forwarding
- ❌ `troubleshoot-proxy.sh` - No proxy
- ❌ `diagnose-proxy-complete.sh` - No proxy
- ❌ `fix-socat-now.sh` - No socat
- ❌ `free-ipv6-ports.sh` - Related to proxy
- ❌ `debug-port-forwarding.sh` - No port forwarding

---

## 📝 Quick Reference

| Task | Script |
|------|--------|
| **Install** | `./install.sh --full-auto` |
| **Uninstall** | `./uninstall.sh --restore-network` |
| **Check Status** | `gateway-status` |
| **Check Device** | `gateway-device` |
| **Diagnose Issues** | `./diagnose-and-fix.sh` |
| **Test DHCP** | `./diagnose-dhcp-requests.sh` |
| **Test IPv6** | `./diagnose-ipv6-connectivity.sh` |
| **Test WAN** | `./diagnose-wan-connectivity.sh` |
| **Verify Install** | `./verify.sh` |
| **Capture Traffic** | `./capture-traffic.sh eth0` |
| **View Logs** | `tail -f /var/log/ipv4-ipv6-gateway.log` |

---

## 💡 Common Troubleshooting Workflows

### Device not getting WAN IPs

```bash
# 1. Check service is running
gateway-status

# 2. Check device is detected
./test-device-detection.sh

# 3. Diagnose DHCP
./diagnose-dhcp-requests.sh

# 4. Check logs
tail -50 /var/log/ipv4-ipv6-gateway.log | grep ERROR
```

### IPv6 not working

```bash
# 1. Check IPv6 addresses
./check-ipv6-addresses.sh

# 2. Test IPv6 connectivity
./diagnose-ipv6-connectivity.sh

# 3. Check gateway status
gateway-status
```

### Complete diagnostic run

```bash
# Run comprehensive diagnostics
./diagnose-and-fix.sh

# Verify installation
./verify.sh

# Check WAN connectivity
./diagnose-wan-connectivity.sh
```

---

**Note**: All scripts are designed for the simplified single-device gateway. Complex features like HAProxy, socat, and automatic port forwarding have been removed.
