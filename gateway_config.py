"""
Simple Configuration for Single-Device Gateway
Minimal settings - no threading, no API, no complex features
"""

import os
from pathlib import Path
from shutil import which

# Service name
SERVICE_NAME = "ipv4-ipv6-gateway"

# Network interfaces
WAN_INTERFACE = "eth0"  # Network side
LAN_INTERFACE = "eth1"  # Device side
LAN_GATEWAY_IP = "192.168.1.1"

# Logging
LOG_FILE = "/var/log/ipv4-ipv6-gateway.log"

# State file (stores current device info)
STATE_FILE = "/etc/ipv4-ipv6-gateway/device.json"

# Check interval (seconds)
CHECK_INTERVAL = 2  # Check for device/WAN changes every 2 seconds (fast detection!)

# Monitor WAN for network changes
MONITOR_WAN_CHANGES = True

# DHCP settings - Initial configuration (first time device connects)
DHCPV4_TIMEOUT = 10  # seconds per attempt (reduced from 15)
DHCPV4_RETRIES = 8  # total attempts (reduced from 10)

DHCPV6_TIMEOUT = 8  # seconds per attempt (reduced from 10)
DHCPV6_RETRIES = 2  # total attempts (reduced - SLAAC is primary for IPv6)

# DHCP settings - Fast reconfiguration (WAN change, MAC already registered on firewall)
# These are MUCH faster since the MAC is already whitelisted
DHCPV4_TIMEOUT_FAST = 3  # seconds per attempt (very fast!)
DHCPV4_RETRIES_FAST = 2  # only 2 attempts needed

DHCPV6_TIMEOUT_FAST = 3  # seconds per attempt (very fast!)
DHCPV6_RETRIES_FAST = 2  # only 2 attempts needed

# SLAAC wait time
SLAAC_WAIT_TIME = (
    5  # seconds to wait for Router Advertisement (increased for reliability)
)
SLAAC_WAIT_TIME_FAST = 2  # seconds for fast reconfig (RA cache likely exists)

# Port forwarding (IPv4 NAT)
# Format: {gateway_port: device_port}
PORT_FORWARDS = {
    8080: 80,  # HTTP
    2323: 23,  # Telnet
    8443: 443,  # HTTPS
    2222: 22,  # SSH
    5900: 5900,  # VNC
    3389: 3389,  # RDP
}

# IPv6→IPv4 proxy ports (for IPv6-only networks)
# Format: {ipv6_port: device_port}
# NOTE: Ports chosen to avoid conflicts with OpenWrt services:
#   - LuCI web interface: ports 80, 443
#   - SSH: port 22
#   - DNS: port 53
IPV6_PROXY_PORTS = {
    8080: 80,  # HTTP: [ipv6]:8080 → device:80 (avoids LuCI on port 80)
    2323: 23,  # Telnet: [ipv6]:2323 → device:23
    5000: 5000,  # Alt HTTP: [ipv6]:5000 → device:5000
}

# System commands
CMD_IP = "/usr/bin/ip"
CMD_UDHCPC = "/sbin/udhcpc"
CMD_ODHCP6C = "/usr/sbin/odhcp6c"
CMD_IPTABLES = "/usr/sbin/iptables"
CMD_IP6TABLES = "/usr/sbin/ip6tables"
CMD_SOCAT = "/usr/bin/socat"


def _find_command(preferred_path: str) -> str:
    """Try preferred path, fall back to PATH lookup"""
    if preferred_path and os.path.exists(preferred_path):
        return preferred_path

    basename = os.path.basename(preferred_path)
    resolved = which(basename)
    if resolved:
        return resolved

    return preferred_path


def validate_config() -> bool:
    """Validate configuration"""
    # Create state directory
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)

    # Resolve commands
    global CMD_IP, CMD_UDHCPC, CMD_ODHCP6C, CMD_IPTABLES, CMD_SOCAT

    CMD_IP = _find_command(CMD_IP)
    CMD_UDHCPC = _find_command(CMD_UDHCPC)
    CMD_ODHCP6C = _find_command(CMD_ODHCP6C)
    CMD_IPTABLES = _find_command(CMD_IPTABLES)
    CMD_SOCAT = _find_command(CMD_SOCAT)

    # Check required commands
    missing = []
    for name, path in [
        ("ip", CMD_IP),
        ("udhcpc", CMD_UDHCPC),
        ("odhcp6c", CMD_ODHCP6C),
        ("iptables", CMD_IPTABLES),
    ]:
        if not os.path.exists(path):
            missing.append(f"{name} (looked for: {path})")

    if missing:
        error = "Required commands not found:\n"
        for cmd in missing:
            error += f"  - {cmd}\n"
        error += "\nOn OpenWrt, install with:\n"
        error += "  opkg update\n"
        error += "  opkg install ip-full busybox odhcp6c iptables\n"
        raise RuntimeError(error)

    # socat is optional (only needed for IPv6-only networks)
    if not os.path.exists(CMD_SOCAT):
        print(f"Warning: socat not found ({CMD_SOCAT})")
        print("IPv6→IPv4 proxying will not work without socat")
        print("Install with: opkg install socat")

    return True
