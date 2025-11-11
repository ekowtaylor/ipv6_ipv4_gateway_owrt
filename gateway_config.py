"""
Configuration for IPv4↔IPv6 Gateway Service
"""

import os
from pathlib import Path
from shutil import which
from typing import Any, Dict, List

# Service configuration
SERVICE_NAME = "ipv4-ipv6-gateway"
SERVICE_DESCRIPTION = "Dynamic IPv4↔IPv6 Gateway with MAC Learning"

# Directories
CONFIG_DIR = "/etc/ipv4-ipv6-gateway"
LOG_DIR = "/var/log"
RUN_DIR = "/var/run"

# Logging
LOG_FILE = os.path.join(LOG_DIR, "ipv4-ipv6-gateway.log")
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Network interfaces
ETH0_INTERFACE = "eth0"  # IPv6 side (network)
ETH1_INTERFACE = "eth1"  # IPv4 side (devices)

# DHCPv6 settings
DHCPV6_TIMEOUT = 10  # seconds
DHCPV6_RETRY_COUNT = 5  # More attempts for slow/busy networks
DHCPV6_RETRY_DELAY = 5  # seconds (exponential backoff applied)

# DHCPv4 settings
DHCPV4_TIMEOUT = 15  # seconds - longer timeout for MAC registration lag
DHCPV4_RETRY_COUNT = 10  # More attempts - critical for upstream firewall scenarios
DHCPV4_RETRY_DELAY = 5  # seconds (exponential backoff applied)

# ARP monitoring
ARP_MONITOR_INTERVAL = 10  # seconds - check for new devices
DEVICE_MONITOR_INTERVAL = 30  # seconds - update device status

# WAN network monitoring (automatic network change detection)
ENABLE_WAN_MONITOR = True  # Monitor WAN interface for network changes
WAN_MONITOR_INTERVAL = 15  # seconds - check for WAN IP changes
WAN_CHANGE_REDISCOVERY_DELAY = 5  # seconds - wait before re-requesting DHCP for all devices
WAN_CHANGE_MIN_INTERVAL = 120  # seconds - minimum time between WAN change triggers (debounce)
WAN_CHANGE_STABLE_TIME = 30  # seconds - IP must be stable this long before considering it changed

# Device storage
DEVICES_FILE = os.path.join(CONFIG_DIR, "devices.json")
BACKUP_DEVICES_FILE = os.path.join(CONFIG_DIR, "devices.json.bak")

# 464XLAT settings
ENABLE_464XLAT = True
CLAT_IPV4_POOL = "192.168.100.0/24"
CLAT_IPV6_PREFIX = "fd00::/96"

# Firewall settings
ENABLE_FORWARDING = True
FIREWALL_RULES: Dict[str, Any] = {
    "allow_eth0_eth1": True,
    "allow_eth1_eth0": True,
}

# Performance tuning
CONNTRACK_MAX = 262144
CONNTRACK_TCP_TIMEOUT_ESTABLISHED = 600
CONNTRACK_UDP_TIMEOUT = 60

# Threading
DISCOVERY_THREAD_DAEMON = True
MONITORING_THREAD_DAEMON = True
THREAD_JOIN_TIMEOUT = 5  # seconds

# Device status
DEVICE_STATUS_TIMEOUT = 300  # Mark device inactive after 5 minutes

# Connection limits
MAX_CONCURRENT_DHCPV6_REQUESTS = 5
MAX_DEVICES = 1000

# Automatic Port Forwarding
# When a device is discovered, automatically forward these ports
# Format: {gateway_port: device_port}
ENABLE_AUTO_PORT_FORWARDING = True
AUTO_PORT_FORWARDS = {
    8080: 80,      # HTTP
    2323: 23,      # Telnet
    8443: 443,     # HTTPS
    2222: 22,      # SSH
    5900: 5900,    # VNC
    3389: 3389,    # RDP
}
# Port forwarding will use device's LAN IP (192.168.1.x)
# Access from WAN: gateway_wan_ip:gateway_port → device:device_port

# Debugging
DEBUG_MODE = False
DEBUG_ARP_QUERIES = False
DEBUG_DHCPV6_REQUESTS = False

# Validation
VALIDATE_MAC_FORMAT = True
VALIDATE_IPV6_FORMAT = True
VALIDATE_IPV4_FORMAT = False  # Less critical for this use case

# API Server (optional - for status/monitoring)
API_ENABLED = True
API_HOST = "0.0.0.0"  # Bind to all interfaces (use "127.0.0.1" for localhost only)
API_PORT = 5050
API_LOG_REQUESTS = False

# Backups
BACKUP_ENABLED = True
BACKUP_INTERVAL = 3600  # 1 hour
BACKUP_RETENTION = 24  # Keep 24 backups

# System commands
# NOTE: these are default paths; validate_config() will also try $PATH fallbacks.
CMD_IP = "/usr/bin/ip"  # often /sbin/ip on OpenWrt
CMD_ARP = "/usr/bin/arp"  # often /sbin/arp (busybox) on OpenWrt
CMD_ODHCP6C = "/usr/sbin/odhcp6c"  # often /sbin/odhcp6c on OpenWrt
CMD_UDHCPC = "/sbin/udhcpc"  # busybox DHCPv4 client on OpenWrt
CMD_IPTABLES = "/usr/sbin/iptables"
CMD_IP6TABLES = "/usr/sbin/ip6tables"
CMD_SYSCTL = "/sbin/sysctl"

# Paths to ensure exist
PATHS_TO_CREATE: List[str] = [
    CONFIG_DIR,
    LOG_DIR,
    RUN_DIR,
]


def get_config() -> Dict[str, Any]:
    """Return configuration as dictionary (for status/logging/debug)"""
    return {
        "service_name": SERVICE_NAME,
        "service_description": SERVICE_DESCRIPTION,
        "config_dir": CONFIG_DIR,
        "log_file": LOG_FILE,
        "log_level": LOG_LEVEL,
        "eth0_interface": ETH0_INTERFACE,
        "eth1_interface": ETH1_INTERFACE,
        "dhcpv6_timeout": DHCPV6_TIMEOUT,
        "dhcpv6_retry_count": DHCPV6_RETRY_COUNT,
        "arp_monitor_interval": ARP_MONITOR_INTERVAL,
        "device_monitor_interval": DEVICE_MONITOR_INTERVAL,
        "devices_file": DEVICES_FILE,
        "backup_devices_file": BACKUP_DEVICES_FILE,
        "api_enabled": API_ENABLED,
        "api_host": API_HOST,
        "api_port": API_PORT,
    }


def _find_command(preferred_path: str) -> str:
    """
    Try the configured path; if it's not present, fall back to PATH lookup.

    This makes the config portable between distros like OpenWrt (/sbin/*)
    and other Linuxes (/usr/bin/*, /usr/sbin/*).
    """
    if preferred_path and os.path.exists(preferred_path):
        return preferred_path

    # Fallback to $PATH using just the basename
    basename = os.path.basename(preferred_path)
    resolved = which(basename)
    if resolved:
        return resolved

    # Nothing worked; keep the original (so the error message is meaningful)
    return preferred_path


def validate_config() -> bool:
    """Validate configuration and ensure required paths/commands exist."""
    # Create required directories
    for path in PATHS_TO_CREATE:
        Path(path).mkdir(parents=True, exist_ok=True)

    # Resolve commands (preferred path or PATH-based fallback)
    global CMD_IP, CMD_ARP, CMD_ODHCP6C, CMD_UDHCPC, CMD_IPTABLES, CMD_IP6TABLES, CMD_SYSCTL

    CMD_IP = _find_command(CMD_IP)
    CMD_ARP = _find_command(CMD_ARP)
    CMD_ODHCP6C = _find_command(CMD_ODHCP6C)
    CMD_UDHCPC = _find_command(CMD_UDHCPC)
    CMD_IPTABLES = _find_command(CMD_IPTABLES)
    CMD_IP6TABLES = _find_command(CMD_IP6TABLES)
    CMD_SYSCTL = _find_command(CMD_SYSCTL)

    # Check required commands exist and provide helpful error messages
    commands = {
        "ip": CMD_IP,
        "odhcp6c": CMD_ODHCP6C,
        "udhcpc": CMD_UDHCPC,
        "iptables": CMD_IPTABLES,
        "ip6tables": CMD_IP6TABLES,
        "sysctl": CMD_SYSCTL,
    }

    # Note: 'arp' is optional since we can use 'ip neigh' as a fallback
    optional_commands = {
        "arp": CMD_ARP,
    }

    missing_commands = []
    for name, path in commands.items():
        if not os.path.exists(path):
            missing_commands.append(f"{name} (looked for: {path})")

    if missing_commands:
        error_msg = "Required command(s) not found:\n"
        for cmd in missing_commands:
            error_msg += f"  - {cmd}\n"
        error_msg += "\nOn OpenWrt, install with:\n"
        error_msg += "  opkg update\n"
        error_msg += "  opkg install ip-full busybox odhcp6c iptables\n"
        error_msg += "\nOr update paths in gateway_config.py to match your system."
        raise RuntimeError(error_msg)

    # Warn about optional commands
    for name, path in optional_commands.items():
        if not os.path.exists(path):
            # Not an error, just log that fallback will be used
            pass

    return True
