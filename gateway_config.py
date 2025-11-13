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
WAN_CHANGE_REDISCOVERY_DELAY = (
    5  # seconds - wait before re-requesting DHCP for all devices
)

# WAN MAC address management
# IMPORTANT: Gateway permanently uses device MAC on WAN interface
# - On first device discovery, gateway's original MAC is saved to file
# - Device's MAC is set on WAN interface and kept permanently
# - Original MAC is ONLY restored during uninstall
# - This prevents gateway's own MAC from ever appearing on MAC-filtered networks

# Device storage
DEVICES_FILE = os.path.join(CONFIG_DIR, "devices.json")
BACKUP_DEVICES_FILE = os.path.join(CONFIG_DIR, "devices.json.bak")

# Gateway MAC storage (for restoration during uninstall)
ORIGINAL_MAC_FILE = os.path.join(CONFIG_DIR, "original_wan_mac.txt")

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
MAX_DEVICES = 1  # SINGLE DEVICE MODE: Only one device supported at a time

# Automatic Port Forwarding
# When a device is discovered, automatically forward these ports
# Format: {gateway_port: device_port}
#
# IMPORTANT: Gateway ports are remapped to avoid conflicts with OpenWrt services!
# The OpenWrt gateway itself runs services on standard ports (80, 22, 443, etc.)
# so we map device ports to non-conflicting external ports.
#
# Example: Device's HTTP (port 80) is accessible via gateway's port 8080
ENABLE_AUTO_PORT_FORWARDING = True
AUTO_PORT_FORWARDS = {
    8080: 80,  # HTTP: Gateway:8080 → Device:80 (avoids conflict with OpenWrt's LuCI)
    2323: 23,  # Telnet: Gateway:2323 → Device:23 (avoids conflict if OpenWrt runs telnet)
    8443: 443,  # HTTPS: Gateway:8443 → Device:443 (avoids conflict with OpenWrt's LuCI HTTPS)
    2222: 22,  # SSH: Gateway:2222 → Device:22 (avoids conflict with OpenWrt's SSH/dropbear)
    5900: 5900,  # VNC (no conflict - OpenWrt doesn't typically run VNC)
    3389: 3389,  # RDP (no conflict - OpenWrt doesn't typically run RDP)
}
# Port forwarding will use device's LAN IP (192.168.1.x)
# Access from WAN: gateway_wan_ip:gateway_port → device:device_port
#
# Access examples:
#   Device HTTP:  curl http://gateway_wan_ip:8080  → Device:80
#   Device SSH:   ssh -p 2222 user@gateway_wan_ip  → Device:22
#   Device Telnet: telnet gateway_wan_ip 2323      → Device:23
#   OpenWrt HTTP:  curl http://gateway_wan_ip:80   → OpenWrt LuCI (gateway itself)
#   OpenWrt SSH:   ssh -p 22 root@gateway_wan_ip   → OpenWrt SSH (gateway itself)

# IPv6→IPv4 Proxying (for IPv4-only devices)
# Proxy IPv6 client connections to IPv4 backend devices
ENABLE_IPV6_TO_IPV4_PROXY = True  # Enable IPv6→IPv4 proxying

# IPv6→IPv4 Proxy Port Mapping
# IMPORTANT: Only ports allowed by the upstream firewall!
# The firewall only allows telnet (23) and HTTP (80) for IPv6 traffic.
# Format: {gateway_ipv6_port: device_port}
#
# Note: IPv6 proxying binds to the device's specific IPv6 address
# Example: [2001:db8::1234]:80 → 192.168.1.100:80
IPV6_PROXY_PORT_FORWARDS = {
    80: 80,  # HTTP only (firewall allows this)
    23: 23,  # Telnet only (firewall allows this)
    # HTTPS (443), SSH (22), VNC, RDP NOT included - firewall blocks them!
}
# Access examples:
#   Device HTTP via IPv6:   curl http://[device_ipv6]:80
#   Device Telnet via IPv6: telnet device_ipv6 23

# Proxy backend selection: "socat" or "haproxy"
# - socat: Lightweight, simple TCP proxy with excellent error messages (recommended for debugging)
# - haproxy: Production-grade proxy with better protocol handling and logging
IPV6_PROXY_BACKEND = "socat"  # Options: "socat" or "haproxy" (default: socat)

# socat-specific settings
SOCAT_PROXY_BIND_IPV6 = "::"  # Bind to all IPv6 addresses (:: = any IPv6)
SOCAT_PROXY_LOG_DIR = "/var/log/socat"  # Directory for socat logs (optional)

# HAProxy-specific settings
HAPROXY_CONFIG_FILE = "/etc/haproxy/haproxy.cfg"  # HAProxy config file location
HAPROXY_STATS_ENABLE = True  # Enable HAProxy stats page
HAPROXY_STATS_PORT = 8404  # Stats page port
HAPROXY_STATS_URI = "/stats"  # Stats page URI
HAPROXY_LOG_LEVEL = (
    "info"  # HAProxy log level (emerg, alert, crit, err, warning, notice, info, debug)
)

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
CMD_SOCAT = "/usr/bin/socat"  # socat for IPv6→IPv4 proxying

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
    # CRITICAL FIX: Validate configuration values to prevent out-of-bounds settings
    # Check numeric ranges for critical parameters
    if not (1 <= MAX_DEVICES <= 10000):
        raise ValueError(f"MAX_DEVICES must be between 1 and 10000, got {MAX_DEVICES}")

    if not (1 <= DHCPV4_TIMEOUT <= 120):
        raise ValueError(
            f"DHCPV4_TIMEOUT must be between 1 and 120 seconds, got {DHCPV4_TIMEOUT}"
        )

    if not (1 <= DHCPV6_TIMEOUT <= 120):
        raise ValueError(
            f"DHCPV6_TIMEOUT must be between 1 and 120 seconds, got {DHCPV6_TIMEOUT}"
        )

    if not (1 <= DHCPV4_RETRY_COUNT <= 20):
        raise ValueError(
            f"DHCPV4_RETRY_COUNT must be between 1 and 20, got {DHCPV4_RETRY_COUNT}"
        )

    if not (1 <= DHCPV6_RETRY_COUNT <= 20):
        raise ValueError(
            f"DHCPV6_RETRY_COUNT must be between 1 and 20, got {DHCPV6_RETRY_COUNT}"
        )

    if not (1 <= ARP_MONITOR_INTERVAL <= 300):
        raise ValueError(
            f"ARP_MONITOR_INTERVAL must be between 1 and 300 seconds, got {ARP_MONITOR_INTERVAL}"
        )

    # Create required directories
    for path in PATHS_TO_CREATE:
        Path(path).mkdir(parents=True, exist_ok=True)

    # Resolve commands (preferred path or PATH-based fallback)
    global CMD_IP, CMD_ARP, CMD_ODHCP6C, CMD_UDHCPC, CMD_IPTABLES, CMD_IP6TABLES, CMD_SYSCTL, CMD_SOCAT

    CMD_IP = _find_command(CMD_IP)
    CMD_ARP = _find_command(CMD_ARP)
    CMD_ODHCP6C = _find_command(CMD_ODHCP6C)
    CMD_UDHCPC = _find_command(CMD_UDHCPC)
    CMD_IPTABLES = _find_command(CMD_IPTABLES)
    CMD_IP6TABLES = _find_command(CMD_IP6TABLES)
    CMD_SYSCTL = _find_command(CMD_SYSCTL)
    CMD_SOCAT = _find_command(CMD_SOCAT)

    # Check required commands exist and provide helpful error messages
    commands = {
        "ip": CMD_IP,
        "odhcp6c": CMD_ODHCP6C,
        "udhcpc": CMD_UDHCPC,
        "iptables": CMD_IPTABLES,
        "ip6tables": CMD_IP6TABLES,
        "sysctl": CMD_SYSCTL,
    }

    # Note: 'arp' and 'socat' are optional
    # - arp: we can use 'ip neigh' as a fallback
    # - socat: only needed if ENABLE_IPV6_TO_IPV4_PROXY is True
    optional_commands = {
        "arp": CMD_ARP,
        "socat": CMD_SOCAT,
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

    # Warn about optional commands if features are enabled
    for name, path in optional_commands.items():
        if not os.path.exists(path):
            if (
                name == "socat"
                and ENABLE_IPV6_TO_IPV4_PROXY
                and IPV6_PROXY_BACKEND == "socat"
            ):
                # socat is required if IPv6→IPv4 proxying is enabled with socat backend
                raise RuntimeError(
                    f"socat command not found (looked for: {path})\n"
                    f"IPv6→IPv4 proxying is enabled with socat backend but socat is not installed.\n"
                    f"\nInstall with:\n"
                    f"  opkg update\n"
                    f"  opkg install socat\n"
                    f"\nOr change proxy backend: IPV6_PROXY_BACKEND = 'haproxy'\n"
                    f"Or disable IPv6→IPv4 proxying: ENABLE_IPV6_TO_IPV4_PROXY = False"
                )
            # Not an error for other optional commands, just log that fallback will be used
            pass

    # HAProxy validation (if that backend is selected)
    if ENABLE_IPV6_TO_IPV4_PROXY and IPV6_PROXY_BACKEND == "haproxy":
        if not which("haproxy"):
            raise RuntimeError(
                f"HAProxy command not found\n"
                f"IPv6→IPv4 proxying is enabled with HAProxy backend but HAProxy is not installed.\n"
                f"\nInstall with:\n"
                f"  opkg update\n"
                f"  opkg install haproxy\n"
                f"\nOr change proxy backend: IPV6_PROXY_BACKEND = 'socat'\n"
                f"Or disable IPv6→IPv4 proxying: ENABLE_IPV6_TO_IPV4_PROXY = False"
            )

    return True
