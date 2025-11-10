"""
Configuration for IPv4↔IPv6 Gateway Service
"""

import os
from pathlib import Path

# Service configuration
SERVICE_NAME = 'ipv4-ipv6-gateway'
SERVICE_DESCRIPTION = 'Dynamic IPv4↔IPv6 Gateway with MAC Learning'

# Directories
CONFIG_DIR = '/etc/ipv4-ipv6-gateway'
LOG_DIR = '/var/log'
RUN_DIR = '/var/run'

# Logging
LOG_FILE = os.path.join(LOG_DIR, 'ipv4-ipv6-gateway.log')
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Network interfaces
ETH0_INTERFACE = 'eth0'  # IPv4 side (devices)
ETH1_INTERFACE = 'eth1'  # IPv6 side (network)

# DHCPv6 settings
DHCPV6_TIMEOUT = 10  # seconds
DHCPV6_RETRY_COUNT = 3
DHCPV6_RETRY_DELAY = 5  # seconds

# ARP monitoring
ARP_MONITOR_INTERVAL = 10  # seconds - check for new devices
DEVICE_MONITOR_INTERVAL = 30  # seconds - update device status

# Device storage
DEVICES_FILE = os.path.join(CONFIG_DIR, 'devices.json')
BACKUP_DEVICES_FILE = os.path.join(CONFIG_DIR, 'devices.json.bak')

# 464XLAT settings
ENABLE_464XLAT = True
CLAT_IPV4_POOL = '192.168.100.0/24'
CLAT_IPV6_PREFIX = 'fd00::/96'

# Firewall settings
ENABLE_FORWARDING = True
FIREWALL_RULES = {
    'allow_eth0_eth1': True,
    'allow_eth1_eth0': True,
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
API_HOST = '127.0.0.1'
API_PORT = 8080
API_LOG_REQUESTS = False

# Backups
BACKUP_ENABLED = True
BACKUP_INTERVAL = 3600  # 1 hour
BACKUP_RETENTION = 24  # Keep 24 backups

# System commands
CMD_IP = '/usr/bin/ip'
CMD_ARP = '/usr/bin/arp'
CMD_ODHCP6C = '/usr/sbin/odhcp6c'
CMD_IPTABLES = '/usr/sbin/iptables'
CMD_IP6TABLES = '/usr/sbin/ip6tables'
CMD_SYSCTL = '/sbin/sysctl'

# Paths to ensure exist
PATHS_TO_CREATE = [
    CONFIG_DIR,
    LOG_DIR,
    RUN_DIR,
]


def get_config():
    """Return configuration as dictionary"""
    return {
        'service_name': SERVICE_NAME,
        'service_description': SERVICE_DESCRIPTION,
        'config_dir': CONFIG_DIR,
        'log_file': LOG_FILE,
        'log_level': LOG_LEVEL,
        'eth0_interface': ETH0_INTERFACE,
        'eth1_interface': ETH1_INTERFACE,
        'dhcpv6_timeout': DHCPV6_TIMEOUT,
        'arp_monitor_interval': ARP_MONITOR_INTERVAL,
        'device_monitor_interval': DEVICE_MONITOR_INTERVAL,
    }


def validate_config():
    """Validate configuration"""
    # Create required directories
    for path in PATHS_TO_CREATE:
        Path(path).mkdir(parents=True, exist_ok=True)

    # Check required commands exist
    commands = [CMD_IP, CMD_ARP, CMD_ODHCP6C, CMD_IPTABLES]
    for cmd in commands:
        if not os.path.exists(cmd):
            raise RuntimeError(f"Required command not found: {cmd}")

    return True