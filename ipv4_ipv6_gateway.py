#!/usr/bin/env python3
"""
Dynamic IPv4↔IPv6 Gateway Service
NanoPi R5C - Plug-and-Play MAC Learning with DHCPv6 Discovery

Monitors IPv4 devices on eth1, discovers their MAC addresses,
spoofs them on eth0 to request DHCPv6, learns IPv6 assignments,
and maintains transparent IPv4↔IPv6 translation via 464XLAT.
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import gateway_config as cfg
from gateway_api_server import GatewayAPIServer

# Validate config and ensure directories/commands exist BEFORE logging setup
cfg.validate_config()

# Configure logging using gateway_config settings
log_level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format=cfg.LOG_FORMAT,
    handlers=[
        logging.FileHandler(cfg.LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("GatewayService")


@dataclass
class DeviceMapping:
    """Represents an IPv4 device and its discovered WAN addresses (IPv4 and/or IPv6)"""

    mac_address: str
    ipv4_address: Optional[str] = None  # LAN IPv4 (192.168.1.x)
    ipv4_wan_address: Optional[str] = None  # WAN IPv4 (from DHCPv4 on eth0)
    ipv6_address: Optional[str] = None  # WAN IPv6 (from DHCPv6 on eth0)
    discovered_at: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = "pending"  # pending, discovering, active, inactive, failed, error

    def __post_init__(self) -> None:
        now_iso = datetime.now().isoformat()
        if self.discovered_at is None:
            self.discovered_at = now_iso
        if self.last_seen is None:
            self.last_seen = now_iso

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceMapping":
        return cls(**data)


class NetworkInterface:
    """Wrapper for network interface operations"""

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.logger = logging.getLogger(f"NetworkInterface[{interface_name}]")

    def get_mac_address(self) -> Optional[str]:
        """Get current MAC address of interface"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "link", "show", self.interface_name],
                capture_output=True,
                text=True,
                check=True,
            )
            match = re.search(
                r"([0-9a-f]{2}:){5}([0-9a-f]{2})", result.stdout, re.IGNORECASE
            )
            if match:
                return match.group(0).lower()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get MAC: {e}")
        return None

    def set_mac_address(self, mac: str) -> bool:
        """Set MAC address on interface"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.interface_name, "address", mac],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Set MAC to {mac}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set MAC: {e}")
            return False

    def is_up(self) -> bool:
        """Check if interface is up"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "link", "show", self.interface_name],
                capture_output=True,
                text=True,
                check=True,
            )
            return "UP" in result.stdout
        except subprocess.CalledProcessError:
            return False

    def bring_up(self) -> bool:
        """Bring interface up"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.interface_name, "up"],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Brought {self.interface_name} up")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to bring up interface: {e}")
            return False

    def get_ipv6_addresses(self) -> List[str]:
        """Get all non-link-local IPv6 addresses on interface"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "show", self.interface_name],
                capture_output=True,
                text=True,
                check=True,
            )
            addresses: List[str] = []
            for line in result.stdout.splitlines():
                match = re.search(r"inet6\s+([0-9a-f:]+)", line, re.IGNORECASE)
                if match:
                    addr = match.group(1)
                    if not addr.lower().startswith("fe80:"):
                        addresses.append(addr)
            return addresses
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get IPv6 addresses: {e}")
            return []

    def flush_ipv6_addresses(self) -> bool:
        """Remove all IPv6 addresses from interface"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "flush", "dev", self.interface_name],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Flushed IPv6 addresses from {self.interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to flush IPv6 addresses: {e}")
            return False

    def get_ipv4_addresses(self) -> List[str]:
        """Get all IPv4 addresses on interface (excluding loopback)"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "show", self.interface_name],
                capture_output=True,
                text=True,
                check=True,
            )
            addresses: List[str] = []
            for line in result.stdout.splitlines():
                # inet 192.168.1.1/24 brd 192.168.1.255 scope global eth1
                match = re.search(r"inet\s+([0-9.]+)", line)
                if match:
                    addr = match.group(1)
                    # Skip loopback
                    if not addr.startswith("127."):
                        addresses.append(addr)
            return addresses
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get IPv4 addresses: {e}")
            return []

    def flush_ipv4_addresses(self) -> bool:
        """Remove all IPv4 addresses from interface"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "flush", "dev", self.interface_name],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Flushed IPv4 addresses from {self.interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to flush IPv4 addresses: {e}")
            return False


class ARPMonitor:
    """Monitors ARP table for new devices on eth1"""

    def __init__(self, interface: str):
        self.interface = interface
        self.logger = logging.getLogger("ARPMonitor")
        self.known_macs = set()

    def get_arp_entries(self) -> List[tuple]:
        """
        Get all MAC addresses and their IPv4 addresses in ARP table for this interface.
        Returns list of (mac, ipv4) tuples.
        Uses 'ip neigh' (modern) or falls back to 'arp' (legacy).
        """
        # Try modern 'ip neigh' first (more reliable on OpenWrt)
        entries = self._get_entries_via_ip_neigh()
        if entries:
            return entries

        # Fallback to legacy 'arp' command
        return self._get_entries_via_arp()

    def _get_entries_via_ip_neigh(self) -> List[tuple]:
        """Get ARP entries using 'ip neigh' command (modern approach)"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "neigh", "show", "dev", self.interface],
                capture_output=True,
                text=True,
                check=True,
            )

            entries: List[tuple] = []
            for line in result.stdout.splitlines():
                # Format: 192.168.1.100 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                # or:     192.168.1.100 lladdr aa:bb:cc:dd:ee:ff STALE
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "lladdr":
                    ipv4 = parts[0]
                    mac = parts[2].lower()

                    # Validate IPv4 format
                    ipv4_match = re.match(
                        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", ipv4
                    )
                    # Validate MAC format
                    mac_match = re.match(r"^([0-9a-f]{2}:){5}([0-9a-f]{2})$", mac)

                    if ipv4_match and mac_match:
                        # Filter out broadcast/invalid MACs
                        if mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                            entries.append((mac, ipv4))

            return entries
        except subprocess.CalledProcessError as e:
            self.logger.debug(f"'ip neigh' failed, will try 'arp': {e}")
            return []

    def _get_entries_via_arp(self) -> List[tuple]:
        """Get ARP entries using legacy 'arp' command (fallback)"""
        # Skip if arp command doesn't exist
        if (
            not hasattr(cfg, "CMD_ARP")
            or not cfg.CMD_ARP
            or not os.path.exists(cfg.CMD_ARP)
        ):
            self.logger.debug("'arp' command not available, skipping fallback")
            return []

        try:
            result = subprocess.run(
                [cfg.CMD_ARP, "-i", self.interface, "-n"],
                capture_output=True,
                text=True,
                check=True,
            )

            entries: List[tuple] = []
            for line in result.stdout.splitlines():
                # Match both MAC and IPv4 address
                # Format: 192.168.1.100    ether   aa:bb:cc:dd:ee:ff   C     eth1
                parts = line.split()
                if len(parts) >= 3:
                    # Try to extract IPv4 and MAC
                    ipv4_match = re.match(
                        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", parts[0]
                    )
                    mac_match = re.search(
                        r"([0-9a-f]{2}:){5}([0-9a-f]{2})", line, re.IGNORECASE
                    )

                    if ipv4_match and mac_match:
                        ipv4 = ipv4_match.group(1)
                        mac = mac_match.group(0).lower()

                        # Filter out broadcast/invalid MACs
                        if mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                            entries.append((mac, ipv4))

            return entries
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get ARP entries: {e}")
            return []

    def get_new_macs(self) -> List[tuple]:
        """
        Get newly discovered MAC addresses with their IPv4 addresses since last call.
        Returns list of (mac, ipv4) tuples.
        """
        current_entries = self.get_arp_entries()
        current_macs = {mac for mac, _ in current_entries}
        new_entries = [
            (mac, ipv4) for mac, ipv4 in current_entries if mac not in self.known_macs
        ]
        self.known_macs = current_macs

        if new_entries:
            self.logger.info(f"Discovered new devices: {new_entries}")

        return new_entries


class DHCPv6Manager:
    """Manages DHCPv6 requests with MAC spoofing"""

    def __init__(self, interface: str, timeout: int = cfg.DHCPV6_TIMEOUT):
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger("DHCPv6Manager")
        self.iface = NetworkInterface(interface)

    def request_ipv6_for_mac(self, mac: str) -> Optional[str]:
        """
        Spoof MAC on interface, request DHCPv6, return assigned IPv6 address.
        Uses exponential backoff retry logic for reliability.
        """
        self.logger.info(f"Requesting IPv6 for MAC: {mac}")

        original_mac = self.iface.get_mac_address()

        try:
            self.iface.flush_ipv6_addresses()

            if not self.iface.set_mac_address(mac):
                self.logger.error(f"Failed to spoof MAC {mac}")
                return None

            time.sleep(1)

            # Retry with exponential backoff
            for attempt in range(cfg.DHCPV6_RETRY_COUNT):
                attempt_num = attempt + 1
                self.logger.debug(
                    f"DHCPv6 attempt {attempt_num}/{cfg.DHCPV6_RETRY_COUNT} for MAC {mac}"
                )

                if self._request_dhcpv6():
                    time.sleep(2)
                    addresses = self.iface.get_ipv6_addresses()

                    if addresses:
                        ipv6 = addresses[0]
                        self.logger.info(
                            f"Successfully obtained IPv6 {ipv6} for MAC {mac} "
                            f"(attempt {attempt_num})"
                        )
                        return ipv6
                    else:
                        self.logger.warning(
                            f"DHCPv6 succeeded but no IPv6 assigned for MAC {mac} "
                            f"(attempt {attempt_num})"
                        )
                else:
                    self.logger.warning(
                        f"DHCPv6 request failed for MAC {mac} (attempt {attempt_num})"
                    )

                # Exponential backoff: wait longer after each failed attempt
                if attempt < cfg.DHCPV6_RETRY_COUNT - 1:
                    backoff_time = cfg.DHCPV6_RETRY_DELAY * (2**attempt)
                    self.logger.debug(f"Waiting {backoff_time}s before retry...")
                    time.sleep(backoff_time)

            # All retries failed
            self.logger.error(
                f"All {cfg.DHCPV6_RETRY_COUNT} DHCPv6 attempts failed for MAC {mac}"
            )
            return None

        except Exception as e:
            self.logger.error(f"Exception during DHCPv6 request: {e}")
            return None
        finally:
            if original_mac:
                self.iface.set_mac_address(original_mac)

    def _request_dhcpv6(self) -> bool:
        """Execute DHCPv6 request using odhcp6c"""
        try:
            process = subprocess.Popen(
                [cfg.CMD_ODHCP6C, "-P", "0", self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.logger.warning(
                    "DHCPv6 request timed out after %s seconds, terminating",
                    self.timeout,
                )
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()

            return True
        except Exception as e:
            self.logger.error(f"DHCPv6 request error: {e}")
            return False


class DHCPv4Manager:
    """Manages DHCPv4 requests with MAC spoofing"""

    def __init__(self, interface: str, timeout: int = cfg.DHCPV4_TIMEOUT):
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger("DHCPv4Manager")
        self.iface = NetworkInterface(interface)

    def request_ipv4_for_mac(self, mac: str) -> Optional[str]:
        """
        Spoof MAC on interface, request DHCPv4, return assigned IPv4 address.
        Uses exponential backoff retry logic for reliability.
        """
        self.logger.info(f"Requesting IPv4 for MAC: {mac}")

        original_mac = self.iface.get_mac_address()

        try:
            self.iface.flush_ipv4_addresses()

            if not self.iface.set_mac_address(mac):
                self.logger.error(f"Failed to spoof MAC {mac}")
                return None

            time.sleep(1)

            # Retry with exponential backoff
            for attempt in range(cfg.DHCPV4_RETRY_COUNT):
                attempt_num = attempt + 1
                self.logger.debug(
                    f"DHCPv4 attempt {attempt_num}/{cfg.DHCPV4_RETRY_COUNT} for MAC {mac}"
                )

                if self._request_dhcpv4():
                    time.sleep(2)
                    addresses = self.iface.get_ipv4_addresses()

                    if addresses:
                        ipv4 = addresses[0]
                        self.logger.info(
                            f"Successfully obtained IPv4 {ipv4} for MAC {mac} "
                            f"(attempt {attempt_num})"
                        )
                        return ipv4
                    else:
                        self.logger.warning(
                            f"DHCPv4 succeeded but no IPv4 assigned for MAC {mac} "
                            f"(attempt {attempt_num})"
                        )
                else:
                    self.logger.warning(
                        f"DHCPv4 request failed for MAC {mac} (attempt {attempt_num})"
                    )

                # Exponential backoff: wait longer after each failed attempt
                if attempt < cfg.DHCPV4_RETRY_COUNT - 1:
                    backoff_time = cfg.DHCPV4_RETRY_DELAY * (2**attempt)
                    self.logger.debug(f"Waiting {backoff_time}s before retry...")
                    time.sleep(backoff_time)

            # All retries failed
            self.logger.error(
                f"All {cfg.DHCPV4_RETRY_COUNT} DHCPv4 attempts failed for MAC {mac}"
            )
            return None

        except Exception as e:
            self.logger.error(f"Exception during DHCPv4 request: {e}")
            return None
        finally:
            if original_mac:
                self.iface.set_mac_address(original_mac)

    def _request_dhcpv4(self) -> bool:
        """Execute DHCPv4 request using udhcpc (busybox DHCP client)"""
        try:
            # udhcpc options:
            # -i interface: specify interface
            # -n: exit if lease is not obtained
            # -q: quit after obtaining lease
            # -f: run in foreground
            # -t N: send up to N discover packets
            # -T TIMEOUT: pause between packets (default 3s)
            # NO -s flag: use default script to actually configure the interface
            process = subprocess.Popen(
                [
                    cfg.CMD_UDHCPC,
                    "-i",
                    self.interface,
                    "-n",  # exit if lease not obtained
                    "-q",  # quit after obtaining lease
                    "-f",  # foreground
                    "-t",
                    "3",  # 3 discovery attempts
                    "-T",
                    "3",  # 3 second timeout between attempts
                    # Removed "-s", "/bin/true" to allow default script to configure interface
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                return_code = process.returncode

                if return_code == 0:
                    self.logger.debug("DHCPv4 request succeeded")
                    # Give the system a moment to apply the configuration
                    time.sleep(1)
                    return True
                else:
                    self.logger.warning(
                        f"DHCPv4 request failed with exit code {return_code}: {stderr.decode()}"
                    )
                    return False

            except subprocess.TimeoutExpired:
                self.logger.warning(
                    "DHCPv4 request timed out after %s seconds, terminating",
                    self.timeout,
                )
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                return False

        except Exception as e:
            self.logger.error(f"DHCPv4 request error: {e}")
            return False


class DeviceStore:
    """Persistent storage for device mappings"""

    def __init__(self, config_dir: str = cfg.CONFIG_DIR):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.devices_file = self.config_dir / "devices.json"
        self.logger = logging.getLogger("DeviceStore")
        self._lock = threading.Lock()

    def load_devices(self) -> Dict[str, DeviceMapping]:
        """Load all device mappings from disk"""
        with self._lock:
            if not self.devices_file.exists():
                self.logger.info("No existing devices file, starting fresh")
                return {}

            try:
                with open(self.devices_file, "r") as f:
                    data = json.load(f)
                    return {
                        mac: DeviceMapping.from_dict(device)
                        for mac, device in data.items()
                    }
            except Exception as e:
                self.logger.error(f"Failed to load devices: {e}")
                return {}

    def save_devices(self, devices: Dict[str, DeviceMapping]) -> bool:
        """Save device mappings to disk (atomic write)"""
        with self._lock:
            try:
                temp_file = self.devices_file.with_suffix(".json.tmp")
                with open(temp_file, "w") as f:
                    data = {mac: d.to_dict() for mac, d in devices.items()}
                    json.dump(data, f, indent=2)
                temp_file.replace(self.devices_file)
                return True
            except Exception as e:
                self.logger.error(f"Failed to save devices: {e}")
                return False

    def add_device(self, device: DeviceMapping) -> bool:
        """Add or update a device mapping"""
        devices = self.load_devices()
        devices[device.mac_address] = device
        return self.save_devices(devices)

    def clear(self) -> None:
        """Clear all stored devices on disk"""
        with self._lock:
            if self.devices_file.exists():
                try:
                    self.devices_file.unlink()
                    self.logger.info("Cleared devices file on disk")
                except Exception as e:
                    self.logger.error(f"Failed to clear devices file: {e}")


class FirewallManager:
    """Manages firewall rules for translation"""

    def __init__(self):
        self.logger = logging.getLogger("FirewallManager")

    def enable_forwarding(self) -> bool:
        """Enable IPv4 and IPv6 forwarding"""
        try:
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv4.ip_forward=1"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.all.forwarding=1"],
                check=True,
                capture_output=True,
            )
            self.logger.info("IP forwarding enabled for IPv4 and IPv6")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to enable forwarding: {e}")
            return False

    def add_iptables_rule(self, rule_spec: List[str]) -> bool:
        """Add an iptables rule"""
        try:
            subprocess.run(
                [cfg.CMD_IPTABLES] + rule_spec,
                check=True,
                capture_output=True,
            )
            self.logger.debug("Added iptables rule: %s", " ".join(rule_spec))
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to add iptables rule: {e}")
            return False

    def allow_eth0_to_eth1(self, eth0: str, eth1: str) -> bool:
        """Allow traffic between eth0 and eth1"""
        rules = [
            ["-A", "FORWARD", "-i", eth0, "-o", eth1, "-j", "ACCEPT"],
            ["-A", "FORWARD", "-i", eth1, "-o", eth0, "-j", "ACCEPT"],
        ]
        for rule in rules:
            if not self.add_iptables_rule(rule):
                return False
        return True


class GatewayService:
    """Main gateway service orchestrating all components"""

    def __init__(self, config_dir: str = cfg.CONFIG_DIR):
        self.logger = logging.getLogger("GatewayService")
        self.config_dir = config_dir

        self.arp_monitor = ARPMonitor(interface=cfg.ETH1_INTERFACE)
        self.dhcpv6_manager = DHCPv6Manager(interface=cfg.ETH0_INTERFACE)
        self.dhcpv4_manager = DHCPv4Manager(interface=cfg.ETH0_INTERFACE)
        self.device_store = DeviceStore(config_dir)
        self.firewall = FirewallManager()
        self.eth0 = NetworkInterface(cfg.ETH0_INTERFACE)
        self.eth1 = NetworkInterface(cfg.ETH1_INTERFACE)

        self.api_server: Optional[GatewayAPIServer] = None

        self.devices: Dict[str, DeviceMapping] = {}
        self._devices_lock = threading.Lock()
        self.running = False
        self.discovery_thread: Optional[threading.Thread] = None
        self.monitor_thread: Optional[threading.Thread] = None

    def should_attempt_protocols(self) -> tuple:
        """
        Determine if we should attempt DHCPv4 and/or DHCPv6.

        Strategy: Always attempt both protocols. Let DHCP fail gracefully if not supported.
        This avoids the chicken-and-egg problem where eth0 has no addresses yet.

        Returns (attempt_ipv4, attempt_ipv6) tuple - both True by default.
        """
        # Always attempt both protocols - this is a dual-stack gateway!
        # If the network doesn't support one, DHCP will timeout/fail gracefully
        attempt_ipv4 = True
        attempt_ipv6 = True

        self.logger.info(
            f"Will attempt - DHCPv4: {attempt_ipv4}, DHCPv6: {attempt_ipv6}"
        )

        return (attempt_ipv4, attempt_ipv6)

    # ---- Public API used by REST layer ----

    def get_health(self) -> dict:
        """Get detailed health metrics"""
        import os
        import time

        # Try to import psutil for enhanced metrics (may not be available on OpenWrt)
        try:
            import psutil

            has_psutil = True
        except ImportError:
            has_psutil = False

        # Calculate uptime (if process start time is tracked)
        uptime_seconds = 0
        memory_usage_mb = 0.0

        if has_psutil:
            try:
                process = psutil.Process(os.getpid())
                uptime_seconds = int(time.time() - process.create_time())
                process_memory = process.memory_info()
                memory_usage_mb = process_memory.rss / (1024 * 1024)
            except Exception:
                pass

        # Count threads
        try:
            thread_count = threading.active_count()
        except Exception:
            thread_count = 0

        # Get last discovery time
        last_discovery = "never"
        with self._devices_lock:
            if self.devices:
                latest_device = max(
                    self.devices.values(),
                    key=lambda d: d.discovered_at or "",
                    default=None,
                )
                if latest_device and latest_device.discovered_at:
                    last_discovery = latest_device.discovered_at

        return {
            "status": "ok" if self.running else "stopped",
            "running": self.running,
            "uptime_seconds": uptime_seconds,
            "memory_usage_mb": round(memory_usage_mb, 2),
            "thread_count": thread_count,
            "last_discovery": last_discovery,
            "interfaces": {
                "eth0": {
                    "name": cfg.ETH0_INTERFACE,
                    "up": self.eth0.is_up(),
                    "description": "IPv6 side (network)",
                },
                "eth1": {
                    "name": cfg.ETH1_INTERFACE,
                    "up": self.eth1.is_up(),
                    "description": "IPv4 side (devices)",
                },
            },
            "device_stats": {
                "total": len(self.devices),
                "active": sum(1 for d in self.devices.values() if d.status == "active"),
                "inactive": sum(
                    1 for d in self.devices.values() if d.status == "inactive"
                ),
                "discovering": sum(
                    1 for d in self.devices.values() if d.status == "discovering"
                ),
                "failed": sum(1 for d in self.devices.values() if d.status == "failed"),
            },
            "timestamp": datetime.now().isoformat(),
        }

    def get_status(self) -> dict:
        """Get current gateway status"""
        with self._devices_lock:
            devices_snapshot = dict(self.devices)

        return {
            "running": self.running,
            "devices": {m: d.to_dict() for m, d in devices_snapshot.items()},
            "device_count": len(devices_snapshot),
            "active_devices": sum(
                1 for d in devices_snapshot.values() if d.status == "active"
            ),
            "eth0_up": self.eth0.is_up(),
            "eth1_up": self.eth1.is_up(),
            "timestamp": datetime.now().isoformat(),
        }

    def get_device(self, mac: str) -> Optional[DeviceMapping]:
        """Get a specific device"""
        with self._devices_lock:
            return self.devices.get(mac)

    def list_devices(self) -> List[DeviceMapping]:
        """List all devices"""
        with self._devices_lock:
            return list(self.devices.values())

    def clear_cache(self) -> dict:
        """
        Clear in-memory and persisted device cache.
        Called by API /admin/clear-cache.
        """
        with self._devices_lock:
            count = len(self.devices)
            self.devices.clear()
        self.device_store.clear()
        self.logger.info("Cleared device cache (removed %d devices)", count)
        return {"cleared_devices": count}

    # ---- Lifecycle ----

    def initialize(self) -> bool:
        """Initialize the gateway service"""
        self.logger.info("Initializing gateway service...")

        self.devices = self.device_store.load_devices()
        self.logger.info("Loaded %d existing device mappings", len(self.devices))

        if not self.eth0.is_up():
            self.logger.info("Bringing %s up...", cfg.ETH0_INTERFACE)
            self.eth0.bring_up()

        if not self.eth1.is_up():
            self.logger.info("Bringing %s up...", cfg.ETH1_INTERFACE)
            self.eth1.bring_up()

        if cfg.ENABLE_FORWARDING:
            if not self.firewall.enable_forwarding():
                self.logger.error("Failed to enable forwarding")
                return False
            if not self.firewall.allow_eth0_to_eth1(
                cfg.ETH0_INTERFACE, cfg.ETH1_INTERFACE
            ):
                self.logger.error("Failed to configure firewall rules")
                return False

        self.logger.info("Gateway service initialized successfully")
        return True

    def start(self) -> None:
        """Start the gateway service"""
        if self.running:
            self.logger.warning("Service already running")
            return

        self.running = True
        self.logger.info("Starting gateway service...")

        self.discovery_thread = threading.Thread(
            target=self._discovery_loop,
            daemon=cfg.DISCOVERY_THREAD_DAEMON,
        )
        self.discovery_thread.start()

        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=cfg.MONITORING_THREAD_DAEMON,
        )
        self.monitor_thread.start()

        if cfg.API_ENABLED:
            self.api_server = GatewayAPIServer(
                gateway_service=self,
                host=cfg.API_HOST,
                port=cfg.API_PORT,
            )
            try:
                self.api_server.start()
            except Exception as e:
                self.logger.error("Failed to start API server: %s", e)

        self.logger.info("Gateway service started")

    def stop(self) -> None:
        """Stop the gateway service"""
        if not self.running:
            return

        self.running = False
        self.logger.info("Stopping gateway service...")

        if self.discovery_thread:
            self.discovery_thread.join(timeout=cfg.THREAD_JOIN_TIMEOUT)
        if self.monitor_thread:
            self.monitor_thread.join(timeout=cfg.THREAD_JOIN_TIMEOUT)

        if self.api_server:
            self.api_server.stop()

        with self._devices_lock:
            self.device_store.save_devices(self.devices)

        self.logger.info("Gateway service stopped")

    # ---- Internal loops ----

    def _discovery_loop(self) -> None:
        """Main loop: discover new MACs and request IPv6"""
        self.logger.info("Discovery loop started")

        while self.running:
            try:
                new_entries = self.arp_monitor.get_new_macs()

                for mac, ipv4 in new_entries:
                    with self._devices_lock:
                        if mac in self.devices:
                            # Update IPv4 if changed
                            if self.devices[mac].ipv4_address != ipv4:
                                self.devices[mac].ipv4_address = ipv4
                                self.logger.info(f"Updated IPv4 for {mac}: {ipv4}")
                            continue
                        if len(self.devices) >= cfg.MAX_DEVICES:
                            self.logger.warning(
                                "Max devices reached (%d); ignoring new MAC %s",
                                cfg.MAX_DEVICES,
                                mac,
                            )
                            continue
                        device = DeviceMapping(mac_address=mac, ipv4_address=ipv4)
                        self.devices[mac] = device
                    self.logger.info("New device discovered: %s (IPv4: %s)", mac, ipv4)

                    thread = threading.Thread(
                        target=self._discover_addresses_for_device,
                        args=(mac,),
                        daemon=True,
                    )
                    thread.start()

                time.sleep(cfg.ARP_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                time.sleep(5)

    def _discover_addresses_for_device(self, mac: str) -> None:
        """
        Discover WAN addresses (IPv4 and/or IPv6) for a specific MAC address.
        Requests DHCPv4 and/or DHCPv6 based on what protocols are available on eth0.
        """
        try:
            with self._devices_lock:
                device = self.devices.get(mac)
                if not device:
                    return
                device.status = "discovering"

            # Determine which protocols to attempt
            attempt_ipv4, attempt_ipv6 = self.should_attempt_protocols()

            # Request IPv4 if we should attempt it
            if attempt_ipv4:
                self.logger.info(f"Requesting DHCPv4 for {mac}")
                ipv4_wan = self.dhcpv4_manager.request_ipv4_for_mac(mac)

                with self._devices_lock:
                    device = self.devices.get(mac)
                    if device and ipv4_wan:
                        device.ipv4_wan_address = ipv4_wan
                        self.logger.info(f"Device {mac} → WAN IPv4: {ipv4_wan}")
                    elif device:
                        self.logger.warning(f"Failed to obtain IPv4 for {mac}")
            else:
                self.logger.info(f"Skipping DHCPv4 for {mac}")

            # Request IPv6 if we should attempt it
            if attempt_ipv6:
                self.logger.info(f"Requesting DHCPv6 for {mac}")
                ipv6 = self.dhcpv6_manager.request_ipv6_for_mac(mac)

                with self._devices_lock:
                    device = self.devices.get(mac)
                    if device and ipv6:
                        device.ipv6_address = ipv6
                        self.logger.info(f"Device {mac} → WAN IPv6: {ipv6}")
                    elif device:
                        self.logger.warning(f"Failed to obtain IPv6 for {mac}")
            else:
                self.logger.info(f"Skipping DHCPv6 for {mac}")

            # Update device status
            with self._devices_lock:
                device = self.devices.get(mac)
                if not device:
                    return

                # Device is active if it got at least one address
                if device.ipv4_wan_address or device.ipv6_address:
                    device.status = "active"
                    addresses = []
                    if device.ipv4_wan_address:
                        addresses.append(f"IPv4: {device.ipv4_wan_address}")
                    if device.ipv6_address:
                        addresses.append(f"IPv6: {device.ipv6_address}")
                    self.logger.info(
                        f"Device {mac} successfully configured - {', '.join(addresses)}"
                    )
                else:
                    device.status = "failed"
                    self.logger.warning(
                        f"Failed to discover any WAN addresses for {mac}"
                    )

                self.device_store.add_device(device)

        except Exception as e:
            self.logger.error(f"Error discovering addresses for {mac}: {e}")
            with self._devices_lock:
                if mac in self.devices:
                    self.devices[mac].status = "error"

    def _monitoring_loop(self) -> None:
        """Monitor active devices and update status / timeouts"""
        self.logger.info("Monitoring loop started")
        timeout_delta = timedelta(seconds=cfg.DEVICE_STATUS_TIMEOUT)

        while self.running:
            try:
                current_arp_entries = self.arp_monitor.get_arp_entries()
                current_macs = {mac for mac, _ in current_arp_entries}
                now = datetime.now()

                with self._devices_lock:
                    for mac, device in self.devices.items():
                        if mac in current_macs:
                            device.last_seen = now.isoformat()
                            if device.status == "pending":
                                device.status = "active"
                        else:
                            try:
                                last_seen_dt = datetime.fromisoformat(device.last_seen)
                                if now - last_seen_dt > timeout_delta:
                                    if device.status == "active":
                                        device.status = "inactive"
                            except Exception:
                                if device.status == "active":
                                    device.status = "inactive"

                    self.device_store.save_devices(self.devices)

                time.sleep(cfg.DEVICE_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)


def main() -> None:
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("IPv4↔IPv6 Gateway Service Starting")
    logger.info("=" * 60)

    service = GatewayService()

    if not service.initialize():
        logger.error("Failed to initialize service")
        sys.exit(1)

    service.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
        service.stop()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        service.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
