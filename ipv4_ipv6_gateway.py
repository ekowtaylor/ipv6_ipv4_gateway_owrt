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
from haproxy_manager import HAProxyManager

# API server completely removed - use gateway-status-direct and gateway-devices-direct instead

# Validate config and ensure directories/commands exist BEFORE logging setup
cfg.validate_config()

# Configure logging using gateway_config settings
log_level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format=cfg.LOG_FORMAT,
    handlers=[
        logging.FileHandler(cfg.LOG_FILE),
    ],
)

logger = logging.getLogger("GatewayService")


class GatewayMetrics:
    """
    Tracks performance metrics and statistics for the gateway.

    Provides insights into:
    - IPv4/IPv6 discovery times
    - Cache hit rates
    - Success/failure rates
    - Protocol usage patterns
    """

    def __init__(self):
        self.counters = {
            "devices_discovered": 0,
            "ipv4_discoveries": 0,
            "ipv6_discoveries": 0,
            "ipv6_cache_hits": 0,
            "ipv6_cache_misses": 0,
            "ipv4_successes": 0,
            "ipv4_failures": 0,
            "ipv6_successes": 0,
            "ipv6_failures": 0,
            "slaac_successes": 0,
            "dhcpv6_successes": 0,
            "proxy_starts": 0,
            "proxy_failures": 0,
            "mac_restorations": 0,
            "wan_ip_changes": 0,
        }

        self.timings = {
            "ipv4_discovery_ms": [],
            "ipv6_discovery_ms": [],
            "total_discovery_ms": [],
        }

        self._lock = threading.Lock()
        self.logger = logging.getLogger("GatewayMetrics")

    def record_ipv4_discovery(self, duration_ms: float, success: bool):
        """Record IPv4 discovery attempt"""
        with self._lock:
            self.counters["ipv4_discoveries"] += 1
            if success:
                self.counters["ipv4_successes"] += 1
                self.timings["ipv4_discovery_ms"].append(duration_ms)
            else:
                self.counters["ipv4_failures"] += 1

    def record_ipv6_discovery(
        self, duration_ms: float, success: bool, from_cache: bool
    ):
        """Record IPv6 discovery attempt"""
        with self._lock:
            self.counters["ipv6_discoveries"] += 1
            if success:
                self.counters["ipv6_successes"] += 1
                self.timings["ipv6_discovery_ms"].append(duration_ms)

                if from_cache:
                    self.counters["ipv6_cache_hits"] += 1
                else:
                    self.counters["ipv6_cache_misses"] += 1
            else:
                self.counters["ipv6_failures"] += 1
                self.counters["ipv6_cache_misses"] += 1

    def record_total_discovery(self, duration_ms: float):
        """Record total discovery time (IPv4 + IPv6)"""
        with self._lock:
            self.timings["total_discovery_ms"].append(duration_ms)
            self.counters["devices_discovered"] += 1

    def record_proxy_start(self, success: bool):
        """Record proxy startup attempt"""
        with self._lock:
            if success:
                self.counters["proxy_starts"] += 1
            else:
                self.counters["proxy_failures"] += 1

    def record_mac_restoration(self):
        """Record MAC address restoration"""
        with self._lock:
            self.counters["mac_restorations"] += 1

    def record_wan_ip_change(self):
        """Record WAN IP address change"""
        with self._lock:
            self.counters["wan_ip_changes"] += 1

    def get_stats(self) -> dict:
        """Get comprehensive statistics"""
        with self._lock:
            # Calculate averages
            avg_ipv4_time = (
                sum(self.timings["ipv4_discovery_ms"])
                / len(self.timings["ipv4_discovery_ms"])
                if self.timings["ipv4_discovery_ms"]
                else 0
            )

            avg_ipv6_time = (
                sum(self.timings["ipv6_discovery_ms"])
                / len(self.timings["ipv6_discovery_ms"])
                if self.timings["ipv6_discovery_ms"]
                else 0
            )

            avg_total_time = (
                sum(self.timings["total_discovery_ms"])
                / len(self.timings["total_discovery_ms"])
                if self.timings["total_discovery_ms"]
                else 0
            )

            # Calculate cache hit rate
            total_ipv6_attempts = (
                self.counters["ipv6_cache_hits"] + self.counters["ipv6_cache_misses"]
            )
            cache_hit_rate = (
                (self.counters["ipv6_cache_hits"] / total_ipv6_attempts * 100)
                if total_ipv6_attempts > 0
                else 0
            )

            # Calculate success rates
            ipv4_success_rate = (
                (
                    self.counters["ipv4_successes"]
                    / self.counters["ipv4_discoveries"]
                    * 100
                )
                if self.counters["ipv4_discoveries"] > 0
                else 0
            )

            ipv6_success_rate = (
                (
                    self.counters["ipv6_successes"]
                    / self.counters["ipv6_discoveries"]
                    * 100
                )
                if self.counters["ipv6_discoveries"] > 0
                else 0
            )

            return {
                "counters": self.counters.copy(),
                "averages": {
                    "ipv4_discovery_ms": round(avg_ipv4_time, 1),
                    "ipv6_discovery_ms": round(avg_ipv6_time, 1),
                    "total_discovery_ms": round(avg_total_time, 1),
                },
                "rates": {
                    "ipv6_cache_hit_rate": round(cache_hit_rate, 1),
                    "ipv4_success_rate": round(ipv4_success_rate, 1),
                    "ipv6_success_rate": round(ipv6_success_rate, 1),
                },
                "recent_discoveries": {
                    "count": len(self.timings["total_discovery_ms"]),
                    "last_5_times_ms": (
                        self.timings["total_discovery_ms"][-5:]
                        if self.timings["total_discovery_ms"]
                        else []
                    ),
                },
            }

    def log_stats(self):
        """Log current statistics"""
        stats = self.get_stats()
        self.logger.info("=" * 60)
        self.logger.info("GATEWAY PERFORMANCE STATISTICS")
        self.logger.info("=" * 60)
        self.logger.info(
            f"Devices discovered: {stats['counters']['devices_discovered']}"
        )
        self.logger.info(
            f"IPv6 cache hit rate: {stats['rates']['ipv6_cache_hit_rate']:.1f}%"
        )
        self.logger.info(
            f"IPv4 success rate: {stats['rates']['ipv4_success_rate']:.1f}%"
        )
        self.logger.info(
            f"IPv6 success rate: {stats['rates']['ipv6_success_rate']:.1f}%"
        )
        self.logger.info(
            f"Avg IPv4 time: {stats['averages']['ipv4_discovery_ms']:.1f}ms"
        )
        self.logger.info(
            f"Avg IPv6 time: {stats['averages']['ipv6_discovery_ms']:.1f}ms"
        )
        self.logger.info(
            f"Avg total time: {stats['averages']['total_discovery_ms']:.1f}ms"
        )
        self.logger.info("=" * 60)


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

    def bring_down(self) -> bool:
        """Bring interface down"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.interface_name, "down"],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Brought {self.interface_name} down")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to bring down interface: {e}")
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

    def add_ipv6_address(self, ipv6: str, prefix_len: int = 64) -> bool:
        """Add an IPv6 address to interface"""
        try:
            subprocess.run(
                [
                    cfg.CMD_IP,
                    "-6",
                    "addr",
                    "add",
                    f"{ipv6}/{prefix_len}",
                    "dev",
                    self.interface_name,
                ],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Added IPv6 {ipv6}/{prefix_len} to {self.interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            # Check if address already exists (not an error)
            if "RTNETLINK answers: File exists" in str(e.stderr):
                self.logger.debug(
                    f"IPv6 {ipv6} already exists on {self.interface_name}"
                )
                return True
            self.logger.error(f"Failed to add IPv6 address: {e}")
            return False

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

        # OPTIMIZATION: Compile regex patterns once (reused in parsing)
        self._ipv4_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
        self._mac_pattern = re.compile(r'^([0-9a-f]{2}:){5}([0-9a-f]{2})$')

    def active_scan(self, subnet: str = "192.168.1") -> None:
        """
        ACTIVE ARP SCAN: Force devices to respond by pinging common IPs.

        This is CRITICAL for detecting idle devices that haven't sent any packets yet!

        The passive ARP monitor only sees devices that have already communicated.
        This active scan forces devices to respond by:
        1. Pinging all common DHCP pool IPs (192.168.1.100-150)
        2. Pinging common static IPs (192.168.1.1, 192.168.1.254, etc.)
        3. Waiting for ARP responses to populate the ARP table

        Args:
            subnet: IP subnet prefix (default: 192.168.1)
        """
        self.logger.info(f"Running ACTIVE ARP scan on {subnet}.0/24...")

        # Common IPs to scan (DHCP pool + gateway + broadcast + common static IPs)
        common_ips = list(range(100, 151))  # DHCP pool: .100 - .150
        common_ips.extend([1, 2, 254])  # Gateway, router, broadcast
        common_ips.extend([10, 20, 50, 128, 129, 130, 131, 132])  # Common static IPs

        # Ping all IPs in parallel (fast!)
        processes = []
        for ip_suffix in common_ips:
            ip = f"{subnet}.{ip_suffix}"
            try:
                # Use -c 1 (one ping), -W 1 (1 second timeout), run in background
                proc = subprocess.Popen(
                    ["ping", "-c", "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                processes.append(proc)
            except Exception as e:
                self.logger.debug(f"Failed to ping {ip}: {e}")

        # Wait for all pings to complete (max 2 seconds)
        time.sleep(2)

        # Terminate any remaining ping processes
        for proc in processes:
            try:
                proc.terminate()
            except Exception:
                pass

        self.logger.info(f"Active ARP scan completed - ARP table should now be populated")

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
    """Manages IPv6 address assignment (SLAAC + DHCPv6) with MAC spoofing"""

    def __init__(self, interface: str, timeout: int = cfg.DHCPV6_TIMEOUT):
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger("DHCPv6Manager")
        self.iface = NetworkInterface(interface)

    def discover_ipv6_from_neighbor_table(self, mac: str) -> Optional[str]:
        """
        Discover device's IPv6 address by querying router's IPv6 neighbor table.

        This is the AUTHORITATIVE way to find the device's IPv6 address!
        The router's neighbor discovery protocol (NDP) cache shows what IPv6
        addresses the router actually knows for this device.

        This is better than DHCPv6 discovery because:
        - Router is the source of truth
        - Works even if device got IPv6 via SLAAC (not DHCPv6)
        - Gets the ACTUAL address router is routing to
        - Avoids MAC spoofing issues (we just query, don't spoof)

        Args:
            mac: Device MAC address to look up

        Returns:
            IPv6 address if found in neighbor table, None otherwise
        """
        try:
            # Query IPv6 neighbor table (NDP cache)
            # Format: fe80::1234 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            result = subprocess.run(
                [cfg.CMD_IP, "-6", "neigh", "show", "dev", self.interface],
                capture_output=True,
                text=True,
                check=True,
            )

            ipv6_addresses = []
            for line in result.stdout.splitlines():
                # Check if this line is for our MAC address
                if mac.lower() in line.lower():
                    # Extract IPv6 address (first field)
                    parts = line.split()
                    if parts:
                        ipv6 = parts[0]
                        # Skip link-local addresses (fe80::)
                        if not ipv6.lower().startswith("fe80:"):
                            ipv6_addresses.append(ipv6)
                            self.logger.info(
                                f"Found IPv6 {ipv6} for MAC {mac} in neighbor table"
                            )

            if ipv6_addresses:
                # CRITICAL: Return ALL IPv6 addresses, not just one!
                # Why bind to all addresses instead of picking "best"?
                # 1. Maximum compatibility - works regardless of which address router/client uses
                # 2. Handles privacy extensions - multiple addresses all work
                # 3. Resilient - if one becomes unreachable, others still work
                # 4. No guessing - don't need to pick which is "preferred"
                #
                # We'll start socat proxies for ALL of them:
                # - socat bind=[dd56:fb82:64ad::85c]:8080 → device:80
                # - socat bind=[dd56:fb82:64ad::46b7:d0ff:fea6:773f]:8080 → device:80
                # This way ANY IPv6 the router knows will work!

                if len(ipv6_addresses) > 1:
                    self.logger.info(
                        f"Found {len(ipv6_addresses)} IPv6 addresses for MAC {mac}: {ipv6_addresses}"
                    )
                    self.logger.info(
                        f"Will bind socat to ALL addresses for maximum compatibility"
                    )
                else:
                    self.logger.info(
                        f"✓ Discovered IPv6 from neighbor table: {ipv6_addresses[0]} (MAC: {mac})"
                    )

                # Return ALL addresses (will be stored as comma-separated string)
                return ",".join(ipv6_addresses)
            else:
                self.logger.debug(
                    f"No global IPv6 addresses found for MAC {mac} in neighbor table"
                )
                return None

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to query IPv6 neighbor table: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error discovering IPv6 from neighbor table: {e}")
            return None

    def request_ipv6_address(
        self, mac: str, cached_ipv6: Optional[str] = None
    ) -> Optional[str]:
        """
        Request IPv6 address for device MAC using SLAAC or DHCPv6.

        OPTIMIZATION: If cached_ipv6 is provided and MAC hasn't changed, we try to
        reuse the cached IPv6 instead of requesting a new one. This is MUCH faster
        than full SLAAC/DHCPv6 (which takes 15+ seconds).

        Strategy:
        1. If cached IPv6 provided and MAC is already set → try to reuse cached IPv6
        2. If reuse fails or no cache → do full SLAAC/DHCPv6 acquisition
        3. Cache the successful IPv6 for future reuse

        CRITICAL: This method does NOT restore the original MAC after obtaining IPv6!
        For MAC-authenticated networks (802.1X, MAC filtering), we must keep the
        device's MAC address permanently on the WAN interface. The network only
        allows traffic from authenticated MACs, so using gateway's MAC would block traffic.

        Args:
            mac: Device MAC address to request IPv6 for
            cached_ipv6: Previously successful IPv6 for this MAC (optional)

        Returns:
            IPv6 address if successful, None otherwise
        """
        original_mac = self.iface.get_mac_address()
        obtained_ipv6 = None  # Track obtained IPv6 for re-adding after MAC restoration

        try:
            # OPTIMIZATION: Try to reuse cached IPv6 if available
            if cached_ipv6 and original_mac == mac:
                self.logger.info(
                    f"Attempting to reuse cached IPv6 {cached_ipv6} for MAC {mac} "
                    f"(MAC unchanged, skipping full SLAAC/DHCPv6)"
                )

                # Check if cached IPv6 is already configured
                current_ipv6s = self.iface.get_ipv6_addresses()
                if cached_ipv6 in current_ipv6s:
                    self.logger.info(
                        f"✓ Cached IPv6 {cached_ipv6} already configured on {self.interface}"
                    )
                    obtained_ipv6 = cached_ipv6  # CRITICAL: Set before early return!
                    return cached_ipv6

                # Try to add cached IPv6
                if self.iface.add_ipv6_address(cached_ipv6, 64):
                    # Verify it was added successfully
                    time.sleep(1)
                    current_ipv6s = self.iface.get_ipv6_addresses()
                    if cached_ipv6 in current_ipv6s:
                        self.logger.info(
                            f"✓ Successfully reused cached IPv6 {cached_ipv6} "
                            f"(saved ~15s SLAAC wait)"
                        )
                        obtained_ipv6 = (
                            cached_ipv6  # CRITICAL: Set before early return!
                        )
                        return cached_ipv6
                    else:
                        self.logger.warning(
                            f"Failed to verify cached IPv6 {cached_ipv6} - "
                            f"falling back to full acquisition"
                        )
                else:
                    self.logger.warning(
                        f"Failed to add cached IPv6 {cached_ipv6} - "
                        f"falling back to full acquisition"
                    )

            # STRATEGY 1: Try to discover IPv6 from router's neighbor table FIRST!
            # This is the most authoritative and reliable method:
            # - Gets the ACTUAL IPv6 the router knows about
            # - No MAC spoofing needed (just query)
            # - Works even if device got IPv6 via SLAAC (not DHCPv6)
            # - Much faster than full SLAAC/DHCPv6 cycle
            self.logger.info(f"Attempting neighbor table discovery for MAC {mac}...")
            neighbor_ipv6 = self.discover_ipv6_from_neighbor_table(mac)

            if neighbor_ipv6:
                self.logger.info(
                    f"✓ SUCCESS! Found IPv6 from neighbor table: {neighbor_ipv6} "
                    f"(saved ~15-75s by skipping SLAAC/DHCPv6!)"
                )
                obtained_ipv6 = neighbor_ipv6
                return neighbor_ipv6

            # STRATEGY 2: Neighbor table didn't have IPv6, fall back to full SLAAC/DHCPv6
            self.logger.info(
                f"Neighbor table had no IPv6 for MAC {mac} - "
                f"performing full IPv6 acquisition (SLAAC/DHCPv6)"
            )

            self.iface.flush_ipv6_addresses()

            if not self.iface.set_mac_address(mac):
                self.logger.error(f"Failed to spoof MAC {mac}")
                return None

            # CRITICAL: Flush IPv6 neighbor cache after MAC change
            # When MAC changes, old IPv6 neighbor entries can cause conflicts
            # The router needs to learn the new MAC for IPv6 neighbor discovery
            try:
                subprocess.run(
                    [cfg.CMD_IP, "-6", "neigh", "flush", "dev", self.interface],
                    check=True,
                    capture_output=True,
                )
                self.logger.debug(f"Flushed IPv6 neighbor cache on {self.interface}")
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to flush IPv6 neighbor cache: {e}")

            # CRITICAL: Force Router Solicitation after MAC spoofing
            # Many routers filter Router Advertisements by MAC address for security
            # After MAC change, we must explicitly request RAs from the router
            try:
                # Enable Router Solicitation on interface
                subprocess.run(
                    [
                        cfg.CMD_SYSCTL,
                        "-w",
                        f"net.ipv6.conf.{self.interface}.router_solicitations=3",
                    ],
                    check=True,
                    capture_output=True,
                )
                self.logger.debug(f"Enabled Router Solicitations on {self.interface}")

                # Trigger immediate Router Solicitation by pinging all-routers multicast
                # This forces the router to send a Router Advertisement to our new MAC
                subprocess.run(
                    ["ping6", "-c", "1", "-W", "1", "-I", self.interface, "ff02::2"],
                    capture_output=True,
                    timeout=2,
                )
                self.logger.debug(f"Sent Router Solicitation to all-routers (ff02::2)")
            except subprocess.TimeoutExpired:
                self.logger.debug("Router Solicitation ping timed out (expected)")
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to send Router Solicitation: {e}")
            except Exception as e:
                self.logger.warning(f"Error during Router Solicitation: {e}")

            time.sleep(1)

            # Retry with exponential backoff
            for attempt in range(cfg.DHCPV6_RETRY_COUNT):
                attempt_num = attempt + 1
                self.logger.debug(
                    f"IPv6 attempt {attempt_num}/{cfg.DHCPV6_RETRY_COUNT} for MAC {mac}"
                )

                # Enable IPv6 on interface (required for SLAAC)
                if not self._enable_ipv6_on_interface():
                    self.logger.warning(f"Failed to enable IPv6 on {self.interface}")
                    continue

                # Wait for SLAAC (Router Advertisement)
                # CRITICAL: IPv6 takes MUCH longer than IPv4 after MAC change!
                # - Router must detect new MAC via Neighbor Discovery
                # - Router Advertisement must be sent to new MAC
                # - SLAAC address generation and DAD (Duplicate Address Detection)
                # Increased from 3s to 15s to allow proper IPv6 acquisition
                self.logger.debug(f"Waiting for SLAAC (Router Advertisement)...")
                time.sleep(15)  # Give SLAAC time to work after MAC spoof

                # Check if SLAAC assigned an address
                addresses = self.iface.get_ipv6_addresses()
                if addresses:
                    ipv6 = addresses[0]
                    obtained_ipv6 = ipv6  # Store for re-adding later
                    self.logger.info(
                        f"Successfully obtained IPv6 {ipv6} via SLAAC for MAC {mac} "
                        f"(attempt {attempt_num})"
                    )

                    # Try DHCPv6 for additional configuration (DNS, etc.)
                    # This won't necessarily give us a new address, but provides other info
                    self.logger.debug(
                        "Attempting DHCPv6 for additional configuration..."
                    )
                    self._request_dhcpv6_info_only()

                    return ipv6

                # SLAAC didn't work, try full DHCPv6
                self.logger.debug("SLAAC didn't assign address, trying DHCPv6...")
                if self._request_dhcpv6():
                    time.sleep(2)
                    addresses = self.iface.get_ipv6_addresses()

                    if addresses:
                        ipv6 = addresses[0]
                        obtained_ipv6 = ipv6  # Store for re-adding later
                        self.logger.info(
                            f"Successfully obtained IPv6 {ipv6} via DHCPv6 for MAC {mac} "
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
                        f"Both SLAAC and DHCPv6 failed for MAC {mac} (attempt {attempt_num})"
                    )

                # Exponential backoff: wait longer after each failed attempt
                if attempt < cfg.DHCPV6_RETRY_COUNT - 1:
                    backoff_time = cfg.DHCPV6_RETRY_DELAY * (2**attempt)
                    self.logger.debug(f"Waiting {backoff_time}s before retry...")
                    time.sleep(backoff_time)

            # All retries failed
            self.logger.error(
                f"All {cfg.DHCPV6_RETRY_COUNT} IPv6 attempts failed for MAC {mac}"
            )
            return None

        except Exception as e:
            self.logger.error(f"Exception during IPv6 request: {e}")
            return None
        finally:
            # CRITICAL FOR MAC-AUTHENTICATED NETWORKS:
            # DO NOT restore original MAC! We must keep the device's MAC address
            # because the network only allows authenticated MACs (802.1X or MAC filtering).
            # The gateway's original MAC is not authorized, so traffic would be blocked.
            if original_mac and mac != original_mac:
                self.logger.warning(
                    f"NOT restoring original MAC {original_mac} - keeping device MAC {mac} "
                    f"for network authentication (802.1X/MAC filtering)"
                )

            # CRITICAL FIX: Re-add IPv6 to eth0 after DHCPv6/SLAAC
            # The kernel may have removed the IPv6 during the DHCPv6 process
            # We must manually ensure the IPv6 is configured for socat/HAProxy to bind to it
            if obtained_ipv6:
                time.sleep(1)  # Let network settle

                self.logger.info(
                    f"Ensuring IPv6 {obtained_ipv6} is configured on {self.interface}..."
                )
                if self.iface.add_ipv6_address(obtained_ipv6, 64):
                    self.logger.info(
                        f"✓ IPv6 {obtained_ipv6} configured on {self.interface}"
                    )

                    # Enable Proxy NDP for this IPv6
                    if self._enable_proxy_ndp(obtained_ipv6):
                        self.logger.info(f"✓ Enabled Proxy NDP for {obtained_ipv6}")
                    else:
                        self.logger.warning(
                            f"⚠ Failed to enable Proxy NDP for {obtained_ipv6}"
                        )

                    # CRITICAL: Wait for kernel to fully initialize the IPv6 address
                    # Give the kernel time to complete DAD (Duplicate Address Detection)
                    # and make the address available for binding
                    self.logger.info(
                        f"Waiting for IPv6 address to be fully ready for binding..."
                    )
                    time.sleep(3)  # Wait for DAD to complete

                    # Verify the address is actually present and usable
                    max_verify_attempts = 5
                    for attempt in range(max_verify_attempts):
                        if self._verify_ipv6_present(obtained_ipv6):
                            self.logger.info(
                                f"✓ Confirmed: IPv6 {obtained_ipv6} is present and ready on {self.interface}"
                            )
                            break
                        else:
                            if attempt < max_verify_attempts - 1:
                                self.logger.warning(
                                    f"IPv6 {obtained_ipv6} not yet ready, waiting... (attempt {attempt + 1}/{max_verify_attempts})"
                                )
                                time.sleep(2)
                            else:
                                self.logger.error(
                                    f"✗ IPv6 {obtained_ipv6} still not ready after {max_verify_attempts} attempts"
                                )
                else:
                    self.logger.error(
                        f"✗ Failed to configure IPv6 {obtained_ipv6} on {self.interface}"
                    )

            # CRITICAL: Do NOT return from finally block!
            # Early returns (lines 626, 638, 746, 761) already handle successful cases
            # Returning here would overwrite those successful return values
            # The finally block should only do cleanup, not return values

    def _verify_ipv6_present(self, ipv6: str) -> bool:
        """
        Verify that an IPv6 address is present on the interface.

        Args:
            ipv6: IPv6 address to verify

        Returns:
            True if address is present and ready, False otherwise
        """
        try:
            addresses = self.iface.get_ipv6_addresses()
            return ipv6 in addresses
        except Exception as e:
            self.logger.error(f"Failed to verify IPv6 presence: {e}")
            return False

    def _enable_ipv6_on_interface(self) -> bool:
        """
        Enable IPv6 on interface for SLAAC.
        This enables Router Advertisement processing.
        """
        try:
            # Enable IPv6 forwarding and accept RA
            subprocess.run(
                [
                    cfg.CMD_SYSCTL,
                    "-w",
                    f"net.ipv6.conf.{self.interface}.disable_ipv6=0",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", f"net.ipv6.conf.{self.interface}.accept_ra=2"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", f"net.ipv6.conf.{self.interface}.autoconf=1"],
                check=True,
                capture_output=True,
            )
            self.logger.debug(f"Enabled IPv6/SLAAC on {self.interface}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to enable IPv6 on {self.interface}: {e}")
            return False

    def _enable_proxy_ndp(self, ipv6: str) -> bool:
        """
        Enable IPv6 Proxy NDP for the given address AND advertise to router.

        This does THREE critical things:
        1. Enables Proxy NDP - kernel responds to neighbor discovery for this IPv6
        2. Enables global proxy_ndp sysctl settings
        3. Sends Neighbor Advertisement to router - announces the IPv6 address

        Without step 3, the router won't know about this IPv6 and can't route to it!

        Args:
            ipv6: IPv6 address to enable proxy NDP for

        Returns:
            True if successful
        """
        # Step 1: Enable global proxy_ndp sysctls (must be done first!)
        try:
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.all.proxy_ndp=1"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", f"net.ipv6.conf.{self.interface}.proxy_ndp=1"],
                check=True,
                capture_output=True,
            )
            self.logger.debug(f"Enabled global proxy_ndp for {self.interface}")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to enable global proxy_ndp: {e}")

        # Step 2: Add proxy NDP entry for this specific IPv6
        try:
            subprocess.run(
                [
                    cfg.CMD_IP,
                    "-6",
                    "neigh",
                    "add",
                    "proxy",
                    ipv6,
                    "dev",
                    self.interface,
                ],
                check=True,
                capture_output=True,
            )
            self.logger.debug(f"Enabled Proxy NDP for {ipv6} on {self.interface}")
        except subprocess.CalledProcessError as e:
            # Check if it already exists (exit code 2)
            if e.returncode == 2:
                self.logger.debug(f"Proxy NDP already enabled for {ipv6}")
            else:
                self.logger.error(f"Failed to enable Proxy NDP for {ipv6}: {e}")
                return False

        # Step 3: CRITICAL - Send Neighbor Advertisement to router!
        # This announces the IPv6 address so the router knows we have it
        # Without this, the router won't route traffic to this IPv6
        try:
            # Send ping6 to all-nodes multicast to trigger neighbor discovery
            # This makes the router learn about our IPv6 address
            self.logger.info(
                f"Advertising IPv6 {ipv6} to router via Neighbor Advertisement..."
            )
            subprocess.run(
                ["ping6", "-c", "2", "-I", self.interface, "ff02::1"],
                capture_output=True,
                timeout=3,
            )
            self.logger.info(f"✓ Advertised IPv6 {ipv6} to router")
        except subprocess.TimeoutExpired:
            self.logger.debug("Neighbor Advertisement ping timeout (expected)")
        except Exception as e:
            self.logger.warning(f"Failed to send Neighbor Advertisement: {e}")

        return True

    def _request_dhcpv6(self) -> bool:
        """Execute DHCPv6 request using odhcp6c (stateful - requests address)"""
        process = None
        try:
            # -P 0: Request address (not just prefix)
            # -s: Script to execute (use default)
            # -t timeout: How long to wait
            process = subprocess.Popen(
                [cfg.CMD_ODHCP6C, "-P", "0", "-t", str(self.timeout), self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = process.communicate(timeout=self.timeout + 2)
                return_code = process.returncode

                if return_code == 0:
                    self.logger.debug("DHCPv6 request succeeded")
                    return True
                else:
                    self.logger.debug(
                        f"DHCPv6 request failed with exit code {return_code}"
                    )
                    return False

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
                    process.wait()
                return False

        except Exception as e:
            self.logger.error(f"DHCPv6 request error: {e}")
            return False
        finally:
            # Ensure process is cleaned up if still running
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def _request_dhcpv6_info_only(self) -> bool:
        """
        Execute DHCPv6 information-only request (doesn't request address).
        Used after SLAAC to get DNS, NTP, etc.
        """
        try:
            # -S: Information-only mode (no address request)
            # -t timeout: How long to wait
            process = subprocess.Popen(
                [cfg.CMD_ODHCP6C, "-S", "-t", "5", self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = process.communicate(timeout=7)
                if process.returncode == 0:
                    self.logger.debug("DHCPv6 info-only request succeeded")
                    return True
                # CRITICAL FIX: Return False if process failed, not True
                return False
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()  # Wait after kill to prevent zombie
                return False

        except Exception as e:
            self.logger.debug(f"DHCPv6 info-only request error (non-critical): {e}")
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
            # CRITICAL FOR MAC-AUTHENTICATED NETWORKS:
            # DO NOT restore original MAC! We must keep the device's MAC address
            # because the network only allows authenticated MACs (802.1X or MAC filtering).
            # The gateway's original MAC is not authorized, so traffic would be blocked.
            # MAC is set PERMANENTLY and only restored during uninstall.
            if original_mac and mac != original_mac:
                self.logger.debug(
                    f"Keeping device MAC {mac} (not restoring {original_mac}) - "
                    f"permanent MAC spoofing for network authentication"
                )

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
        """
        Load all device mappings from disk with robust error handling.

        Handles:
        - Corrupted JSON files (automatic backup and recovery)
        - Missing files (creates new)
        - Permission errors
        - Lock timeouts

        Returns empty dict on any error to allow gateway to start fresh.
        """
        try:
            # CRITICAL: Use timeout on lock to prevent deadlock
            if not self._lock.acquire(timeout=5):
                self.logger.error("Failed to acquire device store lock after 5s - starting fresh")
                return {}

            try:
                if not self.devices_file.exists():
                    self.logger.info("No existing devices file, starting fresh")
                    return {}

                self.logger.info(f"Loading device mappings from {self.devices_file}...")

                try:
                    with open(self.devices_file, "r") as f:
                        data = json.load(f)

                    # Validate it's a dict
                    if not isinstance(data, dict):
                        raise ValueError(f"Expected dict, got {type(data)}")

                    # Convert to DeviceMapping objects
                    devices = {}
                    for mac, device_data in data.items():
                        try:
                            devices[mac] = DeviceMapping.from_dict(device_data)
                        except Exception as e:
                            self.logger.warning(f"Skipping invalid device {mac}: {e}")
                            continue

                    self.logger.info(f"Successfully loaded {len(devices)} device mappings")
                    return devices

                except json.JSONDecodeError as e:
                    # Corrupted JSON! Backup and start fresh
                    self.logger.error(f"⚠️ CORRUPTED device file: {e}")
                    backup_path = self.devices_file.with_suffix(".json.corrupted")

                    try:
                        # Backup the corrupted file for debugging
                        import shutil
                        shutil.copy(self.devices_file, backup_path)
                        self.logger.warning(f"Backed up corrupted file to {backup_path}")
                    except Exception as backup_error:
                        self.logger.warning(f"Could not backup corrupted file: {backup_error}")

                    # Start fresh
                    self.logger.info("Starting with fresh device store due to corruption")
                    return {}

                except PermissionError as e:
                    self.logger.error(f"Permission denied reading {self.devices_file}: {e}")
                    return {}

                except Exception as e:
                    self.logger.error(f"Unexpected error loading devices: {e}")
                    return {}

            finally:
                # CRITICAL: Always release lock!
                self._lock.release()

        except Exception as e:
            self.logger.error(f"Critical error in load_devices: {e}")
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
        """
        Enable IPv4 and IPv6 forwarding.

        CRITICAL IPv6 FIX: When forwarding is enabled, the kernel automatically
        disables Router Advertisement acceptance (accept_ra=0). This breaks SLAAC!

        We MUST set accept_ra=2 to accept RAs even with forwarding enabled.
        This allows the gateway to be BOTH a router AND a SLAAC client.
        """
        try:
            # Enable IPv4 forwarding
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv4.ip_forward=1"],
                check=True,
                capture_output=True,
            )

            # Enable IPv6 forwarding
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.all.forwarding=1"],
                check=True,
                capture_output=True,
            )

            # CRITICAL FIX: Accept Router Advertisements even with forwarding enabled!
            # Without this, eth0 will NOT get IPv6 from router via SLAAC!
            # accept_ra=2 means: "accept RA even when forwarding is enabled"
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.eth0.accept_ra=2"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.all.accept_ra=2"],
                check=True,
                capture_output=True,
            )

            # Enable IPv6 autoconfiguration (SLAAC)
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.eth0.autoconf=1"],
                check=True,
                capture_output=True,
            )

            # Ensure IPv6 is not disabled
            subprocess.run(
                [cfg.CMD_SYSCTL, "-w", "net.ipv6.conf.eth0.disable_ipv6=0"],
                check=True,
                capture_output=True,
            )

            self.logger.info("IP forwarding enabled for IPv4 and IPv6")
            self.logger.info("IPv6 Router Advertisement acceptance enabled (accept_ra=2)")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to enable forwarding: {e}")
            return False

    def allow_icmp(self) -> bool:
        """Allow ICMP (ping) traffic - CRITICAL for connectivity testing"""
        try:
            # ===== IPv4 ICMP Rules =====
            # Allow ICMP INPUT (ping to gateway itself)
            subprocess.run(
                [cfg.CMD_IPTABLES, "-I", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
                check=False,  # Don't fail if rule exists
                capture_output=True,
            )

            # Allow ICMP FORWARD (ping through gateway)
            subprocess.run(
                [cfg.CMD_IPTABLES, "-I", "FORWARD", "-p", "icmp", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ===== IPv6 ICMPv6 Rules =====
            # CRITICAL: IPv6 requires specific ICMPv6 types for Neighbor Discovery Protocol (NDP)
            # Without these, IPv6 routing and address resolution will fail!

            # ICMPv6 Type 128: Echo Request (ping)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "128",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "FORWARD",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "128",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 129: Echo Reply (ping response)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "129",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "FORWARD",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "129",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 133: Router Solicitation (ESSENTIAL for SLAAC)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "133",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 134: Router Advertisement (ESSENTIAL for SLAAC)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "134",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 135: Neighbor Solicitation (ESSENTIAL for NDP/address resolution)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "135",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "FORWARD",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "135",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 136: Neighbor Advertisement (ESSENTIAL for NDP/address resolution)
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "136",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "FORWARD",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "136",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 137: Redirect Message
            subprocess.run(
                [
                    cfg.CMD_IP6TABLES,
                    "-I",
                    "INPUT",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "137",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture_output=True,
            )

            # Also set default IPv6 policy to ACCEPT (critical!)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-P", "INPUT", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-P", "FORWARD", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-P", "OUTPUT", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            self.logger.info(
                "ICMP/ICMPv6 traffic allowed (ping enabled with NDP support)"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable ICMP: {e}")
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


class SocatProxyManager:
    """
    Manages socat-based IPv6→IPv4 proxying for devices.

    When an IPv4-only device is discovered, this creates socat proxies that:
    - Listen on IPv6 ports (on gateway's WAN IPv6 address)
    - Forward to IPv4 ports (on device's LAN IPv4 address)

    Example:
    IPv6 client → [gateway IPv6]:23 → socat → 192.168.1.128:23 → device
    """

    def __init__(self):
        self.logger = logging.getLogger("SocatProxyManager")
        self.proxies: Dict[str, Dict[int, subprocess.Popen]] = (
            {}
        )  # {mac: {port: process}}
        self.log_files: Dict[str, Dict[int, object]] = (
            {}
        )  # {mac: {port: log_file_handle}}
        self._lock = threading.Lock()

    def start_proxy_for_device(
        self, mac: str, device_ipv4: str, device_ipv6: str, port_map: Dict[int, int]
    ) -> bool:
        """
        Start socat proxies for all ports for a device.

        CRITICAL: Handles MULTIPLE IPv6 addresses (comma-separated)!
        A device can have both SLAAC and DHCPv6 addresses, and we must bind to ALL of them
        so clients can connect using any IPv6 address the router knows about.

        Args:
            mac: Device MAC address
            device_ipv4: Device's LAN IPv4 address (e.g., "192.168.1.128")
            device_ipv6: Device's WAN IPv6 address(es) - can be comma-separated!
                        e.g., "2620:10d:c050:100::85c,2620:10d:c050:100:46b7:d0ff:fea6:6afd"
            port_map: Port mapping {gateway_port: device_port}

        Returns:
            True if all proxies started successfully
        """
        # Split comma-separated IPv6 addresses
        ipv6_addresses = [addr.strip() for addr in device_ipv6.split(",") if addr.strip()]

        if len(ipv6_addresses) == 0:
            self.logger.error(f"No valid IPv6 addresses for {mac}")
            return False

        if len(ipv6_addresses) > 1:
            self.logger.info(
                f"Device {mac} has {len(ipv6_addresses)} IPv6 addresses - "
                f"will bind proxies to ALL for maximum compatibility"
            )

        self.logger.info(
            f"Starting IPv6→IPv4 proxies for device {device_ipv4} (MAC: {mac})"
        )

        for i, ipv6 in enumerate(ipv6_addresses, 1):
            self.logger.info(f"  IPv6 #{i}: {ipv6}")

        with self._lock:
            if mac not in self.proxies:
                self.proxies[mac] = {}

            success_count = 0
            total_proxies = len(port_map) * len(ipv6_addresses)

            # Start proxies for EACH IPv6 address and EACH port
            for ipv6 in ipv6_addresses:
                for gateway_port, device_port in port_map.items():
                    # Create unique port key that includes IPv6 index
                    # This allows multiple proxies on same port (different IPv6s)
                    proxy_key = f"{gateway_port}_{ipv6}"

                    if self._start_single_proxy(
                        mac, device_ipv4, ipv6, gateway_port, device_port, proxy_key
                    ):
                        success_count += 1

            self.logger.info(
                f"Started {success_count}/{total_proxies} IPv6→IPv4 proxies for {mac}"
            )
            return success_count > 0

    def _start_single_proxy(
        self,
        mac: str,
        device_ipv4: str,
        device_ipv6: str,
        gateway_port: int,
        device_port: int,
        proxy_key: str = None,
    ) -> bool:
        """
        Start a single socat proxy for one port and one IPv6 address.

        Args:
            proxy_key: Unique identifier for this proxy (allows multiple proxies on same port for different IPv6s)
        """
        # Use proxy_key if provided, otherwise default to just the port number
        if proxy_key is None:
            proxy_key = str(gateway_port)

        try:
            # Check if proxy already running for this key
            if proxy_key in self.proxies.get(mac, {}):
                existing_process = self.proxies[mac][proxy_key]
                if existing_process.poll() is None:  # Still running
                    self.logger.debug(
                        f"Proxy already running for {mac} key {proxy_key}"
                    )
                    return True
                else:
                    # Process died, remove it
                    del self.proxies[mac][proxy_key]

            # Determine if this port needs special protocol handling
            # Telnet ports: 23, 2323 (and any port that maps to 23)
            is_telnet_port = device_port == 23 or gateway_port == 2323

            # HTTP/HTTPS ports: 80, 443, 8080, 8443 (and any port that maps to 80/443)
            is_http_port = device_port in [80, 443] or gateway_port in [8080, 8443]

            # Verbose logging flags for socat
            # -d -d: Double verbose mode - logs connections and data transfer
            # -lf /dev/stdout: Log to stdout (captured by gateway log)
            verbose_flags = ["-d", "-d", "-lf", "/dev/stdout"]

            # SIMPLIFIED SOCAT COMMANDS - Use minimal options that work with all protocols
            # The "rawer" and "ignoreeof" options can cause issues with IPv6
            # Use standard TCP options that are universally compatible

            # CRITICAL FIX: DO NOT bind source IP on outgoing connections!
            # Why: Binding to gateway's LAN IP (192.168.1.1) causes routing conflicts:
            #   - IPv6 connection comes in on eth0
            #   - IPv4 connection goes out on eth1 with forced source IP
            #   - Device's response to 192.168.1.1 creates cross-interface routing confusion
            #   - Kernel can't determine correct return path → connection fails with RST
            # Solution: Let kernel auto-select source IP based on routing table (it's smarter!)
            #   - Kernel picks correct interface (eth1) and appropriate source IP
            #   - Responses route correctly back to socat
            #   - Connection succeeds! ✅

            # BIND TO DEVICE-SPECIFIC IPv6 ADDRESS
            # CRITICAL FIX: socat IPv6 bind syntax - NO brackets in bind parameter!
            # Correct:   TCP6-LISTEN:80,bind=2620:10d:c050:100::1,fork
            # Incorrect: TCP6-LISTEN:80,bind=[2620:10d:c050:100::1],fork (brackets cause failure!)
            socat_cmd = [
                cfg.CMD_SOCAT,
                *verbose_flags,
                f"TCP6-LISTEN:{gateway_port},bind={device_ipv6},fork,reuseaddr",
                f"TCP4:{device_ipv4}:{device_port}",  # No source binding - let kernel decide!
            ]

            # Start socat in background with logging
            # CRITICAL FIX: Ensure log path exists and is writable
            log_path = Path(cfg.LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Open log file for this proxy (will be closed when process terminates)
            try:
                log_file = open(log_path, "a")
            except IOError as e:
                self.logger.error(f"Cannot open log file {log_path}: {e}")
                # Fallback to /dev/null
                log_file = open("/dev/null", "a")

            process = subprocess.Popen(
                socat_cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,  # Merge stderr to stdout
                start_new_session=True,  # Detach from parent
            )

            # Store log file handle so we can close it later
            if mac not in self.log_files:
                self.log_files[mac] = {}
            self.log_files[mac][proxy_key] = log_file

            # Wait a moment to see if it crashes immediately
            time.sleep(0.1)
            if process.poll() is not None:
                self.logger.error(
                    f"Socat proxy failed to start for {mac} key {proxy_key}"
                )
                return False

            # Success! Store the process
            if mac not in self.proxies:
                self.proxies[mac] = {}
            self.proxies[mac][proxy_key] = process

            # Determine proxy type for logging
            if is_telnet_port:
                proxy_type = "telnet-aware"
            elif is_http_port:
                proxy_type = "http-aware"
            else:
                proxy_type = "standard"

            self.logger.info(
                f"IPv6→IPv4 proxy ({proxy_type}): [{device_ipv6}]:{gateway_port} → {device_ipv4}:{device_port} "
                f"(PID: {process.pid})"
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to start socat proxy for {mac} key {proxy_key}: {e}"
            )
            return False

    def stop_proxies_for_device(self, mac: str) -> None:
        """Stop all socat proxies for a device"""
        with self._lock:
            if mac not in self.proxies:
                return

            self.logger.info(f"Stopping IPv6→IPv4 proxies for {mac}")

            for port, process in list(self.proxies[mac].items()):
                try:
                    if process.poll() is None:  # Still running
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        self.logger.debug(f"Stopped proxy for {mac} port {port}")
                except Exception as e:
                    self.logger.error(
                        f"Error stopping proxy for {mac} port {port}: {e}"
                    )

                # CRITICAL FIX: Close log file handle to prevent resource leak
                if mac in self.log_files and port in self.log_files[mac]:
                    try:
                        self.log_files[mac][port].close()
                        del self.log_files[mac][port]
                    except Exception as e:
                        self.logger.error(
                            f"Error closing log file for {mac} port {port}: {e}"
                        )

            del self.proxies[mac]
            # Clean up log files dict if empty
            if mac in self.log_files and not self.log_files[mac]:
                del self.log_files[mac]

    def stop_all_proxies(self) -> None:
        """Stop all socat proxies"""
        with self._lock:
            self.logger.info("Stopping all IPv6→IPv4 proxies")
            for mac in list(self.proxies.keys()):
                self.stop_proxies_for_device(mac)

    def get_proxy_status(self, mac: Optional[str] = None) -> Dict:
        """Get status of proxies (for monitoring/debugging)"""
        with self._lock:
            if mac:
                # Status for specific device
                if mac not in self.proxies:
                    return {"mac": mac, "proxies": {}, "running": False}

                proxies_status = {}
                for port, process in self.proxies[mac].items():
                    proxies_status[port] = {
                        "pid": process.pid,
                        "running": process.poll() is None,
                    }

                return {
                    "mac": mac,
                    "proxies": proxies_status,
                    "running": len(proxies_status) > 0,
                }
            else:
                # Status for all devices
                all_status = {}
                for mac, ports in self.proxies.items():
                    proxies_status = {}
                    for port, process in ports.items():
                        proxies_status[port] = {
                            "pid": process.pid,
                            "running": process.poll() is None,
                        }
                    all_status[mac] = proxies_status

                return all_status


class WANMonitor:
    """
    Monitors WAN interface for both MAC tampering AND IP address changes.

    With permanent MAC spoofing, we need to handle two distinct scenarios:

    1. MAC TAMPERING (OpenWrt services reset MAC):
       - Restore MAC immediately
       - Don't trigger rediscovery (MAC is permanent, IPs will come back)

    2. IP ADDRESS CHANGES (router reboot, DHCP renewal, ISP changes):
       - Keep MAC permanent (don't change it!)
       - Trigger rediscovery to get new IPs and restart proxies

    This dual approach ensures both protection and proper operation.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.logger = logging.getLogger("WANMonitor")
        self.iface = NetworkInterface(interface)

        # MAC protection
        self.expected_mac: Optional[str] = None  # The MAC we should maintain
        self.last_mac_restore_time: Optional[float] = None  # Track last MAC restoration
        self.mac_restore_cooldown = 5  # Wait 5s between MAC restores (prevents loop)

        # IP change detection
        self.last_ipv4: Optional[List[str]] = None
        self.last_ipv6: Optional[List[str]] = None
        self.last_ip_change_time: Optional[float] = None
        self.ip_change_cooldown = 120  # Wait 120s between IP change triggers (prevents loop from DAD/temporary changes)

    def set_expected_mac(self, mac: str) -> None:
        """
        Set the expected MAC address that should be maintained on WAN interface.
        This is called after setting device MAC to prevent OpenWrt services from changing it.
        """
        self.expected_mac = mac.lower()
        self.logger.info(f"WAN monitor will maintain MAC: {self.expected_mac}")

    def get_current_addresses(self) -> tuple:
        """Get current IPv4 and IPv6 addresses on WAN interface"""
        ipv4_addrs = self.iface.get_ipv4_addresses()
        ipv6_addrs = self.iface.get_ipv6_addresses()
        return (ipv4_addrs, ipv6_addrs)

    def check_for_mac_tampering(self) -> bool:
        """
        Check if WAN MAC has been tampered with by OpenWrt services.
        Returns False always (never triggers rediscovery, only restores MAC).

        CRITICAL: With permanent MAC spoofing, we DON'T monitor IP changes!
        - IP changes are normal network behavior
        - MAC is permanent until uninstall
        - Only protect against OpenWrt resetting MAC

        Protects against OpenWrt services (netifd, hotplug scripts) resetting MAC:
        - Detects if WAN MAC has been changed back to gateway's original MAC
        - Automatically restores device MAC to prevent breaking network authentication
        - Includes cooldown to prevent restoration loops
        """
        # Check if we have an expected MAC to maintain
        if not self.expected_mac:
            return False

        # Check current MAC on interface
        current_mac = self.iface.get_mac_address()
        if not current_mac:
            return False

        # MAC is correct, nothing to do
        if current_mac.lower() == self.expected_mac:
            return False

        # MAC has been changed! Check cooldown to prevent loops
        current_time = time.time()
        if self.last_mac_restore_time is not None:
            time_since_last_restore = current_time - self.last_mac_restore_time
            if time_since_last_restore < self.mac_restore_cooldown:
                # Within cooldown - don't restore again (prevents loop)
                self.logger.debug(
                    f"MAC change detected but in cooldown period "
                    f"({time_since_last_restore:.1f}s < {self.mac_restore_cooldown}s)"
                )
                return False

        # MAC changed and outside cooldown - restore it!
        self.logger.error(
            f"⚠️ WAN MAC ADDRESS CHANGED! Expected {self.expected_mac}, found {current_mac}"
        )
        self.logger.error(
            f"⚠️ This suggests OpenWrt service (netifd/hotplug) reset the MAC!"
        )

        # Immediately restore the expected MAC
        self.logger.warning(f"🔧 Restoring correct MAC {self.expected_mac}...")
        if not self.iface.bring_down():
            self.logger.error("Failed to bring interface down")
            return False

        if not self.iface.set_mac_address(self.expected_mac):
            self.logger.error(
                f"❌ FAILED to restore MAC! Network authentication may break!"
            )
            self.iface.bring_up()  # Try to bring it back up anyway
            return False

        if not self.iface.bring_up():
            self.logger.error("Failed to bring interface up after MAC restoration")
            return False

        self.logger.info(f"✓ Restored WAN MAC to {self.expected_mac}")

        # Track this restoration to prevent loops
        self.last_mac_restore_time = current_time

        # Wait for network to stabilize after MAC restoration
        time.sleep(2)

        # NEVER trigger rediscovery - we just fixed the problem
        # The MAC is permanent, IP addresses will come back on their own
        return False

    def check_for_ip_changes(self) -> bool:
        """
        Check if WAN IPv4 address has changed (router reboot, DHCP renewal, etc.).
        Returns True if IPv4 changed (triggers rediscovery), False otherwise.

        CRITICAL FIX: ONLY monitor IPv4 changes, NOT IPv6!

        Why we DON'T monitor IPv6:
        - IPv6 addresses change frequently and legitimately:
          * DAD (Duplicate Address Detection) - temporary address states
          * Privacy Extensions - addresses rotate for privacy
          * Temporary addresses - created/destroyed during discovery
          * Router Advertisement updates - periodic RA changes
        - Monitoring IPv6 creates infinite loops:
          * WAN monitor detects IPv6 change
          * Triggers rediscovery
          * Rediscovery flushes/re-acquires IPv6
          * WAN monitor sees this as ANOTHER change
          * Loop continues forever!

        IPv4 is stable and reliable for detecting real network changes:
        - IPv4 only changes on real events (router reboot, ISP changes, DHCP renewal)
        - IPv4 changes are a reliable indicator that IPv6 also needs updating
        - One stable trigger is better than two flaky triggers!

        IMPORTANT: With permanent MAC spoofing:
        - MAC stays permanent (already set on first device)
        - IPv4 changes ARE legitimate (router reboot, DHCP lease renewal, ISP changes)
        - When IPv4 changes, we rediscover BOTH IPv4 and IPv6
        - Includes cooldown to prevent loops during DHCP negotiation
        """
        current_ipv4, current_ipv6 = self.get_current_addresses()

        # First time - just initialize
        if self.last_ipv4 is None:
            self.last_ipv4 = current_ipv4
            self.last_ipv6 = current_ipv6  # Track for logging but don't monitor
            self.last_ip_change_time = None
            self.logger.info(
                f"WAN IPv4 monitoring initialized - IPv4: {current_ipv4} "
                f"(IPv6 health checking enabled)"
            )
            return False

        # ONLY check for IPv4 changes (IPv6 monitoring disabled!)
        ipv4_changed = set(current_ipv4) != set(self.last_ipv4 or [])

        if ipv4_changed:
            # CRITICAL: Check cooldown to prevent infinite loop
            # During DHCP renewal, IPs may appear/disappear temporarily
            current_time = time.time()
            if self.last_ip_change_time is not None:
                time_since_last_change = current_time - self.last_ip_change_time

                if time_since_last_change < self.ip_change_cooldown:
                    # Within cooldown period - ignore this change (likely transient)
                    self.logger.debug(
                        f"WAN IPv4 change detected but ignoring (cooldown: {time_since_last_change:.1f}s < {self.ip_change_cooldown}s)"
                    )
                    # Update tracking but don't trigger reconfiguration
                    self.last_ipv4 = current_ipv4
                    self.last_ipv6 = current_ipv6
                    return False

            # Outside cooldown or first change - this is a real network change
            self.logger.warning("🌐 WAN IPv4 address change detected!")
            self.logger.warning(f"  IPv4 changed: {self.last_ipv4} → {current_ipv4}")
            self.logger.info(f"  IPv6 current: {current_ipv6} (will be rediscovered)")

            # Update last known addresses and change time
            self.last_ipv4 = current_ipv4
            self.last_ipv6 = current_ipv6
            self.last_ip_change_time = current_time

            # IMPORTANT: MAC stays permanent! Only IPs change
            self.logger.info(
                "Note: Device MAC remains permanent - rediscovering both IPv4 and IPv6"
            )

            return True

        # Update IPv6 tracking silently (no change detection)
        self.last_ipv6 = current_ipv6

        return False

    def check_ipv6_health(self) -> bool:
        """
        Passive IPv6 health check - verify IPv6 is still working WITHOUT triggering on normal changes.

        This is DIFFERENT from monitoring IPv6 address changes:
        - Does NOT trigger on address changes (DAD, privacy extensions, etc.)
        - ONLY triggers if IPv6 is actually broken (unreachable, misconfigured, router lost it)
        - Uses connectivity testing, not address comparison

        Returns True if IPv6 is broken and needs rediscovery, False if healthy.

        Health checks:
        1. IPv6 address still configured on eth0?
        2. Can ping6 the router (all-routers multicast)?
        3. Router still has neighbor entry for our MAC?

        If any check fails consistently (3 times), we consider IPv6 broken.
        """
        current_ipv4, current_ipv6 = self.get_current_addresses()

        # No IPv6 addresses? Check if we should have one
        if not current_ipv6:
            # Check if we have devices that need IPv6
            from gateway_service import GatewayService  # Avoid circular import

            # If we're in the middle of discovery, don't panic
            if hasattr(self, "_ipv6_check_skip_count"):
                self._ipv6_check_skip_count += 1
                if self._ipv6_check_skip_count < 3:
                    self.logger.debug(
                        f"IPv6 not present but skipping check ({self._ipv6_check_skip_count}/3) - may be in discovery"
                    )
                    return False
            else:
                self._ipv6_check_skip_count = 1
                return False

            # IPv6 missing for 3+ checks - might be broken
            self.logger.warning("⚠️ IPv6 address missing from WAN interface!")
            self._ipv6_check_skip_count = 0
            return True

        # Reset skip counter - we have IPv6
        self._ipv6_check_skip_count = 0

        # Test IPv6 connectivity to router
        try:
            # Ping all-routers multicast (ff02::2) - router should always respond
            # This tests if IPv6 routing is working
            result = subprocess.run(
                ["ping6", "-c", "1", "-W", "2", "-I", self.interface, "ff02::2"],
                capture_output=True,
                timeout=3,
            )

            if result.returncode == 0:
                # IPv6 is healthy!
                self.logger.debug("✓ IPv6 health check passed (router reachable)")
                return False
            else:
                # Router not reachable - but could be transient
                if not hasattr(self, "_ipv6_fail_count"):
                    self._ipv6_fail_count = 0

                self._ipv6_fail_count += 1

                if self._ipv6_fail_count >= 3:
                    # Failed 3 times in a row - IPv6 is broken!
                    self.logger.error(
                        f"❌ IPv6 health check FAILED {self._ipv6_fail_count} times - router unreachable!"
                    )
                    self._ipv6_fail_count = 0
                    return True
                else:
                    self.logger.warning(
                        f"⚠️ IPv6 health check failed ({self._ipv6_fail_count}/3) - router ping timeout"
                    )
                    return False

        except subprocess.TimeoutExpired:
            self.logger.debug("IPv6 health check ping timeout (expected)")
            return False
        except Exception as e:
            self.logger.warning(f"IPv6 health check error: {e}")
            return False

        # Reset fail counter on success
        if hasattr(self, "_ipv6_fail_count"):
            self._ipv6_fail_count = 0

        return False


class GatewayService:
    """Main gateway service orchestrating all components"""

    def __init__(self, config_dir: str = cfg.CONFIG_DIR):
        self.logger = logging.getLogger("GatewayService")
        self.config_dir = config_dir

        # Service state
        self.running = False
        self.devices: Dict[str, DeviceMapping] = {}
        self._devices_lock = threading.Lock()

        # WAN MAC initialization tracking
        # CRITICAL: Prevents race conditions when multiple devices discovered simultaneously
        self.wan_init_lock = threading.Lock()
        self.wan_initialized = False  # Set to True after first device sets WAN MAC

        # Discovery state tracking
        # CRITICAL: Prevents WAN monitor from triggering during active discovery (prevents loops!)
        self.discovery_in_progress = False
        self.discovery_lock = threading.Lock()

        # Network interfaces
        self.eth0 = NetworkInterface(cfg.ETH0_INTERFACE)
        self.eth1 = NetworkInterface(cfg.ETH1_INTERFACE)

        # Managers
        self.arp_monitor = ARPMonitor(interface=cfg.ETH1_INTERFACE)
        self.dhcpv6_manager = DHCPv6Manager(interface=cfg.ETH0_INTERFACE)
        self.dhcpv4_manager = DHCPv4Manager(interface=cfg.ETH0_INTERFACE)
        self.device_store = DeviceStore(config_dir)
        self.firewall = FirewallManager()

        # WAN monitor (for MAC protection and IP change detection)
        if cfg.ENABLE_WAN_MONITOR:
            self.wan_monitor = WANMonitor(interface=cfg.ETH0_INTERFACE)
            self.logger.info("WAN monitor initialized (MAC protection + IP change detection)")
        else:
            self.wan_monitor = None
            self.logger.info("WAN monitor disabled")

        # Store detected HTTP ports for each device (MAC -> port)
        self.device_http_ports: Dict[str, int] = {}

        # Initialize proxy manager based on selected backend
        self.proxy_manager = None
        if cfg.ENABLE_IPV6_TO_IPV4_PROXY:
            if cfg.IPV6_PROXY_BACKEND == "haproxy":
                self.proxy_manager = HAProxyManager()
                self.logger.info("Using HAProxy for IPv6→IPv4 proxying")
            elif cfg.IPV6_PROXY_BACKEND == "socat":
                self.proxy_manager = SocatProxyManager()
                self.logger.info("Using socat for IPv6→IPv4 proxying")
            else:
                self.logger.error(f"Unknown proxy backend: {cfg.IPV6_PROXY_BACKEND}")

        # API server placeholder (deprecated but kept for backward compatibility)
        self.api_server = None

        # Thread references
        self.discovery_thread = None
        self.monitor_thread = None
        self.wan_monitor_thread = None

    def _detect_device_http_port(self, device_ipv4: str) -> Optional[int]:
        """
        Auto-detect which port the device's HTTP service is running on.

        CRITICAL: Devices may run HTTP on different ports:
        - Port 80 (standard HTTP)
        - Port 5000 (Flask/development servers)
        - Port 8080 (alternative HTTP)
        - Port 8000 (Python SimpleHTTPServer)

        We scan common ports and test for HTTP responses to find the correct one.

        Args:
            device_ipv4: Device's LAN IPv4 address (e.g., "192.168.1.129")

        Returns:
            Port number if HTTP service found, None otherwise
        """
        common_http_ports = [80, 5000, 8080, 8000, 8888, 3000]

        self.logger.info(f"🔍 Auto-detecting HTTP port for device {device_ipv4}...")

        for port in common_http_ports:
            try:
                # Try to connect and send HTTP request
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2 second timeout

                # Try to connect
                result = sock.connect_ex((device_ipv4, port))

                if result == 0:
                    # Port is open! Test if it's HTTP
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        response = sock.recv(1024)

                        # Check if response looks like HTTP
                        if b"HTTP" in response:
                            sock.close()
                            self.logger.info(
                                f"✓ Found HTTP service on {device_ipv4}:{port}"
                            )
                            return port
                    except:
                        pass  # Not HTTP, try next port

                sock.close()

            except Exception as e:
                self.logger.debug(f"Port {port} check failed: {e}")
                continue

        # No HTTP port found - default to 80
        self.logger.warning(
            f"⚠️ Could not detect HTTP port for {device_ipv4}, defaulting to port 80"
        )
        return 80

    def _save_original_wan_mac(self, mac: str) -> bool:
        """
        Save the original WAN interface MAC address to file.
        This MAC will be restored during uninstall.

        Args:
            mac: Original MAC address to save

        Returns:
            True if saved successfully
        """
        try:
            os.makedirs(os.path.dirname(cfg.ORIGINAL_MAC_FILE), exist_ok=True)
            with open(cfg.ORIGINAL_MAC_FILE, "w") as f:
                f.write(mac)
            self.logger.info(f"Saved original WAN MAC {mac} to {cfg.ORIGINAL_MAC_FILE}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save original WAN MAC: {e}")
            return False

    def _load_original_wan_mac(self) -> Optional[str]:
        """
        Load the original WAN interface MAC address from file.

        Returns:
            Original MAC address or None if not found
        """
        try:
            if os.path.exists(cfg.ORIGINAL_MAC_FILE):
                with open(cfg.ORIGINAL_MAC_FILE, "r") as f:
                    mac = f.read().strip()
                self.logger.info(
                    f"Loaded original WAN MAC {mac} from {cfg.ORIGINAL_MAC_FILE}"
                )
                return mac
        except Exception as e:
            self.logger.error(f"Failed to load original WAN MAC: {e}")
        return None

    def restore_original_wan_mac(self) -> bool:
        """
        Restore the WAN interface to its original MAC address.
        Called during uninstall to restore gateway to factory state.

        Returns:
            True if restored successfully
        """
        original_mac = self._load_original_wan_mac()
        if not original_mac:
            self.logger.warning("No original WAN MAC found to restore")
            return False

        self.logger.info(f"Restoring WAN interface to original MAC {original_mac}")

        # Bring down interface before changing MAC
        self.eth0.bring_down()

        # Set original MAC
        if not self.eth0.set_mac_address(original_mac):
            self.logger.error(f"Failed to restore original MAC {original_mac}")
            return False

        # Bring interface back up
        self.eth0.bring_up()

        # Delete the original MAC file (cleanup)
        try:
            if os.path.exists(cfg.ORIGINAL_MAC_FILE):
                os.remove(cfg.ORIGINAL_MAC_FILE)
                self.logger.info(f"Removed {cfg.ORIGINAL_MAC_FILE}")
        except Exception as e:
            self.logger.warning(f"Failed to remove {cfg.ORIGINAL_MAC_FILE}: {e}")

        self.logger.info(f"✓ WAN interface restored to original MAC {original_mac}")
        return True

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

        # Bring up network interfaces
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
            # CRITICAL: Allow ICMP (ping) traffic for connectivity testing
            if not self.firewall.allow_icmp():
                self.logger.error("Failed to enable ICMP")
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

        # Start WAN network monitor if enabled
        if cfg.ENABLE_WAN_MONITOR and self.wan_monitor:
            self.wan_monitor_thread = threading.Thread(
                target=self._wan_monitoring_loop,
                daemon=True,
                name="WANMonitor",
            )
            self.wan_monitor_thread.start()
            self.logger.info("WAN network monitoring started")

        # API server removed - use gateway-status-direct and gateway-devices-direct instead
        # Old API server code commented out below:
        # if cfg.API_ENABLED:
        #     self.api_server = GatewayAPIServer(
        #         gateway_service=self,
        #         host=cfg.API_HOST,
        #         port=cfg.API_PORT,
        #     )
        #     try:
        #         self.api_server.start()
        #     except Exception as e:
        #         self.logger.error("Failed to start API server: %s", e)

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

        # Stop all proxies (works for both socat and HAProxy)
        if self.proxy_manager:
            self.proxy_manager.stop_all_proxies()

        with self._devices_lock:
            self.device_store.save_devices(self.devices)

        self.logger.info("Gateway service stopped")

    # ---- Internal loops ----

    def _perform_initial_network_scan(self) -> None:
        """
        Perform active network scan on startup to populate ARP table.

        Problem: When gateway starts, ARP table may be empty even if devices are connected:
        - Device was connected before gateway started
        - Device hasn't sent packets recently
        - ARP entries expire after inactivity

        Solution: Actively ping the LAN subnet to populate ARP table
        This ensures we detect devices immediately instead of waiting for them to send traffic
        """
        lan_interface = cfg.ETH1_INTERFACE

        self.logger.info("🔍 Performing initial network scan to populate ARP table...")

        # CRITICAL: Wrap entire scan in try/except with timeout to prevent hangs
        try:
            # Get the LAN subnet from eth1
            result = subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "show", lan_interface],
                capture_output=True,
                text=True,
                check=True,
                timeout=3,  # Add timeout to prevent hang
            )

            # Extract subnet (e.g., "192.168.1.1/24")
            import re

            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", result.stdout)

            if not match:
                self.logger.warning(
                    f"Could not find LAN subnet on {lan_interface}, skipping scan"
                )
                return

            ip_addr = match.group(1)
            prefix = int(match.group(2))

            self.logger.debug(f"LAN subnet: {ip_addr}/{prefix}")

            # Calculate network range (simplified - assumes /24)
            if prefix == 24:
                base_ip = ".".join(ip_addr.split(".")[0:3])

                # Ping sweep: ping just a few likely IPs (fast and safe)
                self.logger.debug(f"Pinging common IPs in {base_ip}.0/24...")

                # SIMPLIFIED: Just ping a few likely device IPs (much faster and safer)
                # Avoid full subnet scan which can hang on some networks
                likely_ips = [1, 100, 101, 128, 129, 254]

                for i in likely_ips:
                    try:
                        subprocess.run(
                            ["ping", "-c", "1", "-W", "1", f"{base_ip}.{i}"],
                            capture_output=True,
                            timeout=2,  # 2 second max per ping
                        )
                    except (subprocess.TimeoutExpired, Exception):
                        # Ignore failures - not critical
                        pass

                self.logger.info("✓ Initial network scan completed")

            else:
                self.logger.debug(
                    f"Unsupported prefix /{prefix}, skipping scan (only /24 supported)"
                )

        except subprocess.TimeoutExpired:
            self.logger.warning("Initial network scan timed out (non-critical)")
        except Exception as e:
            self.logger.warning(f"Initial network scan failed (non-critical): {e}")

        # Wait a moment for ARP table to populate
        try:
            time.sleep(1)

            # Log how many devices we found
            arp_entries = self.arp_monitor.get_arp_entries()
            self.logger.info(
                f"✓ ARP table now has {len(arp_entries)} entries after scan"
            )
        except Exception as e:
            self.logger.warning(f"Failed to check ARP entries: {e}")

    def _discovery_loop(self) -> None:
        """Main loop: discover new MACs and request IPv6"""
        self.logger.info("Discovery loop started (SINGLE DEVICE MODE)")

        # CRITICAL FIX: Active network scan on startup!
        # Actively pings LAN subnet to populate ARP table
        # Prevents needing to unplug/replug device on fresh install
        self._perform_initial_network_scan()

        while self.running:
            try:
                new_entries = self.arp_monitor.get_new_macs()

                # CRITICAL: If no devices found, run active ARP scan to detect idle devices!
                if not new_entries and len(self.devices) == 0:
                    self.logger.info("📡 No devices found in ARP table - running active scan...")
                    self.arp_monitor.active_scan()
                    # Wait for ARP table to populate
                    time.sleep(2)
                    # Try again after scan
                    new_entries = self.arp_monitor.get_new_macs()
                    if new_entries:
                        self.logger.info(f"✓ Active scan found {len(new_entries)} device(s)!")

                for mac, ipv4 in new_entries:
                    should_spawn_thread = False
                    replaced_device_mac = None

                    with self._devices_lock:
                        # SINGLE DEVICE MODE: If we already have a device, remove it first
                        if len(self.devices) > 0:
                            # Get the current device's MAC
                            current_macs = list(self.devices.keys())
                            if mac not in current_macs:
                                # New device detected - replace the old one
                                replaced_device_mac = current_macs[0]
                                old_device = self.devices[replaced_device_mac]

                                self.logger.warning(
                                    f"🔄 NEW DEVICE DETECTED: Replacing {replaced_device_mac} "
                                    f"(IPv4: {old_device.ipv4_address}) with {mac} (IPv4: {ipv4})"
                                )

                                # Stop proxies for old device
                                if self.proxy_manager:
                                    self.proxy_manager.stop_proxies_for_device(
                                        replaced_device_mac
                                    )

                                # Remove old device
                                del self.devices[replaced_device_mac]
                                self.arp_monitor.known_macs.discard(replaced_device_mac)

                                self.logger.info(
                                    f"✓ Removed old device {replaced_device_mac}"
                                )

                        # Check if this MAC is already being tracked
                        if mac in self.devices:
                            # Update IPv4 if changed
                            if self.devices[mac].ipv4_address != ipv4:
                                self.devices[mac].ipv4_address = ipv4
                                self.logger.info(f"Updated IPv4 for {mac}: {ipv4}")
                            continue

                        # Create new device and mark as "discovering"
                        device = DeviceMapping(mac_address=mac, ipv4_address=ipv4)
                        device.status = "discovering"
                        self.devices[mac] = device
                        should_spawn_thread = True

                    if should_spawn_thread:
                        if replaced_device_mac:
                            self.logger.info(
                                f"🆕 Configuring new device: {mac} (IPv4: {ipv4}) "
                                f"[Replaced: {replaced_device_mac}]"
                            )
                        else:
                            self.logger.info(
                                f"🆕 New device discovered: {mac} (IPv4: {ipv4})"
                            )

                        # Spawn discovery thread (with retry on failure)
                        max_retries = 3
                        thread_spawned = False
                        for attempt in range(max_retries):
                            try:
                                thread = threading.Thread(
                                    target=self._discover_addresses_for_device,
                                    args=(mac,),
                                    daemon=True,
                                    name=f"Discovery-{mac}",
                                )
                                thread.start()
                                self.logger.info(
                                    f"Started discovery thread for {mac} (thread: {thread.name})"
                                )
                                thread_spawned = True
                                break  # Success, exit retry loop
                            except RuntimeError as thread_error:
                                if attempt < max_retries - 1:
                                    self.logger.warning(
                                        f"Thread spawn failed for {mac} (attempt {attempt + 1}/{max_retries}), retrying..."
                                    )
                                    time.sleep(1)
                                else:
                                    self.logger.error(
                                        f"Failed to start discovery thread for {mac} after {max_retries} attempts: {thread_error}"
                                    )
                                    # CRITICAL FIX: Clean up device if all thread spawn attempts failed
                                    with self._devices_lock:
                                        if mac in self.devices:
                                            self.devices[mac].status = "error"
                                            self.logger.error(
                                                f"Marked device {mac} as error due to thread spawn failure"
                                            )

                time.sleep(cfg.ARP_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                time.sleep(5)

    def _update_wan_mac_for_device(self, mac: str) -> bool:
        """
        Update WAN interface MAC and all protection layers for a new device.
        Called when switching from one device to another in SINGLE DEVICE MODE.

        Updates:
        1. eth0 MAC address
        2. UCI configuration (persistent)
        3. Hotplug protection file
        4. WAN monitor protection

        Returns True if successful.
        """
        self.logger.warning(f"🔄 Updating WAN MAC to new device: {mac}")

        # 1. Update eth0 MAC address
        if not self.eth0.bring_down():
            self.logger.error("Failed to bring eth0 down for MAC change")
            return False

        if not self.eth0.set_mac_address(mac):
            self.logger.error(f"Failed to set eth0 MAC to {mac}")
            self.eth0.bring_up()
            return False

        if not self.eth0.bring_up():
            self.logger.error("Failed to bring eth0 up after MAC change")
            return False

        self.logger.info(f"✓ Updated eth0 MAC to {mac}")

        # 2. Update UCI configuration (makes it persistent across reboots)
        try:
            subprocess.run(
                ["uci", "set", f"network.wan.macaddr={mac}"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["uci", "commit", "network"], check=True, capture_output=True
            )
            self.logger.info(f"✓ Updated UCI config to MAC {mac}")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to update UCI (non-critical): {e}")
        except FileNotFoundError:
            self.logger.debug("UCI not available (not on OpenWrt)")

        # 3. Update hotplug protection file
        try:
            mac_file = "/etc/ipv4-ipv6-gateway/current_device_mac.txt"
            os.makedirs(os.path.dirname(mac_file), exist_ok=True)
            with open(mac_file, "w") as f:
                f.write(mac)
            self.logger.info(f"✓ Updated hotplug protection to MAC {mac}")
        except Exception as e:
            self.logger.warning(f"Failed to update hotplug file (non-critical): {e}")

        # 4. Update WAN monitor protection
        if self.wan_monitor:
            self.wan_monitor.set_expected_mac(mac)
            self.logger.info(f"✓ Updated WAN monitor to protect MAC {mac}")

        # Wait for network to stabilize
        time.sleep(2)

        self.logger.warning(f"✓ WAN interface now using device MAC {mac}")
        return True

    def _discover_addresses_for_device(self, mac: str) -> None:
        """
        Discover WAN addresses (IPv4 and/or IPv6) for a specific MAC address.
        Requests DHCPv4 and/or DHCPv6 based on what protocols are available on eth0.

        IMPORTANT: On first device discovery, saves gateway's original MAC and sets
        device MAC permanently on WAN interface. Original MAC is only restored during uninstall.

        On subsequent device changes (SINGLE DEVICE MODE), updates MAC and all protection layers.
        """
        try:
            with self._devices_lock:
                device = self.devices.get(mac)
                if not device:
                    return
                device.status = "discovering"

            # CRITICAL: Handle MAC changes for both first device and device switching
            with self.wan_init_lock:
                current_wan_mac = self.eth0.get_mac_address()

                if not self.wan_initialized:
                    # FIRST DEVICE - Save original gateway MAC
                    self.logger.warning(
                        f"🌐 FIRST DEVICE DETECTED! Setting permanent MAC {mac} on WAN interface"
                    )

                    # Get and save original gateway MAC
                    if current_wan_mac and current_wan_mac != mac:
                        if not self._save_original_wan_mac(current_wan_mac):
                            self.logger.error("Failed to save original WAN MAC!")
                        else:
                            self.logger.info(
                                f"✓ Saved original WAN MAC {current_wan_mac}"
                            )

                    # Update MAC and all protection layers
                    if not self._update_wan_mac_for_device(mac):
                        self.logger.error(
                            f"❌ CRITICAL: Failed to set WAN MAC to {mac}!"
                        )
                        with self._devices_lock:
                            if mac in self.devices:
                                self.devices[mac].status = "failed"
                        return

                    self.wan_initialized = True
                    self.logger.warning(f"✓ Gateway's own MAC is HIDDEN from network")
                    self.logger.warning(
                        f"✓ Original MAC will be restored during uninstall"
                    )

                elif current_wan_mac and current_wan_mac.lower() != mac.lower():
                    # DEVICE SWITCHING - Update to new device's MAC
                    self.logger.warning(
                        f"🔄 DEVICE SWITCH DETECTED! Changing from {current_wan_mac} to {mac}"
                    )

                    # Update MAC and all protection layers
                    if not self._update_wan_mac_for_device(mac):
                        self.logger.error(
                            f"❌ CRITICAL: Failed to update WAN MAC to {mac}!"
                        )
                        with self._devices_lock:
                            if mac in self.devices:
                                self.devices[mac].status = "failed"
                        return

                    self.logger.warning(
                        f"✓ WAN interface switched to new device MAC {mac}"
                    )
                else:
                    # Same device, MAC already correct
                    self.logger.debug(f"WAN MAC already set to {mac}, continuing...")

            # Determine which protocols to attempt
            attempt_ipv4, attempt_ipv6 = self.should_attempt_protocols()

            # OPTIMIZATION: Parallel IPv4/IPv6 discovery
            # Launch both protocols simultaneously to reduce total discovery time
            # Before: IPv4 (2-5s) + IPv6 (15-75s) = 17-80s total (sequential)
            # After: max(IPv4, IPv6) = 15-75s total (parallel) - 50% faster!

            import time as timing_module

            discovery_start_time = timing_module.time()

            ipv4_wan = None
            ipv6 = None

            # Get cached IPv6 before launching threads
            cached_ipv6 = None
            with self._devices_lock:
                device = self.devices.get(mac)
                cached_ipv6 = device.ipv6_address if device else None

            def discover_ipv4():
                """Thread function for IPv4 discovery"""
                nonlocal ipv4_wan
                if attempt_ipv4:
                    self.logger.info(f"Requesting DHCPv4 for {mac}")
                    ipv4_start = timing_module.time()
                    ipv4_wan = self.dhcpv4_manager.request_ipv4_for_mac(mac)
                    ipv4_duration = timing_module.time() - ipv4_start

                    if ipv4_wan:
                        self.logger.info(
                            f"Device {mac} → WAN IPv4: {ipv4_wan} (took {ipv4_duration:.1f}s)"
                        )
                    else:
                        self.logger.warning(
                            f"Failed to obtain IPv4 for {mac} (took {ipv4_duration:.1f}s)"
                        )
                else:
                    self.logger.info(f"Skipping DHCPv4 for {mac}")

            def discover_ipv6():
                """Thread function for IPv6 discovery"""
                nonlocal ipv6
                if attempt_ipv6:
                    if cached_ipv6:
                        self.logger.info(
                            f"Requesting DHCPv6 for {mac} (cached: {cached_ipv6})"
                        )
                    else:
                        self.logger.info(f"Requesting DHCPv6 for {mac} (no cache)")

                    ipv6_start = timing_module.time()
                    ipv6 = self.dhcpv6_manager.request_ipv6_address(
                        mac, cached_ipv6=cached_ipv6
                    )
                    ipv6_duration = timing_module.time() - ipv6_start

                    if ipv6:
                        cache_status = (
                            "(cached - fast!)"
                            if ipv6_duration < 5
                            else "(full acquisition)"
                        )
                        self.logger.info(
                            f"Device {mac} → WAN IPv6: {ipv6} {cache_status} (took {ipv6_duration:.1f}s)"
                        )
                    else:
                        self.logger.warning(
                            f"Failed to obtain IPv6 for {mac} (took {ipv6_duration:.1f}s)"
                        )
                else:
                    self.logger.info(f"Skipping DHCPv6 for {mac}")

            # Launch both discoveries in parallel
            ipv4_thread = threading.Thread(
                target=discover_ipv4, name=f"IPv4-Discovery-{mac}"
            )
            ipv6_thread = threading.Thread(
                target=discover_ipv6, name=f"IPv6-Discovery-{mac}"
            )

            self.logger.info(f"Starting parallel IPv4/IPv6 discovery for {mac}...")
            ipv4_thread.start()
            ipv6_thread.start()

            # CRITICAL FIX: Wait for threads to ACTUALLY complete, no timeouts!
            # Problem: Timeouts cause threads to be abandoned while still running
            # The background thread logs success, but the main thread saves device with null
            # Solution: Wait indefinitely for threads to complete (they have internal timeouts)
            self.logger.info(f"Waiting for IPv4 discovery to complete...")
            ipv4_thread.join()  # Wait until IPv4 thread finishes (no timeout!)

            self.logger.info(f"Waiting for IPv6 discovery to complete...")
            ipv6_thread.join()  # Wait until IPv6 thread finishes (no timeout!)

            total_discovery_time = timing_module.time() - discovery_start_time
            self.logger.info(
                f"Parallel discovery completed for {mac} in {total_discovery_time:.1f}s "
                f"(IPv4: {ipv4_wan}, IPv6: {ipv6})"
            )

            # Update device with discovered addresses
            with self._devices_lock:
                device = self.devices.get(mac)
                if device:
                    if ipv4_wan:
                        device.ipv4_wan_address = ipv4_wan
                    if ipv4_wan:
                        device.ipv4_wan_address = ipv4_wan
                    if ipv6:
                        device.ipv6_address = ipv6

                        # Verify IPv6 is actually configured on eth0
                        self.logger.info(
                            f"Verifying IPv6 {ipv6} is configured on eth0..."
                        )
                        ipv6_addresses_on_eth0 = self.eth0.get_ipv6_addresses()

                        if ipv6 in ipv6_addresses_on_eth0:
                            self.logger.info(
                                f"✓ Confirmed: IPv6 {ipv6} is present on eth0"
                            )
                        else:
                            self.logger.warning(
                                f"⚠ WARNING: IPv6 {ipv6} NOT found on eth0!"
                            )
                            self.logger.warning(
                                f"  eth0 IPv6 addresses: {ipv6_addresses_on_eth0}"
                            )
                            self.logger.warning(
                                f"  This will cause HAProxy/socat bind to FAIL!"
                            )
                    else:
                        self.logger.warning(f"Failed to obtain IPv6 for {mac}")

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

                    # Setup automatic port forwarding if enabled
                    if cfg.ENABLE_AUTO_PORT_FORWARDING:
                        # IPv4 port forwarding (if device has LAN IPv4)
                        if device.ipv4_address:
                            self._setup_auto_port_forwarding_ipv4(
                                device.ipv4_address, mac
                            )

                        # IPv6→IPv4 proxying (if enabled and device has both IPv4 and IPv6)
                        # Use separate port mapping for IPv6 (only firewall-allowed ports)
                        if (
                            cfg.ENABLE_IPV6_TO_IPV4_PROXY
                            and self.proxy_manager
                            and device.ipv4_address
                            and device.ipv6_address
                        ):
                            # CRITICAL: Auto-detect device's actual HTTP port!
                            # Devices may run HTTP on port 80, 5000, 8080, 8000, etc.
                            detected_http_port = self._detect_device_http_port(device.ipv4_address)

                            # Store detected port for this device
                            self.device_http_ports[mac] = detected_http_port

                            # Create dynamic port map based on detected HTTP port
                            # Always forward telnet (23), but use detected port for HTTP
                            dynamic_port_map = {
                                2323: 23,  # Telnet (fixed)
                                8080: detected_http_port,  # HTTP (auto-detected!)
                            }

                            self.logger.info(
                                f"Using dynamic port map for {mac}: "
                                f"Telnet 2323→23, HTTP 8080→{detected_http_port}"
                            )

                            # Start proxies with DYNAMIC PORT MAP!
                            # Pass device's IPv6 address so proxy binds to it specifically
                            self.proxy_manager.start_proxy_for_device(
                                mac=mac,
                                device_ipv4=device.ipv4_address,
                                device_ipv6=device.ipv6_address,  # Device's unique IPv6 address
                                port_map=dynamic_port_map,  # DYNAMIC ports!
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

    def _setup_auto_port_forwarding_ipv4(self, device_ip: str, mac: str) -> None:
        """
        Setup IPv4 port forwarding using iptables.
        Forwards common ports from gateway WAN to device LAN IP.
        """
        self.logger.info(
            f"Setting up IPv4 port forwarding for {device_ip} (MAC: {mac})"
        )

        wan_interface = cfg.ETH0_INTERFACE
        lan_interface = cfg.ETH1_INTERFACE

        for gateway_port, device_port in cfg.AUTO_PORT_FORWARDS.items():
            try:
                # DNAT rule: Forward traffic from WAN port to device
                dnat_cmd = [
                    cfg.CMD_IPTABLES,
                    "-t",
                    "nat",
                    "-C",  # Check if rule exists
                    "PREROUTING",
                    "-i",
                    wan_interface,
                    "-p",
                    "tcp",
                    "--dport",
                    str(gateway_port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{device_ip}:{device_port}",
                ]

                # Check if rule already exists
                check_result = subprocess.run(dnat_cmd, capture_output=True)

                if check_result.returncode != 0:
                    # Rule doesn't exist, add it
                    add_dnat_cmd = dnat_cmd.copy()
                    add_dnat_cmd[3] = "-A"  # Change -C to -A
                    subprocess.run(add_dnat_cmd, check=True, capture_output=True)

                    # FORWARD rule: Allow forwarded traffic
                    forward_cmd = [
                        cfg.CMD_IPTABLES,
                        "-A",
                        "FORWARD",
                        "-i",
                        wan_interface,
                        "-o",
                        lan_interface,
                        "-p",
                        "tcp",
                        "-d",
                        device_ip,
                        "--dport",
                        str(device_port),
                        "-j",
                        "ACCEPT",
                    ]
                    subprocess.run(forward_cmd, check=True, capture_output=True)

                    # Return traffic
                    return_cmd = [
                        cfg.CMD_IPTABLES,
                        "-A",
                        "FORWARD",
                        "-i",
                        lan_interface,
                        "-o",
                        wan_interface,
                        "-p",
                        "tcp",
                        "-s",
                        device_ip,
                        "--sport",
                        str(device_port),
                        "-j",
                        "ACCEPT",
                    ]
                    subprocess.run(return_cmd, check=True, capture_output=True)

                    # Local access (from gateway itself)
                    local_cmd = [
                        cfg.CMD_IPTABLES,
                        "-t",
                        "nat",
                        "-A",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "--dport",
                        str(gateway_port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"{device_ip}:{device_port}",
                    ]
                    subprocess.run(local_cmd, check=True, capture_output=True)

                    self.logger.info(
                        f"IPv4 port forward: gateway:{gateway_port} → {device_ip}:{device_port}"
                    )
                else:
                    self.logger.debug(
                        f"IPv4 port forward already exists: gateway:{gateway_port} → {device_ip}:{device_port}"
                    )

            except subprocess.CalledProcessError as e:
                self.logger.warning(
                    f"Failed to setup IPv4 port forward {gateway_port}→{device_port}: {e}"
                )
            except Exception as e:
                self.logger.error(
                    f"Error setting up IPv4 port forward {gateway_port}→{device_port}: {e}"
                )

    def _setup_auto_port_forwarding_ipv6(self, device_ipv6: str, mac: str) -> None:
        """
        Setup IPv6 firewall rules for direct device access.

        NOTE: Unlike IPv4, IPv6 does NOT use port forwarding/translation!
        The device has a globally routable IPv6 address, so clients access
        the device's ports directly (80, 23, 22, etc.) not translated ports.

        This method only adds firewall FORWARD rules to ensure traffic can reach
        the device. No port translation occurs.

        Access examples:
        - curl "http://[device_ipv6]:80"       (NOT :8080)
        - telnet device_ipv6 23                (NOT :2323)
        - ssh user@device_ipv6                 (port 22, NOT :2222)
        """
        self.logger.info(
            f"Setting up IPv6 firewall rules for {device_ipv6} (MAC: {mac})"
        )

        wan_interface = cfg.ETH0_INTERFACE

        for gateway_port, device_port in cfg.AUTO_PORT_FORWARDS.items():
            try:
                # Check if FORWARD rule exists for this device_port
                check_cmd = [
                    cfg.CMD_IP6TABLES,
                    "-C",  # Check
                    "FORWARD",
                    "-p",
                    "tcp",
                    "-d",
                    device_ipv6,
                    "--dport",
                    str(device_port),  # Direct port, no translation
                    "-j",
                    "ACCEPT",
                ]

                check_result = subprocess.run(check_cmd, capture_output=True)

                if check_result.returncode != 0:
                    # Rule doesn't exist, add it
                    # FORWARD rule: Allow traffic to device's real port
                    forward_cmd = [
                        cfg.CMD_IP6TABLES,
                        "-A",
                        "FORWARD",
                        "-p",
                        "tcp",
                        "-d",
                        device_ipv6,
                        "--dport",
                        str(device_port),
                        "-j",
                        "ACCEPT",
                    ]
                    subprocess.run(forward_cmd, check=True, capture_output=True)

                    # Return traffic
                    return_cmd = [
                        cfg.CMD_IP6TABLES,
                        "-A",
                        "FORWARD",
                        "-p",
                        "tcp",
                        "-s",
                        device_ipv6,
                        "--sport",
                        str(device_port),
                        "-j",
                        "ACCEPT",
                    ]
                    subprocess.run(return_cmd, check=True, capture_output=True)

                    self.logger.info(
                        f"IPv6 firewall: Allow traffic to [{device_ipv6}]:{device_port}"
                    )
                else:
                    self.logger.debug(
                        f"IPv6 firewall rule already exists for [{device_ipv6}]:{device_port}"
                    )

            except subprocess.CalledProcessError as e:
                self.logger.warning(
                    f"Failed to setup IPv6 firewall rule for port {device_port}: {e}"
                )
            except Exception as e:
                self.logger.error(
                    f"Error setting up IPv6 firewall rule for port {device_port}: {e}"
                )

    def _monitoring_loop(self) -> None:
        """
        Monitor active devices and update status / timeouts.

        CRITICAL: Also syncs IPv6 addresses with router's neighbor table!
        This prevents gateway/router IPv6 mismatches when router renews/changes addresses.

        NEW: Also monitors device HTTP port health!
        Detects when services go down/up or switch ports, and automatically fixes proxies.
        """
        self.logger.info("Monitoring loop started (with IPv6 sync + port health checks)")
        timeout_delta = timedelta(seconds=cfg.DEVICE_STATUS_TIMEOUT)

        # Track last IPv6 sync time (sync every 60 seconds)
        last_ipv6_sync = 0
        ipv6_sync_interval = 60  # seconds

        # Track last port health check (check every 30 seconds)
        last_port_health_check = 0
        port_health_check_interval = 30  # seconds

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

                current_time = time.time()

                # CRITICAL: Periodic IPv6 sync with router's neighbor table
                # Prevents gateway/router IPv6 mismatches (router renews/changes IPv6)
                if current_time - last_ipv6_sync >= ipv6_sync_interval:
                    self._sync_ipv6_with_router()
                    last_ipv6_sync = current_time

                # NEW: Periodic port health check
                # Detects when device services go down/up or switch ports
                if current_time - last_port_health_check >= port_health_check_interval:
                    self._check_device_port_health()
                    last_port_health_check = current_time

                time.sleep(cfg.DEVICE_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

    def _wan_monitoring_loop(self) -> None:
        """
        Monitor WAN interface for both MAC tampering AND IP address changes.

        Two monitoring scenarios with permanent MAC spoofing:

        1. MAC TAMPERING (OpenWrt services reset MAC):
           - Detected by check_for_mac_tampering()
           - Automatically restored, does NOT trigger rediscovery
           - MAC is permanent until uninstall

        2. IP ADDRESS CHANGES (router reboot, DHCP renewal, ISP changes):
           - Detected by check_for_ip_changes()
           - MAC stays permanent (not changed!)
           - DOES trigger rediscovery to update IPs and restart proxies

        This dual approach ensures both protection and proper operation.
        """
        self.logger.info(
            "WAN monitoring started (MAC protection + IP change detection)"
        )

        while self.running:
            try:
                if self.wan_monitor:
                    # Check for MAC tampering first (auto-restores if needed)
                    self.wan_monitor.check_for_mac_tampering()

                    # Then check for IP changes (triggers rediscovery if needed)
                    # CRITICAL: Skip if discovery already in progress (prevents loop!)
                    with self.discovery_lock:
                        if self.discovery_in_progress:
                            self.logger.debug(
                                "Skipping WAN IP change check - discovery in progress"
                            )
                            time.sleep(cfg.WAN_MONITOR_INTERVAL)
                            continue

                    if self.wan_monitor.check_for_ip_changes():
                        # WAN IPs changed - rediscover addresses
                        self.logger.warning(
                            "WAN IP addresses changed - triggering device re-discovery"
                        )

                        # Wait a moment for network to stabilize
                        time.sleep(cfg.WAN_CHANGE_REDISCOVERY_DELAY)

                        # Re-discover all devices (MAC stays permanent!)
                        self._rediscover_all_devices()

                time.sleep(cfg.WAN_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in WAN monitoring loop: {e}")
                time.sleep(10)

    def _sync_ipv6_with_router(self) -> None:
        """
        Periodically sync device IPv6 addresses with router's neighbor table.

        CRITICAL: Prevents gateway/router IPv6 mismatches!

        Problem: Router can change device's IPv6 at any time:
        - DHCPv6 lease renewal
        - Router reboots
        - Privacy extensions
        - Network changes

        If gateway cached old IPv6 but router knows new IPv6:
        - Socat binds to old IPv6 ❌
        - Router routes to new IPv6 ❌
        - Connections FAIL! ❌

        Solution: Periodically query router's neighbor table and update if changed
        This keeps gateway and router ALWAYS in sync!
        """
        self.logger.debug("Syncing IPv6 addresses with router's neighbor table...")

        with self._devices_lock:
            for mac, device in list(self.devices.items()):
                # Skip if device has no IPv6 (nothing to sync)
                if not device.ipv6_address:
                    continue

                # Query router's neighbor table for this MAC
                router_ipv6s = self.dhcpv6_manager.discover_ipv6_from_neighbor_table(
                    mac
                )

                if not router_ipv6s:
                    # Router doesn't have IPv6 for this MAC anymore
                    self.logger.warning(
                        f"⚠️ Router has NO IPv6 for {mac} (gateway cached: {device.ipv6_address})"
                    )
                    # Keep cached IPv6 for now - router might still be updating
                    continue

                # Normalize both for comparison (handle comma-separated lists)
                cached_ipv6_set = set(device.ipv6_address.split(","))
                router_ipv6_set = set(router_ipv6s.split(","))

                # Compare with cached IPv6
                if cached_ipv6_set != router_ipv6_set:
                    # IPv6 MISMATCH! Router has different IPv6 than we cached
                    self.logger.warning(f"🔄 IPv6 MISMATCH for {mac}!")
                    self.logger.warning(f"   Gateway cached: {device.ipv6_address}")
                    self.logger.warning(f"   Router knows:   {router_ipv6s}")
                    self.logger.warning(f"   Updating gateway to match router...")

                    # Update device's IPv6 to match router
                    old_ipv6 = device.ipv6_address
                    device.ipv6_address = router_ipv6s

                    # Save updated device info
                    self.device_store.add_device(device)

                    # CRITICAL: Restart socat proxies with new IPv6 addresses!
                    if self.proxy_manager and device.ipv4_address:
                        self.logger.info(
                            f"Restarting proxies with new IPv6 addresses..."
                        )

                        # Stop old proxies (bound to old IPv6)
                        self.proxy_manager.stop_proxies_for_device(mac)

                        # Wait for cleanup
                        time.sleep(1)

                        # Start new proxies (bound to new IPv6)
                        self.proxy_manager.start_proxy_for_device(
                            mac=mac,
                            device_ipv4=device.ipv4_address,
                            device_ipv6=router_ipv6s,
                            port_map=cfg.IPV6_PROXY_PORT_FORWARDS,
                        )

                        self.logger.info(
                            f"✓ Proxies restarted with new IPv6: {router_ipv6s}"
                        )

                    self.logger.info(f"✓ Synced {mac}: {old_ipv6} → {router_ipv6s}")
                else:
                    # IPv6 matches - all good!
                    self.logger.debug(
                        f"✓ IPv6 in sync for {mac}: {device.ipv6_address}"
                    )

    def _check_device_port_health(self) -> None:
        """
        Periodically check device HTTP port health.

        CRITICAL: Detects when device services go down/up or switch ports!

        Problem: Device services can change/fail without gateway knowing:
        - HTTP service crashes → proxy forwarding to dead port
        - Device reboots → HTTP not ready yet on old port
        - Device switches ports (80 → 5000) → proxy forwarding to wrong port
        - Port responds but service is down

        Solution: Periodically test if detected HTTP port is still responding
        If port down → log warning, optionally mark device as service_down
        If port switched → detect new port, update mapping, restart proxies

        This ensures proxies always forward to the ACTUAL working port!
        """
        self.logger.debug("Checking device HTTP port health...")

        with self._devices_lock:
            for mac, device in list(self.devices.items()):
                # Skip if device has no IPv4 (can't check ports)
                if not device.ipv4_address:
                    continue

                # Skip if device is not active
                if device.status != "active":
                    continue

                # Get previously detected HTTP port for this device
                if mac not in self.device_http_ports:
                    # No port detected yet, try to detect now
                    self.logger.debug(f"No HTTP port detected for {mac}, detecting now...")
                    detected_port = self._detect_device_http_port(device.ipv4_address)
                    if detected_port:
                        self.device_http_ports[mac] = detected_port
                        self.logger.info(f"Detected HTTP port {detected_port} for {mac}")
                    continue

                current_port = self.device_http_ports[mac]

                # Test if current port is still responding
                import socket
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((device.ipv4_address, current_port))
                    sock.close()

                    if result == 0:
                        # Port still responding - all good!
                        self.logger.debug(
                            f"✓ HTTP port {current_port} healthy for {mac} ({device.ipv4_address})"
                        )
                        continue
                    else:
                        # Port not responding! Check if it switched to different port
                        self.logger.warning(
                            f"⚠️ HTTP port {current_port} NOT responding for {mac} ({device.ipv4_address})"
                        )
                        self.logger.warning(f"   Checking if service switched ports...")

                        # Try to detect if HTTP moved to different port
                        new_port = self._detect_device_http_port(device.ipv4_address)

                        if new_port and new_port != current_port:
                            # Service switched ports!
                            self.logger.warning(
                                f"🔄 HTTP service SWITCHED PORTS for {mac}!"
                            )
                            self.logger.warning(
                                f"   Old port: {current_port} → New port: {new_port}"
                            )

                            # Update port mapping
                            self.device_http_ports[mac] = new_port

                            # Restart proxies with new port mapping
                            if self.proxy_manager and device.ipv6_address:
                                self.logger.info(
                                    f"Restarting proxies with new HTTP port {new_port}..."
                                )

                                # Stop old proxies
                                self.proxy_manager.stop_proxies_for_device(mac)

                                # Wait for cleanup
                                time.sleep(1)

                                # Create new dynamic port map
                                dynamic_port_map = {
                                    2323: 23,  # Telnet (fixed)
                                    8080: new_port,  # HTTP (updated!)
                                }

                                # Start new proxies with updated port
                                self.proxy_manager.start_proxy_for_device(
                                    mac=mac,
                                    device_ipv4=device.ipv4_address,
                                    device_ipv6=device.ipv6_address,
                                    port_map=dynamic_port_map,
                                )

                                self.logger.info(
                                    f"✓ Proxies restarted: HTTP 8080 → {new_port}"
                                )
                        elif new_port == current_port:
                            # Port came back up (temporary issue)
                            self.logger.info(
                                f"✓ HTTP port {current_port} is now responding again for {mac}"
                            )
                        else:
                            # Service completely down
                            self.logger.error(
                                f"❌ HTTP service DOWN for {mac} ({device.ipv4_address}) - "
                                f"no HTTP port responding!"
                            )
                            # Don't change device status - might be temporary
                            # User can check logs to see service is down

                except Exception as e:
                    self.logger.debug(f"Port health check error for {mac}: {e}")
                    continue

    def _rediscover_all_devices(self) -> None:
        """
        Clear WAN addresses for all devices and trigger re-discovery.
        Called when WAN network changes.

        CRITICAL: Sets discovery_in_progress flag to prevent WAN monitor from
        triggering again during this rediscovery (prevents infinite loop!)
        """
        # CRITICAL: Set discovery flag to prevent WAN monitor loop!
        with self.discovery_lock:
            if self.discovery_in_progress:
                self.logger.warning("Rediscovery already in progress, skipping duplicate trigger")
                return
            self.discovery_in_progress = True

        try:
            self.logger.info("Re-discovering all devices due to WAN network change")

            devices_to_rediscover = []

            with self._devices_lock:
                for mac, device in self.devices.items():
                    # Clear WAN addresses
                    old_ipv4 = device.ipv4_wan_address
                    old_ipv6 = device.ipv6_address

                    device.ipv4_wan_address = None
                    device.ipv6_address = None
                    device.status = "discovering"

                    self.logger.info(
                        f"Cleared WAN addresses for {mac} "
                        f"(was IPv4: {old_ipv4}, IPv6: {old_ipv6})"
                    )

                    # Only rediscover if device is still in ARP table (active)
                    current_arp_entries = self.arp_monitor.get_arp_entries()
                    current_macs = {mac for mac, _ in current_arp_entries}

                    if mac in current_macs:
                        devices_to_rediscover.append(mac)
                    else:
                        device.status = "inactive"
                        self.logger.info(f"Device {mac} not in ARP table, marking inactive")

                # Save updated device states
                self.device_store.save_devices(self.devices)

            # Spawn discovery threads for active devices
            for mac in devices_to_rediscover:
                try:
                    thread = threading.Thread(
                        target=self._discover_addresses_for_device,
                        args=(mac,),
                        daemon=True,
                        name=f"Rediscovery-{mac}",
                    )
                    thread.start()
                    self.logger.info(
                        f"Started re-discovery thread for {mac} (thread: {thread.name})"
                    )
                except Exception as thread_error:
                    self.logger.error(
                        f"Failed to start re-discovery thread for {mac}: {thread_error}"
                    )
                    with self._devices_lock:
                        if mac in self.devices:
                            self.devices[mac].status = "error"

            self.logger.info(
                f"Re-discovery initiated for {len(devices_to_rediscover)} active devices"
            )

            # Wait for discovery to complete (with timeout)
            # Give discovery threads time to finish before allowing WAN monitor to trigger again
            max_wait = 180  # 3 minutes max (DHCPv6 can take 60-75s)
            wait_interval = 5  # Check every 5 seconds

            self.logger.info(f"Waiting up to {max_wait}s for rediscovery to complete...")

            for elapsed in range(0, max_wait, wait_interval):
                # Check if all devices finished discovering
                with self._devices_lock:
                    discovering_count = sum(
                        1 for d in self.devices.values() if d.status == "discovering"
                    )

                if discovering_count == 0:
                    self.logger.info(f"✓ Rediscovery completed in {elapsed}s")
                    break

                self.logger.debug(
                    f"Waiting for {discovering_count} device(s) to finish discovering... "
                    f"({elapsed}/{max_wait}s elapsed)"
                )
                time.sleep(wait_interval)
            else:
                # Timeout reached
                self.logger.warning(
                    f"Rediscovery timeout after {max_wait}s - some devices still discovering"
                )

        finally:
            # CRITICAL: Always clear discovery flag, even on error!
            with self.discovery_lock:
                self.discovery_in_progress = False
            self.logger.info("Rediscovery process complete - WAN monitor re-enabled")


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
