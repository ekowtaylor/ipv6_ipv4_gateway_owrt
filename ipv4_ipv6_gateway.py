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
from haproxy_manager import HAProxyManager

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

    def add_ipv6_address(self, ipv6: str, prefix_len: int = 64) -> bool:
        """Add an IPv6 address to interface"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "add", f"{ipv6}/{prefix_len}", "dev", self.interface_name],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Added IPv6 {ipv6}/{prefix_len} to {self.interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            # Check if address already exists (not an error)
            if "RTNETLINK answers: File exists" in str(e.stderr):
                self.logger.debug(f"IPv6 {ipv6} already exists on {self.interface_name}")
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

    def request_ipv6_for_mac(self, mac: str) -> Optional[str]:
        """
        Spoof MAC on interface, enable SLAAC + DHCPv6, return assigned IPv6 address.

        This method supports both IPv6 address assignment methods:
        1. SLAAC (Stateless Address Autoconfiguration) - uses Router Advertisement
        2. DHCPv6 (Stateful) - requests address from DHCPv6 server

        Many networks use both:
        - SLAAC for address assignment
        - DHCPv6 for additional info (DNS, NTP, etc.)

        Uses exponential backoff retry logic for reliability.
        """
        self.logger.info(f"Requesting IPv6 for MAC: {mac} (SLAAC + DHCPv6)")

        original_mac = self.iface.get_mac_address()
        obtained_ipv6 = None  # Track obtained IPv6 for re-adding after MAC restoration

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
                    f"IPv6 attempt {attempt_num}/{cfg.DHCPV6_RETRY_COUNT} for MAC {mac}"
                )

                # Enable IPv6 on interface (required for SLAAC)
                if not self._enable_ipv6_on_interface():
                    self.logger.warning(f"Failed to enable IPv6 on {self.interface}")
                    continue

                # Wait for SLAAC (Router Advertisement)
                self.logger.debug(f"Waiting for SLAAC (Router Advertisement)...")
                time.sleep(3)  # Give SLAAC time to work

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
                    self.logger.debug("Attempting DHCPv6 for additional configuration...")
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

                self.logger.info(f"Ensuring IPv6 {obtained_ipv6} is configured on {self.interface}...")
                if self.iface.add_ipv6_address(obtained_ipv6, 64):
                    self.logger.info(f"✓ IPv6 {obtained_ipv6} configured on {self.interface}")

                    # Enable Proxy NDP for this IPv6
                    if self._enable_proxy_ndp(obtained_ipv6):
                        self.logger.info(f"✓ Enabled Proxy NDP for {obtained_ipv6}")
                    else:
                        self.logger.warning(f"⚠ Failed to enable Proxy NDP for {obtained_ipv6}")

                    # CRITICAL: Wait for kernel to fully initialize the IPv6 address
                    # Give the kernel time to complete DAD (Duplicate Address Detection)
                    # and make the address available for binding
                    self.logger.info(f"Waiting for IPv6 address to be fully ready for binding...")
                    time.sleep(3)  # Wait for DAD to complete

                    # Verify the address is actually present and usable
                    max_verify_attempts = 5
                    for attempt in range(max_verify_attempts):
                        if self._verify_ipv6_present(obtained_ipv6):
                            self.logger.info(f"✓ Confirmed: IPv6 {obtained_ipv6} is present and ready on {self.interface}")
                            break
                        else:
                            if attempt < max_verify_attempts - 1:
                                self.logger.warning(f"IPv6 {obtained_ipv6} not yet ready, waiting... (attempt {attempt + 1}/{max_verify_attempts})")
                                time.sleep(2)
                            else:
                                self.logger.error(f"✗ IPv6 {obtained_ipv6} still not ready after {max_verify_attempts} attempts")
                else:
                    self.logger.error(f"✗ Failed to configure IPv6 {obtained_ipv6} on {self.interface}")

            # CRITICAL FIX: Return the obtained IPv6 from the finally block
            # Without this, the function returns None even on success
            return obtained_ipv6

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
                [cfg.CMD_SYSCTL, "-w", f"net.ipv6.conf.{self.interface}.disable_ipv6=0"],
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
        Enable IPv6 Proxy NDP for the given address.

        This tells the kernel to respond to Neighbor Discovery requests
        for this IPv6 address, even though it's not the "primary" address.

        Args:
            ipv6: IPv6 address to enable proxy NDP for

        Returns:
            True if successful
        """
        try:
            subprocess.run(
                [cfg.CMD_IP, "-6", "neigh", "add", "proxy", ipv6, "dev", self.interface],
                check=True,
                capture_output=True
            )
            self.logger.debug(f"Enabled Proxy NDP for {ipv6} on {self.interface}")
            return True
        except subprocess.CalledProcessError as e:
            # Check if it already exists (exit code 2)
            if e.returncode == 2:
                self.logger.debug(f"Proxy NDP already enabled for {ipv6}")
                return True
            else:
                self.logger.error(f"Failed to enable Proxy NDP for {ipv6}: {e}")
                return False

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
                    self.logger.debug(f"DHCPv6 request failed with exit code {return_code}")
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
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "128", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "FORWARD", "-p", "ipv6-icmp", "--icmpv6-type", "128", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 129: Echo Reply (ping response)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "129", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "FORWARD", "-p", "ipv6-icmp", "--icmpv6-type", "129", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 133: Router Solicitation (ESSENTIAL for SLAAC)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "133", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 134: Router Advertisement (ESSENTIAL for SLAAC)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "134", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 135: Neighbor Solicitation (ESSENTIAL for NDP/address resolution)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "135", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "FORWARD", "-p", "ipv6-icmp", "--icmpv6-type", "135", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 136: Neighbor Advertisement (ESSENTIAL for NDP/address resolution)
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "136", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "FORWARD", "-p", "ipv6-icmp", "--icmpv6-type", "136", "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )

            # ICMPv6 Type 137: Redirect Message
            subprocess.run(
                [cfg.CMD_IP6TABLES, "-I", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", "137", "-j", "ACCEPT"],
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

            self.logger.info("ICMP/ICMPv6 traffic allowed (ping enabled with NDP support)")
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
        self.proxies: Dict[str, Dict[int, subprocess.Popen]] = {}  # {mac: {port: process}}
        self.log_files: Dict[str, Dict[int, object]] = {}  # {mac: {port: log_file_handle}}
        self._lock = threading.Lock()

    def start_proxy_for_device(self, mac: str, device_ipv4: str, device_ipv6: str, port_map: Dict[int, int]) -> bool:
        """
        Start socat proxies for all ports for a device.

        Args:
            mac: Device MAC address
            device_ipv4: Device's LAN IPv4 address (e.g., "192.168.1.128")
            device_ipv6: Device's WAN IPv6 address (e.g., "2620:10d:c050:100:46b7:d0ff:fea6:6dfc")
            port_map: Port mapping {gateway_port: device_port}

        Returns:
            True if all proxies started successfully
        """
        self.logger.info(f"Starting IPv6→IPv4 proxies for device {device_ipv4} (IPv6: {device_ipv6}, MAC: {mac})")

        with self._lock:
            if mac not in self.proxies:
                self.proxies[mac] = {}

            success_count = 0
            for gateway_port, device_port in port_map.items():
                if self._start_single_proxy(mac, device_ipv4, device_ipv6, gateway_port, device_port):
                    success_count += 1

            self.logger.info(
                f"Started {success_count}/{len(port_map)} IPv6→IPv4 proxies for {mac}"
            )
            return success_count > 0

    def _start_single_proxy(self, mac: str, device_ipv4: str, device_ipv6: str, gateway_port: int, device_port: int) -> bool:
        """Start a single socat proxy for one port"""
        try:
            # Check if proxy already running for this port
            if gateway_port in self.proxies.get(mac, {}):
                existing_process = self.proxies[mac][gateway_port]
                if existing_process.poll() is None:  # Still running
                    self.logger.debug(
                        f"Proxy already running for {mac} port {gateway_port}"
                    )
                    return True
                else:
                    # Process died, remove it
                    del self.proxies[mac][gateway_port]

            # Determine if this port needs special protocol handling
            # Telnet ports: 23, 2323 (and any port that maps to 23)
            is_telnet_port = (device_port == 23 or gateway_port == 2323)

            # HTTP/HTTPS ports: 80, 443, 8080, 8443 (and any port that maps to 80/443)
            is_http_port = (device_port in [80, 443] or gateway_port in [8080, 8443])

            # Verbose logging flags for socat
            # -d -d: Double verbose mode - logs connections and data transfer
            # -lf /dev/stdout: Log to stdout (captured by gateway log)
            verbose_flags = ["-d", "-d", "-lf", "/dev/stdout"]

            # SIMPLIFIED SOCAT COMMANDS - Use minimal options that work with all protocols
            # The "rawer" and "ignoreeof" options can cause issues with IPv6
            # Use standard TCP options that are universally compatible

            # CRITICAL: Bind outgoing connections to gateway's LAN IP (192.168.1.1)
            # This ensures the device receives connections from a known source and can route responses back
            gateway_lan_ip = "192.168.1.1"  # Gateway's eth1 IP

            # BIND TO DEVICE-SPECIFIC IPv6 ADDRESS
            socat_cmd = [
                cfg.CMD_SOCAT,
                *verbose_flags,
                f"TCP6-LISTEN:{gateway_port},bind=[{device_ipv6}],fork,reuseaddr",
                f"TCP4:{device_ipv4}:{device_port},bind={gateway_lan_ip}"
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
                start_new_session=True  # Detach from parent
            )

            # Store log file handle so we can close it later
            if mac not in self.log_files:
                self.log_files[mac] = {}
            self.log_files[mac][gateway_port] = log_file

            # Wait a moment to see if it crashes immediately
            time.sleep(0.1)
            if process.poll() is not None:
                self.logger.error(
                    f"Socat proxy failed to start for {mac} port {gateway_port}"
                )
                return False

            # Success! Store the process
            if mac not in self.proxies:
                self.proxies[mac] = {}
            self.proxies[mac][gateway_port] = process

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
                f"Failed to start socat proxy for {mac} port {gateway_port}: {e}"
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
                    self.logger.error(f"Error stopping proxy for {mac} port {port}: {e}")

                # CRITICAL FIX: Close log file handle to prevent resource leak
                if mac in self.log_files and port in self.log_files[mac]:
                    try:
                        self.log_files[mac][port].close()
                        del self.log_files[mac][port]
                    except Exception as e:
                        self.logger.error(f"Error closing log file for {mac} port {port}: {e}")

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
                        "running": process.poll() is None
                    }

                return {
                    "mac": mac,
                    "proxies": proxies_status,
                    "running": len(proxies_status) > 0
                }
            else:
                # Status for all devices
                all_status = {}
                for mac, ports in self.proxies.items():
                    proxies_status = {}
                    for port, process in ports.items():
                        proxies_status[port] = {
                            "pid": process.pid,
                            "running": process.poll() is None
                        }
                    all_status[mac] = proxies_status

                return all_status


class WANMonitor:
    """Monitors WAN interface for network changes"""

    def __init__(self, interface: str):
        self.interface = interface
        self.logger = logging.getLogger("WANMonitor")
        self.iface = NetworkInterface(interface)
        self.last_ipv4: Optional[List[str]] = None
        self.last_ipv6: Optional[List[str]] = None

    def get_current_addresses(self) -> tuple:
        """Get current IPv4 and IPv6 addresses on WAN interface"""
        ipv4_addrs = self.iface.get_ipv4_addresses()
        ipv6_addrs = self.iface.get_ipv6_addresses()
        return (ipv4_addrs, ipv6_addrs)

    def check_for_changes(self) -> bool:
        """
        Check if WAN network has changed.
        Returns True if network changed, False otherwise.
        """
        current_ipv4, current_ipv6 = self.get_current_addresses()

        # First time - just initialize
        if self.last_ipv4 is None and self.last_ipv6 is None:
            self.last_ipv4 = current_ipv4
            self.last_ipv6 = current_ipv6
            self.logger.info(
                f"WAN monitor initialized - IPv4: {current_ipv4}, IPv6: {current_ipv6}"
            )
            return False

        # Check for changes
        ipv4_changed = set(current_ipv4) != set(self.last_ipv4 or [])
        ipv6_changed = set(current_ipv6) != set(self.last_ipv6 or [])

        if ipv4_changed or ipv6_changed:
            self.logger.warning("WAN network change detected!")
            if ipv4_changed:
                self.logger.warning(
                    f"  IPv4 changed: {self.last_ipv4} → {current_ipv4}"
                )
            if ipv6_changed:
                self.logger.warning(
                    f"  IPv6 changed: {self.last_ipv6} → {current_ipv6}"
                )

            # Update last known addresses
            self.last_ipv4 = current_ipv4
            self.last_ipv6 = current_ipv6

            return True

        return False


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

        self.eth0 = NetworkInterface(cfg.ETH0_INTERFACE)
        self.eth1 = NetworkInterface(cfg.ETH1_INTERFACE)

        # WAN network monitor (for automatic rediscovery on network changes)
        self.wan_monitor = WANMonitor(interface=cfg.ETH0_INTERFACE) if cfg.ENABLE_WAN_MONITOR else None

        self.api_server: Optional[GatewayAPIServer] = None

        self.devices: Dict[str, DeviceMapping] = {}
        self._devices_lock = threading.Lock()
        self.running = False
        self.discovery_thread: Optional[threading.Thread] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.wan_monitor_thread: Optional[threading.Thread] = None

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

        # Stop all proxies (works for both socat and HAProxy)
        if self.proxy_manager:
            self.proxy_manager.stop_all_proxies()

        with self._devices_lock:
            self.device_store.save_devices(self.devices)

        self.logger.info("Gateway service stopped")

    # ---- Internal loops ----

    def _discovery_loop(self) -> None:
        """Main loop: discover new MACs and request IPv6"""
        self.logger.info("Discovery loop started (SINGLE DEVICE MODE)")

        while self.running:
            try:
                new_entries = self.arp_monitor.get_new_macs()

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
                                    self.proxy_manager.stop_proxies_for_device(replaced_device_mac)

                                # Remove old device
                                del self.devices[replaced_device_mac]
                                self.arp_monitor.known_macs.discard(replaced_device_mac)

                                self.logger.info(f"✓ Removed old device {replaced_device_mac}")

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
                            self.logger.info(f"🆕 New device discovered: {mac} (IPv4: {ipv4})")

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
                                            self.logger.error(f"Marked device {mac} as error due to thread spawn failure")

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

                        # Verify IPv6 is actually configured on eth0
                        self.logger.info(f"Verifying IPv6 {ipv6} is configured on eth0...")
                        ipv6_addresses_on_eth0 = self.eth0.get_ipv6_addresses()

                        if ipv6 in ipv6_addresses_on_eth0:
                            self.logger.info(f"✓ Confirmed: IPv6 {ipv6} is present on eth0")
                        else:
                            self.logger.warning(f"⚠ WARNING: IPv6 {ipv6} NOT found on eth0!")
                            self.logger.warning(f"  eth0 IPv6 addresses: {ipv6_addresses_on_eth0}")
                            self.logger.warning(f"  This will cause HAProxy/socat bind to FAIL!")

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

                    # Setup automatic port forwarding if enabled
                    if cfg.ENABLE_AUTO_PORT_FORWARDING:
                        # IPv4 port forwarding (if device has LAN IPv4)
                        if device.ipv4_address:
                            self._setup_auto_port_forwarding_ipv4(device.ipv4_address, mac)

                        # IPv6→IPv4 proxying (if enabled and device has both IPv4 and IPv6)
                        # Use separate port mapping for IPv6 (only firewall-allowed ports)
                        if cfg.ENABLE_IPV6_TO_IPV4_PROXY and self.proxy_manager and device.ipv4_address and device.ipv6_address:
                            # Start proxies with FIREWALL-ALLOWED ports only (telnet 23, HTTP 80)
                            # Pass device's IPv6 address so proxy binds to it specifically
                            self.proxy_manager.start_proxy_for_device(
                                mac=mac,
                                device_ipv4=device.ipv4_address,
                                device_ipv6=device.ipv6_address,  # Device's unique IPv6 address
                                port_map=cfg.IPV6_PROXY_PORT_FORWARDS  # Only telnet & HTTP!
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
        self.logger.info(f"Setting up IPv4 port forwarding for {device_ip} (MAC: {mac})")

        wan_interface = cfg.ETH0_INTERFACE
        lan_interface = cfg.ETH1_INTERFACE

        for gateway_port, device_port in cfg.AUTO_PORT_FORWARDS.items():
            try:
                # DNAT rule: Forward traffic from WAN port to device
                dnat_cmd = [
                    cfg.CMD_IPTABLES,
                    "-t", "nat",
                    "-C",  # Check if rule exists
                    "PREROUTING",
                    "-i", wan_interface,
                    "-p", "tcp",
                    "--dport", str(gateway_port),
                    "-j", "DNAT",
                    "--to-destination", f"{device_ip}:{device_port}"
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
                        "-A", "FORWARD",
                        "-i", wan_interface,
                        "-o", lan_interface,
                        "-p", "tcp",
                        "-d", device_ip,
                        "--dport", str(device_port),
                        "-j", "ACCEPT"
                    ]
                    subprocess.run(forward_cmd, check=True, capture_output=True)

                    # Return traffic
                    return_cmd = [
                        cfg.CMD_IPTABLES,
                        "-A", "FORWARD",
                        "-i", lan_interface,
                        "-o", wan_interface,
                        "-p", "tcp",
                        "-s", device_ip,
                        "--sport", str(device_port),
                        "-j", "ACCEPT"
                    ]
                    subprocess.run(return_cmd, check=True, capture_output=True)

                    # Local access (from gateway itself)
                    local_cmd = [
                        cfg.CMD_IPTABLES,
                        "-t", "nat",
                        "-A", "OUTPUT",
                        "-p", "tcp",
                        "--dport", str(gateway_port),
                        "-j", "DNAT",
                        "--to-destination", f"{device_ip}:{device_port}"
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
        self.logger.info(f"Setting up IPv6 firewall rules for {device_ipv6} (MAC: {mac})")

        wan_interface = cfg.ETH0_INTERFACE

        for gateway_port, device_port in cfg.AUTO_PORT_FORWARDS.items():
            try:
                # Check if FORWARD rule exists for this device_port
                check_cmd = [
                    cfg.CMD_IP6TABLES,
                    "-C",  # Check
                    "FORWARD",
                    "-p", "tcp",
                    "-d", device_ipv6,
                    "--dport", str(device_port),  # Direct port, no translation
                    "-j", "ACCEPT"
                ]

                check_result = subprocess.run(check_cmd, capture_output=True)

                if check_result.returncode != 0:
                    # Rule doesn't exist, add it
                    # FORWARD rule: Allow traffic to device's real port
                    forward_cmd = [
                        cfg.CMD_IP6TABLES,
                        "-A", "FORWARD",
                        "-p", "tcp",
                        "-d", device_ipv6,
                        "--dport", str(device_port),
                        "-j", "ACCEPT"
                    ]
                    subprocess.run(forward_cmd, check=True, capture_output=True)

                    # Return traffic
                    return_cmd = [
                        cfg.CMD_IP6TABLES,
                        "-A", "FORWARD",
                        "-p", "tcp",
                        "-s", device_ipv6,
                        "--sport", str(device_port),
                        "-j", "ACCEPT"
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

    def _wan_monitoring_loop(self) -> None:
        """
        Monitor WAN interface for network changes and trigger re-discovery.
        When WAN network changes (different IP addresses), all devices are
        re-discovered to obtain new WAN addresses.
        """
        self.logger.info("WAN monitoring loop started")

        while self.running:
            try:
                if self.wan_monitor and self.wan_monitor.check_for_changes():
                    # WAN network changed!
                    self.logger.warning(
                        "WAN network changed - triggering device re-discovery"
                    )

                    # Wait a moment for network to stabilize
                    time.sleep(cfg.WAN_CHANGE_REDISCOVERY_DELAY)

                    # Clear all WAN addresses and trigger re-discovery
                    self._rediscover_all_devices()

                time.sleep(cfg.WAN_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in WAN monitoring loop: {e}")
                time.sleep(10)

    def _rediscover_all_devices(self) -> None:
        """
        Clear WAN addresses for all devices and trigger re-discovery.
        Called when WAN network changes.
        """
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
                    self.logger.info(
                        f"Device {mac} not in ARP table, marking inactive"
                    )

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
