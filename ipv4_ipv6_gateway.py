#!/usr/bin/env python3
"""
Simple Single-Device IPv4↔IPv6 Gateway
NanoPi R5C - For ONE device at a time

Simplified version - no threading, no REST API, no multi-device complexity.
Discovers ONE device on eth1, gets it DHCPv4/v6 addresses via MAC spoofing,
and sets up port forwarding.
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
from datetime import datetime
from pathlib import Path
from typing import Optional

# Import config
import gateway_config as cfg

# Validate config
cfg.validate_config()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(cfg.LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("SimpleGateway")


@dataclass
class Device:
    """Device state"""

    mac_address: str
    lan_ipv4: Optional[str] = None  # LAN IPv4 (on 192.168.1.0/24)
    wan_ipv4: Optional[str] = None  # WAN IPv4 from DHCP
    wan_ipv6: Optional[str] = None  # Primary WAN IPv6 (first global address)
    wan_ipv6_all: Optional[list] = None  # All WAN IPv6 addresses (SLAAC, DHCPv6, etc.)
    discovered_at: Optional[str] = None
    last_updated: Optional[str] = None
    status: str = "unknown"  # unknown, configured, error

    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.discovered_at:
            self.discovered_at = now
        if not self.last_updated:
            self.last_updated = now

    def to_dict(self):
        return asdict(self)


class SimpleGateway:
    """Simple gateway for single device"""

    def __init__(self):
        self.logger = logging.getLogger("SimpleGateway")
        self.device: Optional[Device] = None
        self.wan_interface = cfg.WAN_INTERFACE
        self.lan_interface = cfg.LAN_INTERFACE
        self.original_wan_mac: Optional[str] = None
        self.state_file = cfg.STATE_FILE
        self.running = False

        # Track link states for cable detection
        self.wan_link_up: Optional[bool] = None
        self.lan_link_up: Optional[bool] = None

    def initialize(self) -> bool:
        """Initialize gateway"""
        self.logger.info("Initializing Simple Gateway (Single Device Mode)")

        # Store original WAN MAC
        self.original_wan_mac = self._get_interface_mac(self.wan_interface)
        if not self.original_wan_mac:
            self.logger.error(f"Failed to get MAC for {self.wan_interface}")
            return False

        self.logger.info(f"Original WAN MAC: {self.original_wan_mac}")

        # Load previous device state if exists
        self._load_state()

        return True

    def start(self):
        """Start gateway service - main loop"""
        self.running = True
        self.logger.info("Gateway started - monitoring for single device")

        # IMPORTANT: Run initial discovery immediately!
        # This detects devices already connected BEFORE service started
        self.logger.info("Running initial device discovery...")

        # First, trigger ARP population by pinging the LAN subnet
        # This ensures devices already connected (but idle) appear in ARP table
        self._populate_arp_table()

        initial_device = self._discover_device()
        if initial_device:
            mac, lan_ip = initial_device
            self.logger.info(f"Found device already connected: {mac} at {lan_ip}")
            # Configure immediately (blocking, not threaded for first device)
            self._configure_device(mac, lan_ip)
        else:
            self.logger.info("No devices found during initial discovery")
            self.logger.info("Waiting for device to connect to eth1...")

        try:
            while self.running:
                # Check for device on LAN
                device_info = self._discover_device()

                if device_info:
                    mac, lan_ip = device_info

                    # If no device configured, or MAC changed, configure this device
                    if not self.device or self.device.mac_address != mac:
                        self.logger.info(f"New device detected: {mac} at {lan_ip}")
                        # Use threading to avoid blocking the main loop
                        config_thread = threading.Thread(
                            target=self._configure_device,
                            args=(mac, lan_ip),
                            daemon=True,
                        )
                        config_thread.start()
                    else:
                        # Device already configured, just update timestamp
                        self.device.last_updated = datetime.now().isoformat()
                        self._save_state()
                else:
                    # No device found in ARP
                    if self.device:
                        # Check how long device has been gone
                        # Only cleanup if gone for 1+ check cycles (2 seconds with CHECK_INTERVAL=2)
                        if not hasattr(self, "_device_missing_count"):
                            self._device_missing_count = 0

                        self._device_missing_count += 1

                        if self._device_missing_count >= 1:  # Faster cleanup!
                            self.logger.warning(
                                f"Device {self.device.mac_address} disconnected - cleaning up"
                            )
                            self._cleanup_device()
                            self._device_missing_count = 0
                        else:
                            self.logger.debug(
                                f"Device not found in ARP (count: {self._device_missing_count})"
                            )
                    else:
                        # Reset counter if no device configured
                        self._device_missing_count = 0

                # Check WAN network changes (only for successfully configured devices)
                if (
                    self.device
                    and self.device.status == "configured"
                    and cfg.MONITOR_WAN_CHANGES
                ):
                    if self._wan_network_changed():
                        self.logger.warning(
                            "WAN network changed - reconfiguring device (fast mode)"
                        )
                        # Use threading to avoid blocking the main loop
                        # Use fast_reconfig=True since MAC is already registered
                        reconfig_thread = threading.Thread(
                            target=self._configure_device,
                            args=(self.device.mac_address, self.device.lan_ipv4, True),
                            daemon=True,
                        )
                        reconfig_thread.start()

                # Check for cable unplug/replug events
                self._check_link_states()

                # Sleep before next check
                time.sleep(cfg.CHECK_INTERVAL)

        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}", exc_info=True)
        finally:
            self.stop()

    def stop(self):
        """Stop gateway and cleanup"""
        self.logger.info("Stopping gateway...")
        self.running = False

        # Restore original WAN MAC
        if self.original_wan_mac:
            self.logger.info(f"Restoring original WAN MAC: {self.original_wan_mac}")
            self._set_interface_mac(self.wan_interface, self.original_wan_mac)

        # Stop proxy if running
        if self.device and self.device.wan_ipv6:
            self._stop_proxy(self.device.mac_address)

        self.logger.info("Gateway stopped")

    def _populate_arp_table(self):
        """
        Trigger ARP table population by pinging LAN subnet.

        This ensures devices that are already connected (but idle) appear in ARP table.
        Without this, devices that haven't sent packets won't be discoverable.
        """
        self.logger.info("Populating ARP table by pinging LAN subnet...")

        try:
            # Get gateway IP network (192.168.1.0/24)
            # We'll ping a few common IPs to trigger ARP responses
            base_ip = cfg.LAN_GATEWAY_IP.rsplit(".", 1)[0]  # "192.168.1"

            # Ping a small range of likely IPs (100-110) to speed up discovery
            # Most DHCP servers start at .100
            for i in range(100, 111):
                ip = f"{base_ip}.{i}"
                if ip == cfg.LAN_GATEWAY_IP:
                    continue  # Skip gateway itself

                # Quick ping (1 packet, 0.5s timeout, no wait for response)
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", "-q", ip],
                    capture_output=True,
                    timeout=2,
                )

            # Give ARP table a moment to populate
            time.sleep(0.5)
            self.logger.info("ARP table populated")

        except Exception as e:
            self.logger.debug(f"Error populating ARP table: {e}")
            # Non-fatal - discovery will still work if device sends traffic

    def _discover_device(self) -> Optional[tuple[str, str]]:
        """
        Discover the ONE device on LAN interface.
        Returns (mac, ip) tuple or None.

        If the currently configured device is in ARP, return it.
        Otherwise return the first non-gateway device found.
        """
        try:
            # Get ARP entries for LAN interface
            result = subprocess.run(
                [cfg.CMD_IP, "neigh", "show", "dev", self.lan_interface],
                capture_output=True,
                text=True,
                check=True,
            )

            # Debug: Log what we're checking
            self.logger.debug(f"Checking ARP table for {self.lan_interface}")
            self.logger.debug(f"ARP output: {result.stdout}")

            # Parse ARP output and collect all devices
            # Format: 192.168.1.100 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            # OR:     192.168.1.100 lladdr aa:bb:cc:dd:ee:ff STALE
            # OR:     192.168.1.100 lladdr aa:bb:cc:dd:ee:ff DELAY
            devices = []

            for line in result.stdout.splitlines():
                parts = line.split()
                self.logger.debug(f"ARP line: {line} -> Parts: {parts}")

                # ARP format: <IP> lladdr <MAC> [STATE]
                # parts[0]=IP, parts[1]="lladdr", parts[2]=MAC, parts[3]=STATE (optional)
                if len(parts) >= 3 and parts[1] == "lladdr":
                    ip = parts[0]
                    mac = parts[2].lower()

                    # Skip gateway itself (192.168.1.1)
                    if ip == cfg.LAN_GATEWAY_IP:
                        self.logger.debug(f"Skipping gateway IP: {ip}")
                        continue

                    # Add to devices list
                    devices.append((mac, ip))
                    self.logger.debug(f"Found device in ARP: {mac} at {ip}")

            # No devices found
            if not devices:
                self.logger.debug("No devices found in ARP table")
                return None

            # If we have a currently configured device, check if it's still in ARP
            if self.device:
                for mac, ip in devices:
                    if mac == self.device.mac_address:
                        self.logger.debug(
                            f"Configured device still present: {mac} at {ip}"
                        )
                        return (mac, ip)

            # Either no configured device, or it's gone
            # Return the first device found
            mac, ip = devices[0]
            self.logger.info(f"Found device in ARP: {mac} at {ip}")
            return (mac, ip)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get ARP entries: {e}")
            return None

    def _configure_device(self, mac: str, lan_ip: str, fast_reconfig: bool = False):
        """
        Configure WAN access for the device

        Args:
            mac: Device MAC address
            lan_ip: Device LAN IP
            fast_reconfig: If True, use faster timeouts (MAC already registered)
        """
        mode = "fast reconfig" if fast_reconfig else "initial config"
        self.logger.info(f"Configuring device {mac} ({lan_ip}) - {mode}")

        # Create/update device object
        self.device = Device(mac_address=mac, lan_ipv4=lan_ip, status="configuring")
        self._save_state()

        # Step 1: Spoof MAC on WAN interface
        if not self._spoof_mac(mac, fast_mode=fast_reconfig):
            self.device.status = "error"
            self._save_state()
            return

        # Step 2: Get DHCPv4 if available
        wan_ipv4 = self._request_dhcpv4(mac, fast_mode=fast_reconfig)
        if wan_ipv4:
            self.device.wan_ipv4 = wan_ipv4
            self.logger.info(f"Got WAN IPv4: {wan_ipv4}")

        # Step 3: Get IPv6 (SLAAC or DHCPv6)
        wan_ipv6 = self._request_ipv6(mac, fast_mode=fast_reconfig)
        if wan_ipv6:
            # Collect ALL IPv6 addresses
            all_ipv6 = self._get_all_interface_ipv6(self.wan_interface)

            if all_ipv6:
                # Select primary address (prefer SLAAC over DHCPv6)
                primary_ipv6 = self._select_primary_ipv6(all_ipv6, mac)

                if primary_ipv6:
                    self.device.wan_ipv6 = primary_ipv6
                    self.device.wan_ipv6_all = all_ipv6

                    self.logger.info(f"Got WAN IPv6 (primary): {primary_ipv6}")
                    self.logger.info(
                        f"All WAN IPv6 addresses ({len(all_ipv6)}): {', '.join(all_ipv6)}"
                    )
                else:
                    # Fallback to first address
                    self.device.wan_ipv6 = wan_ipv6
                    self.device.wan_ipv6_all = all_ipv6
                    self.logger.info(f"Got WAN IPv6: {wan_ipv6}")
            else:
                # Only one address found
                self.device.wan_ipv6 = wan_ipv6
                self.logger.info(f"Got WAN IPv6: {wan_ipv6}")

        # Step 4: Setup port forwarding
        if wan_ipv4:
            self._setup_ipv4_port_forwarding(lan_ip, wan_ipv4)

        # Step 5: Setup IPv6 proxy (always, when IPv6 is available)
        if wan_ipv6 and cfg.IPV6_PROXY_PORTS:
            # Check if IPv6 NAT is available first
            if self._check_ipv6_nat_support():
                self._setup_ipv6_proxy(mac, lan_ip, wan_ipv6)
            else:
                self.logger.warning(
                    "IPv6 NAT not available - skipping IPv6 proxy setup"
                )
                self.logger.warning(
                    "Your device has IPv6 internet access, but external IPv6 clients cannot connect to it"
                )
                self.logger.info(
                    "To enable IPv6 proxy, install: opkg install kmod-ipt-nat6 ip6tables"
                )

        # Mark as configured
        self.device.status = "configured"
        self.device.last_updated = datetime.now().isoformat()
        self._save_state()

        self.logger.info(f"Device {mac} configured successfully ({mode})")
        self._print_status()

    def _spoof_mac(self, mac: str, fast_mode: bool = False) -> bool:
        """
        Spoof MAC on WAN interface using UCI (OpenWrt-compatible)

        Args:
            mac: MAC address to spoof
            fast_mode: If True, use minimal wait time
        """
        self.logger.info(f"Spoofing WAN MAC to {mac}")

        try:
            # CRITICAL: On OpenWrt, we MUST use UCI to set MAC
            # Otherwise netifd will override our changes!

            # Step 1: Set MAC in UCI configuration
            self.logger.info(f"Setting MAC in UCI (OpenWrt network config)...")
            subprocess.run(
                ["uci", "set", f"network.wan.macaddr={mac}"],
                check=True,
                capture_output=True,
            )

            # Commit UCI changes
            subprocess.run(
                ["uci", "commit", "network"],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"✓ MAC set in UCI configuration")

            # Step 2: Bring interface down (manually, before netifd reload)
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.wan_interface, "down"],
                check=True,
                capture_output=True,
            )

            # Step 3: Flush ALL IPv6 addresses from interface (critical!)
            # This removes old SLAAC addresses generated from previous MAC
            subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "flush", "dev", self.wan_interface],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Flushed old IPv6 addresses from {self.wan_interface}")

            # Step 4: Flush IPv4 addresses too
            subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "flush", "dev", self.wan_interface],
                check=True,
                capture_output=True,
            )

            # Step 5: Reload network interface (let netifd apply the new MAC from UCI)
            self.logger.info(f"Reloading WAN interface via ifup...")
            subprocess.run(
                ["ifup", "wan"],
                check=True,
                capture_output=True,
                timeout=10,
            )
            self.logger.info(f"✓ WAN interface reloaded with new MAC")

            # Step 6: Enable IPv6 on interface (critical for SLAAC!)
            self.logger.info("Enabling IPv6 and Router Advertisement acceptance...")
            try:
                # Enable IPv6 on this interface
                subprocess.run(
                    [
                        "sysctl",
                        "-w",
                        f"net.ipv6.conf.{self.wan_interface}.disable_ipv6=0",
                    ],
                    check=True,
                    capture_output=True,
                )

                # Accept Router Advertisements (required for SLAAC)
                subprocess.run(
                    ["sysctl", "-w", f"net.ipv6.conf.{self.wan_interface}.accept_ra=2"],
                    check=True,
                    capture_output=True,
                )

                # Enable autoconf (SLAAC autoconfiguration)
                subprocess.run(
                    ["sysctl", "-w", f"net.ipv6.conf.{self.wan_interface}.autoconf=1"],
                    check=True,
                    capture_output=True,
                )

                # Accept RA default route
                subprocess.run(
                    [
                        "sysctl",
                        "-w",
                        f"net.ipv6.conf.{self.wan_interface}.accept_ra_defrtr=1",
                    ],
                    check=True,
                    capture_output=True,
                )

                self.logger.info("✓ IPv6 Router Advertisement acceptance enabled")

            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to enable IPv6 RA: {e}")
                self.logger.warning("SLAAC may not work - continuing anyway")

            # Step 7: Force link down/up cycle to clear upstream router caches
            # This is CRITICAL! The upstream router needs to see the link go down
            # to reset its RA cache and recognize the new MAC address
            self.logger.info("Forcing link cycle to reset upstream router cache...")
            try:
                # Down
                subprocess.run(
                    [cfg.CMD_IP, "link", "set", self.wan_interface, "down"],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )

                # Wait a moment (give upstream router time to detect link down)
                time.sleep(1)

                # Up
                subprocess.run(
                    [cfg.CMD_IP, "link", "set", self.wan_interface, "up"],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )

                self.logger.info(
                    "✓ Link cycle complete - upstream router should send fresh RAs"
                )

            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to cycle link: {e}")

            # Wait for interface to come up and link negotiation
            # Fast mode: 2s (MAC already registered, but need fresh RAs)
            # Normal mode: 3s (wait for link negotiation + firewall registration + RAs)
            wait_time = 2 if fast_mode else 3
            self.logger.info(f"Waiting {wait_time}s for link negotiation and RAs...")
            time.sleep(wait_time)

            # Verify MAC was set correctly
            current_mac = self._get_interface_mac(self.wan_interface)
            if current_mac and current_mac.lower() == mac.lower():
                self.logger.info(f"MAC spoofing successful: {current_mac}")
                return True
            else:
                self.logger.error(
                    f"MAC spoofing failed: expected {mac}, got {current_mac}"
                )
                return False

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to spoof MAC: {e}")
            return False

    def _request_dhcpv4(self, mac: str, fast_mode: bool = False) -> Optional[str]:
        """
        Request DHCPv4 address

        Args:
            mac: Device MAC address
            fast_mode: Use faster timeouts (for reconfiguration)
        """
        retries = cfg.DHCPV4_RETRIES_FAST if fast_mode else cfg.DHCPV4_RETRIES
        timeout = cfg.DHCPV4_TIMEOUT_FAST if fast_mode else cfg.DHCPV4_TIMEOUT
        mode_str = "fast" if fast_mode else "normal"

        self.logger.info(
            f"Requesting DHCPv4 for {mac} ({mode_str} mode: {retries} retries, {timeout}s timeout)"
        )

        for attempt in range(1, retries + 1):
            self.logger.info(f"DHCPv4 attempt {attempt}/{retries}")

            try:
                # Use udhcpc to request DHCP
                result = subprocess.run(
                    [
                        cfg.CMD_UDHCPC,
                        "-i",
                        self.wan_interface,
                        "-n",  # Exit if lease not obtained
                        "-q",  # Quit after obtaining lease
                        "-t",
                        str(retries),
                        "-T",
                        str(timeout),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 5,
                )

                if result.returncode == 0:
                    # Get IP from interface
                    ipv4 = self._get_interface_ipv4(self.wan_interface)
                    if ipv4:
                        self.logger.info(f"DHCPv4 success: {ipv4}")
                        return ipv4

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                self.logger.warning(f"DHCPv4 attempt {attempt} failed: {e}")

            # Exponential backoff (faster in fast mode)
            if attempt < retries:
                if fast_mode:
                    delay = 1  # Fixed 1 second in fast mode
                else:
                    delay = min(2**attempt, 30)  # Exponential in normal mode
                time.sleep(delay)

        self.logger.warning(f"DHCPv4 failed after all retries ({mode_str} mode)")
        return None

    def _request_ipv6(self, mac: str, fast_mode: bool = False) -> Optional[str]:
        """
        Request IPv6 via SLAAC or DHCPv6

        Args:
            mac: Device MAC address
            fast_mode: Use faster timeouts (for reconfiguration)
        """
        retries = cfg.DHCPV6_RETRIES_FAST if fast_mode else cfg.DHCPV6_RETRIES
        timeout = cfg.DHCPV6_TIMEOUT_FAST if fast_mode else cfg.DHCPV6_TIMEOUT
        slaac_wait = cfg.SLAAC_WAIT_TIME_FAST if fast_mode else cfg.SLAAC_WAIT_TIME
        mode_str = "fast" if fast_mode else "normal"

        self.logger.info(f"Requesting IPv6 for {mac} ({mode_str} mode)")

        # Try SLAAC first with multiple checks
        # Router Advertisements can arrive at different times (200ms to 600s intervals)
        slaac_checks = 3  # Check 3 times
        slaac_interval = slaac_wait  # Time between checks

        self.logger.info(
            f"Trying SLAAC ({slaac_checks} checks, {slaac_interval}s interval)..."
        )

        for check in range(1, slaac_checks + 1):
            self.logger.debug(f"SLAAC check {check}/{slaac_checks}")
            time.sleep(slaac_interval)

            ipv6 = self._get_interface_ipv6(self.wan_interface)
            if ipv6:
                self.logger.info(
                    f"Got IPv6 via SLAAC: {ipv6} (after {check * slaac_interval}s)"
                )
                return ipv6

        self.logger.info("SLAAC failed after all checks")

        # Fall back to DHCPv6
        self.logger.info(f"Trying DHCPv6 ({retries} retries, {timeout}s timeout)...")

        for attempt in range(1, retries + 1):
            self.logger.info(f"DHCPv6 attempt {attempt}/{retries}")

            try:
                result = subprocess.run(
                    [
                        cfg.CMD_ODHCP6C,
                        "-s",
                        "/bin/true",  # Don't run script
                        "-t",
                        str(timeout),
                        "-v",
                        self.wan_interface,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 5,
                )

                if result.returncode == 0:
                    ipv6 = self._get_interface_ipv6(self.wan_interface)
                    if ipv6:
                        self.logger.info(f"DHCPv6 success: {ipv6}")
                        return ipv6

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                self.logger.warning(f"DHCPv6 attempt {attempt} failed: {e}")

            # Backoff (faster in fast mode)
            if attempt < retries:
                if fast_mode:
                    delay = 1  # Fixed 1 second in fast mode
                else:
                    delay = min(2**attempt, 20)  # Exponential in normal mode
                time.sleep(delay)

        self.logger.warning(f"IPv6 acquisition failed ({mode_str} mode)")
        return None

    def _check_port_open(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """
        Check if a TCP port is open on the device
        Returns True if port is listening, False otherwise
        """
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0  # Port is open
        except socket.error:
            return False
        finally:
            try:
                sock.close()
            except:
                pass

    def _setup_ipv4_port_forwarding(self, lan_ip: str, wan_ip: str):
        """
        Setup IPv4 NAT forwarding (TCP ports + ICMP)
        This makes the WAN IP behave exactly like the device's own IP
        """
        self.logger.info(f"═══ Setting up IPv4 Port Forwarding ═══")
        self.logger.info(f"  Device LAN IP: {lan_ip}")
        self.logger.info(f"  Device WAN IP: {wan_ip}")
        self.logger.info(f"  Total ports to forward: {len(cfg.PORT_FORWARDS)}")

        # CRITICAL: Add MASQUERADE for return traffic from LAN to WAN
        # Without this, device replies with source=192.168.1.x instead of WAN IP
        # and upstream router rejects it
        try:
            # Check if MASQUERADE rule exists
            check = subprocess.run(
                [
                    cfg.CMD_IPTABLES,
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    f"{cfg.LAN_GATEWAY_IP.rsplit('.', 1)[0]}.0/24",  # 192.168.1.0/24
                    "-o",
                    self.wan_interface,
                    "-j",
                    "MASQUERADE",
                ],
                capture_output=True,
            )

            if check.returncode != 0:
                # Add MASQUERADE rule for LAN→WAN traffic
                subprocess.run(
                    [
                        cfg.CMD_IPTABLES,
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        f"{cfg.LAN_GATEWAY_IP.rsplit('.', 1)[0]}.0/24",  # 192.168.1.0/24
                        "-o",
                        self.wan_interface,
                        "-j",
                        "MASQUERADE",
                    ],
                    check=True,
                    capture_output=True,
                )
                self.logger.info(
                    f"  ✓ MASQUERADE: LAN traffic → {self.wan_interface} (return path fixed)"
                )
            else:
                self.logger.info(f"  ↻ MASQUERADE already exists for LAN → WAN")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"  ✗ Failed to setup MASQUERADE: {e}")
            self.logger.error("  WARNING: Return traffic may not work!")

        # REMOVED: ICMP forwarding to device
        # REASON: This breaks router connectivity!
        # The router gets WAN IP via MAC spoofing, but forwarding ALL ICMP
        # to that IP breaks ping to the router itself.
        #
        # DECISION: Let router respond to pings normally
        # Device will be accessible via:
        # - Direct LAN IP (192.168.1.x)
        # - Port forwards (TCP/UDP)
        # - NOT via ICMP ping to WAN IP (acceptable tradeoff)

        self.logger.info(
            f"  ℹ ICMP forwarding disabled (prevents breaking router ping)"
        )
        self.logger.info(f"  ℹ Device accessible via: LAN IP {lan_ip} or port forwards")

        # Forward TCP ports to device
        ports_added = 0
        ports_existed = 0
        ports_failed = 0
        ports_skipped = 0

        self.logger.info("Checking which device ports are actually listening...")

        for gateway_port, device_port in cfg.PORT_FORWARDS.items():
            try:
                # First check if port is actually open on device
                port_is_open = self._check_port_open(lan_ip, device_port, timeout=2.0)

                if not port_is_open:
                    self.logger.info(
                        f"  ⊘ Port {gateway_port:5d} → {lan_ip}:{device_port:5d} (SKIPPED - port not listening)"
                    )
                    ports_skipped += 1
                    continue  # Skip this port - nothing listening

                # Port is open, proceed with forwarding
                # Check if rule exists
                check = subprocess.run(
                    [
                        cfg.CMD_IPTABLES,
                        "-t",
                        "nat",
                        "-C",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "-d",
                        wan_ip,
                        "--dport",
                        str(gateway_port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"{lan_ip}:{device_port}",
                    ],
                    capture_output=True,
                )

                if check.returncode != 0:
                    # Add DNAT rule
                    subprocess.run(
                        [
                            cfg.CMD_IPTABLES,
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "tcp",
                            "-d",
                            wan_ip,
                            "--dport",
                            str(gateway_port),
                            "-j",
                            "DNAT",
                            "--to-destination",
                            f"{lan_ip}:{device_port}",
                        ],
                        check=True,
                        capture_output=True,
                    )

                    # Add FORWARD rule
                    subprocess.run(
                        [
                            cfg.CMD_IPTABLES,
                            "-A",
                            "FORWARD",
                            "-p",
                            "tcp",
                            "-d",
                            lan_ip,
                            "--dport",
                            str(device_port),
                            "-j",
                            "ACCEPT",
                        ],
                        check=True,
                        capture_output=True,
                    )

                    self.logger.info(
                        f"  ✓ Port {gateway_port:5d} → {lan_ip}:{device_port:5d} (ADDED - service detected)"
                    )
                    ports_added += 1
                else:
                    self.logger.info(
                        f"  ↻ Port {gateway_port:5d} → {lan_ip}:{device_port:5d} (EXISTS)"
                    )
                    ports_existed += 1

            except subprocess.CalledProcessError as e:
                self.logger.error(
                    f"  ✗ Port {gateway_port:5d} → {lan_ip}:{device_port:5d} (FAILED: {e})"
                )
                ports_failed += 1

        # Summary
        self.logger.info(f"═══ Port Forwarding Summary ═══")
        self.logger.info(f"  Added:   {ports_added}")
        self.logger.info(f"  Existed: {ports_existed}")
        self.logger.info(f"  Skipped: {ports_skipped} (ports not listening)")
        self.logger.info(f"  Failed:  {ports_failed}")
        self.logger.info(f"═══════════════════════════════")

    def _check_ipv6_nat_support(self) -> bool:
        """
        Check if IPv6 NAT is available on the system

        Returns:
            True if ip6tables NAT table is accessible, False otherwise
        """
        try:
            # Try to access the NAT table - this will fail if not available
            result = subprocess.run(
                [cfg.CMD_IP6TABLES, "-t", "nat", "-L"],
                capture_output=True,
                timeout=2,
            )

            if result.returncode == 0:
                self.logger.info("✓ IPv6 NAT support detected and functional")
                return True
            else:
                error_msg = result.stderr.decode().strip()
                self.logger.info(f"IPv6 NAT not available: {error_msg}")
                return False

        except FileNotFoundError:
            self.logger.info("ip6tables command not found - IPv6 NAT not available")
            return False
        except Exception as e:
            self.logger.debug(f"IPv6 NAT check failed: {e}")
            return False

    def _setup_ipv6_proxy(self, mac: str, lan_ip: str, wan_ipv6: str):
        """
        Setup IPv6→IPv4 proxy using socat with SNAT for return traffic

        SNAT ensures the device sees connections from the gateway (192.168.1.1)
        instead of random IPv6 addresses, which improves compatibility.
        """
        self.logger.info("=" * 70)
        self.logger.info("IPv6 → IPv4 PROXY SETUP")
        self.logger.info("=" * 70)
        self.logger.info(f"Device MAC:      {mac}")
        self.logger.info(f"Device LAN IP:   {lan_ip}")
        self.logger.info(f"Router WAN IPv6: {wan_ipv6}")
        self.logger.info(f"Proxy Ports:     {cfg.IPV6_PROXY_PORTS}")
        self.logger.info("")

        # Check if IPv6 NAT is available
        try:
            result = subprocess.run(
                [cfg.CMD_IP6TABLES, "-t", "nat", "-L"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode != 0:
                self.logger.error("IPv6 NAT (ip6tables -t nat) is NOT available!")
                self.logger.error("IPv6 proxy will NOT work without IPv6 NAT support.")
                self.logger.error(
                    "Install with: opkg install kmod-ipt-nat6 ip6tables-mod-nat"
                )
                return
            self.logger.info("✓ IPv6 NAT support detected")
        except Exception as e:
            self.logger.error(f"Failed to check IPv6 NAT support: {e}")
            return

        # Check if socat is available
        if not os.path.exists(cfg.CMD_SOCAT):
            self.logger.error(f"socat not found at {cfg.CMD_SOCAT}")
            self.logger.error("Install with: opkg install socat")
            return
        self.logger.info(f"✓ socat found at {cfg.CMD_SOCAT}")
        self.logger.info("")

        # Kill existing socat processes for this device
        self.logger.info("Cleaning up existing proxy processes...")
        self._stop_proxy(mac)
        self.logger.info("✓ Existing proxies stopped")
        self.logger.info("")

        # Setup each port
        successful_ports = []
        failed_ports = []

        for ipv6_port, device_port in cfg.IPV6_PROXY_PORTS.items():
            self.logger.info(
                f"Setting up proxy: IPv6 port {ipv6_port} → Device port {device_port}"
            )

            try:
                # Step 1: Add ip6tables SNAT rule for return traffic
                self.logger.info(f"  Step 1: Adding ip6tables SNAT rule...")

                # Remove existing rule (if any)
                try:
                    subprocess.run(
                        [
                            cfg.CMD_IP6TABLES,
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-d",
                            lan_ip,
                            "-p",
                            "tcp",
                            "--dport",
                            str(device_port),
                            "-j",
                            "SNAT",
                            "--to-source",
                            cfg.LAN_GATEWAY_IP,
                        ],
                        capture_output=True,
                        timeout=2,
                    )
                    self.logger.info(f"    Removed old SNAT rule")
                except:
                    self.logger.info(f"    No existing SNAT rule to remove")

                # Add SNAT rule for this port
                subprocess.run(
                    [
                        cfg.CMD_IP6TABLES,
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-d",
                        lan_ip,
                        "-p",
                        "tcp",
                        "--dport",
                        str(device_port),
                        "-j",
                        "SNAT",
                        "--to-source",
                        cfg.LAN_GATEWAY_IP,
                    ],
                    check=True,
                    timeout=5,
                )

                self.logger.info(
                    f"    ✓ SNAT rule added: {lan_ip}:{device_port} → {cfg.LAN_GATEWAY_IP}"
                )

                # Step 2: Start socat proxy
                self.logger.info(f"  Step 2: Starting socat proxy...")

                cmd = [
                    cfg.CMD_SOCAT,
                    f"TCP6-LISTEN:{ipv6_port},bind=[{wan_ipv6}],fork,reuseaddr",
                    f"TCP4:{lan_ip}:{device_port}",
                ]

                self.logger.info(f"    Command: {' '.join(cmd)}")

                # Start in background
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )

                self.logger.info(f"    ✓ socat started (PID: {proc.pid})")

                # Verify socat is running
                time.sleep(0.5)
                if proc.poll() is None:
                    self.logger.info(f"    ✓ socat process verified running")
                    successful_ports.append((ipv6_port, device_port))
                    self.logger.info(
                        f"  ✅ SUCCESS: [{wan_ipv6}]:{ipv6_port} → {lan_ip}:{device_port}"
                    )
                else:
                    self.logger.error(f"    ✗ socat process died immediately!")
                    failed_ports.append((ipv6_port, device_port, "Process died"))

            except subprocess.CalledProcessError as e:
                error_msg = f"ip6tables command failed: {e}"
                self.logger.error(f"  ❌ FAILED: {error_msg}")
                self.logger.error(
                    f"     Hint: Install IPv6 NAT support with: opkg install kmod-ipt-nat6"
                )
                failed_ports.append((ipv6_port, device_port, error_msg))
            except Exception as e:
                error_msg = str(e)
                self.logger.error(f"  ❌ FAILED: {error_msg}")
                failed_ports.append((ipv6_port, device_port, error_msg))

            self.logger.info("")

        # Summary
        self.logger.info("=" * 70)
        self.logger.info("IPv6 PROXY SETUP SUMMARY")
        self.logger.info("=" * 70)

        if successful_ports:
            self.logger.info(
                f"✅ Successfully configured {len(successful_ports)} proxy port(s):"
            )
            for ipv6_port, device_port in successful_ports:
                self.logger.info(
                    f"   • IPv6 port {ipv6_port} → Device port {device_port}"
                )
                self.logger.info(f"     Access: curl 'http://[{wan_ipv6}]:{ipv6_port}'")

        if failed_ports:
            self.logger.warning(
                f"❌ Failed to configure {len(failed_ports)} proxy port(s):"
            )
            for ipv6_port, device_port, error in failed_ports:
                self.logger.warning(
                    f"   • IPv6 port {ipv6_port} → Device port {device_port}: {error}"
                )

        if not successful_ports and not failed_ports:
            self.logger.info("⚠ No proxy ports configured (IPV6_PROXY_PORTS is empty)")

        self.logger.info("")

        # Validation: Check running socat processes
        self.logger.info("Validating socat proxy processes...")
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            socat_procs = [
                line
                for line in result.stdout.split("\n")
                if "socat" in line and "TCP6-LISTEN" in line
            ]

            if socat_procs:
                self.logger.info(
                    f"✓ Found {len(socat_procs)} running socat process(es):"
                )
                for proc in socat_procs:
                    self.logger.info(f"  {proc.strip()}")
            else:
                self.logger.warning("⚠ No socat processes found running!")
        except Exception as e:
            self.logger.warning(f"Could not validate socat processes: {e}")

        self.logger.info("")

        # Validation: Check ip6tables SNAT rules
        self.logger.info("Validating ip6tables SNAT rules...")
        try:
            result = subprocess.run(
                [cfg.CMD_IP6TABLES, "-t", "nat", "-L", "POSTROUTING", "-n", "-v"],
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0:
                snat_lines = [
                    line
                    for line in result.stdout.split("\n")
                    if "SNAT" in line and lan_ip in line
                ]
                if snat_lines:
                    self.logger.info(
                        f"✓ Found {len(snat_lines)} SNAT rule(s) for {lan_ip}:"
                    )
                    for line in snat_lines:
                        self.logger.info(f"  {line.strip()}")
                else:
                    self.logger.warning(f"⚠ No SNAT rules found for {lan_ip}")
            else:
                self.logger.warning("⚠ Could not list ip6tables SNAT rules")
        except Exception as e:
            self.logger.warning(f"Could not validate SNAT rules: {e}")

        self.logger.info("=" * 70)
        self.logger.info("")

        time.sleep(1)  # Let socat stabilize

    def _stop_proxy(self, mac: str):
        """Stop all socat proxies and remove IPv6 SNAT rules"""
        self.logger.info("Stopping IPv6 proxies and cleaning up SNAT rules")

        # Remove IPv6 SNAT rules first
        if self.device and self.device.lan_ipv4:
            lan_ip = self.device.lan_ipv4
            for device_port in cfg.IPV6_PROXY_PORTS.values():
                try:
                    subprocess.run(
                        [
                            "ip6tables",
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-d",
                            lan_ip,
                            "-p",
                            "tcp",
                            "--dport",
                            str(device_port),
                            "-j",
                            "SNAT",
                            "--to-source",
                            cfg.LAN_GATEWAY_IP,
                        ],
                        capture_output=True,
                        timeout=2,
                    )
                    self.logger.info(
                        f"Removed IPv6 SNAT rule for {lan_ip}:{device_port}"
                    )
                except Exception as e:
                    self.logger.debug(
                        f"Failed to remove SNAT rule for port {device_port}: {e}"
                    )

        # Kill socat processes
        try:
            # Find socat processes
            result = subprocess.run(["ps", "-w"], capture_output=True, text=True)

            for line in result.stdout.splitlines():
                if "socat" in line and "TCP6-LISTEN" in line:
                    parts = line.split()
                    if parts:
                        pid = parts[0]
                        try:
                            subprocess.run(["kill", pid], timeout=2)
                            self.logger.info(f"Killed socat process {pid}")
                        except Exception:
                            pass

        except Exception as e:
            self.logger.warning(f"Error stopping proxies: {e}")

    def _wan_network_changed(self) -> bool:
        """
        Check if WAN network has changed.

        Returns True if:
        - IPv4 address changed
        - IPv6 address changed
        - IPv4/IPv6 appeared when it was missing before
        - IPv4/IPv6 disappeared
        """
        if not self.device:
            return False

        # Get current WAN IPs
        current_ipv4 = self._get_interface_ipv4(self.wan_interface)
        current_ipv6 = self._get_interface_ipv6(self.wan_interface)

        changed = False

        # IPv4 change detection
        if self.device.wan_ipv4:
            # We had IPv4 before
            if current_ipv4 != self.device.wan_ipv4:
                if current_ipv4:
                    self.logger.warning(
                        f"WAN IPv4 changed: {self.device.wan_ipv4} → {current_ipv4}"
                    )
                else:
                    self.logger.warning(f"WAN IPv4 lost: {self.device.wan_ipv4} → None")
                changed = True
        elif current_ipv4:
            # We didn't have IPv4 before, but now we do!
            self.logger.info(f"WAN IPv4 appeared: None → {current_ipv4}")
            changed = True

        # IPv6 change detection
        if self.device.wan_ipv6:
            # We had IPv6 before
            if current_ipv6 != self.device.wan_ipv6:
                if current_ipv6:
                    self.logger.warning(
                        f"WAN IPv6 changed: {self.device.wan_ipv6} → {current_ipv6}"
                    )
                else:
                    self.logger.warning(f"WAN IPv6 lost: {self.device.wan_ipv6} → None")
                changed = True
        elif current_ipv6:
            # We didn't have IPv6 before, but now we do!
            self.logger.info(f"WAN IPv6 appeared: None → {current_ipv6}")
            changed = True

        return changed

    def _get_interface_mac(self, interface: str) -> Optional[str]:
        """Get MAC address of interface"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "link", "show", interface],
                capture_output=True,
                text=True,
                check=True,
            )
            match = re.search(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", result.stdout, re.I)
            if match:
                return match.group(0).lower()
        except Exception as e:
            self.logger.error(f"Failed to get MAC for {interface}: {e}")
        return None

    def _set_interface_mac(self, interface: str, mac: str) -> bool:
        """Set MAC address of interface"""
        try:
            subprocess.run(
                [cfg.CMD_IP, "link", "set", interface, "down"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP, "link", "set", interface, "address", mac],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [cfg.CMD_IP, "link", "set", interface, "up"],
                check=True,
                capture_output=True,
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to set MAC for {interface}: {e}")
            return False

    def _get_interface_ipv4(self, interface: str) -> Optional[str]:
        """Get IPv4 address of interface"""
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "show", interface],
                capture_output=True,
                text=True,
                check=True,
            )
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def _get_interface_ipv6(self, interface: str) -> Optional[str]:
        """
        Get primary global IPv6 address of interface (not link-local)
        Returns the first non-link-local address found
        """
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "show", interface],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                match = re.search(r"inet6\s+([0-9a-f:]+)", line, re.I)
                if match:
                    addr = match.group(1)
                    # Skip link-local (fe80::)
                    if not addr.startswith("fe80"):
                        return addr
        except Exception:
            pass
        return None

    def _get_all_interface_ipv6(self, interface: str) -> list:
        """
        Get ALL global IPv6 addresses of interface (not link-local)
        Returns list of addresses (e.g., SLAAC, DHCPv6, privacy extensions)
        """
        addresses = []
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "show", interface],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                match = re.search(r"inet6\s+([0-9a-f:]+)", line, re.I)
                if match:
                    addr = match.group(1)
                    # Skip link-local (fe80::) but include all global addresses
                    if not addr.startswith("fe80"):
                        addresses.append(addr)
        except Exception as e:
            self.logger.debug(f"Error getting IPv6 addresses: {e}")

        return addresses

    def _is_slaac_address(self, ipv6_addr: str, mac: str) -> bool:
        """
        Check if IPv6 address is a SLAAC address (EUI-64 based on MAC)

        SLAAC addresses contain the MAC address in modified EUI-64 format.
        Example: MAC aa:bb:cc:dd:ee:ff becomes a8bb:ccff:fedd:eeff in IPv6

        Args:
            ipv6_addr: IPv6 address to check
            mac: Device MAC address

        Returns:
            True if address appears to be SLAAC-derived from MAC
        """
        try:
            # Convert MAC to EUI-64 format for comparison
            # MAC: aa:bb:cc:dd:ee:ff
            # EUI-64: aabb:ccff:fedd:eeff (with 7th bit flipped in first byte)
            mac_parts = mac.lower().split(":")
            if len(mac_parts) != 6:
                return False

            # Get last 4 bytes of IPv6 (last 64 bits contain EUI-64)
            ipv6_lower = ipv6_addr.lower()

            # Simple heuristic: SLAAC addresses are usually longer (not compressed)
            # and contain patterns from the MAC
            # DHCPv6 addresses are usually short (e.g., ::85c)

            # Check if address is very short (likely DHCPv6 or privacy extension)
            if ipv6_lower.count(":") <= 3:  # e.g., "::85c" has 2 colons
                return False

            # Check if MAC bytes appear in IPv6 address (partial match)
            # Convert MAC parts to hex string fragments
            mac_fragments = [mac_parts[i] + mac_parts[i + 1] for i in range(0, 6, 2)]

            # If any significant MAC fragment appears in IPv6, likely SLAAC
            for fragment in mac_fragments:
                if fragment in ipv6_lower.replace(":", ""):
                    return True

            return False

        except Exception as e:
            self.logger.debug(f"Error checking SLAAC address: {e}")
            return False

    def _select_primary_ipv6(self, addresses: list, mac: str) -> Optional[str]:
        """
        Select primary IPv6 address from list.

        Priority:
        1. SLAAC address (if available)
        2. DHCPv6 or other addresses

        Args:
            addresses: List of IPv6 addresses
            mac: Device MAC address

        Returns:
            Primary IPv6 address (SLAAC preferred, else first address)
        """
        if not addresses:
            return None

        # Find SLAAC addresses
        slaac_addresses = [
            addr for addr in addresses if self._is_slaac_address(addr, mac)
        ]

        if slaac_addresses:
            # Prefer SLAAC
            self.logger.info(f"Using SLAAC address: {slaac_addresses[0]}")
            return slaac_addresses[0]
        else:
            # Use first address (likely DHCPv6)
            self.logger.info(f"No SLAAC found, using DHCPv6/other: {addresses[0]}")
            return addresses[0]

    def _save_state(self):
        """Save device state to file"""
        if not self.device:
            return

        try:
            Path(cfg.STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
            with open(cfg.STATE_FILE, "w") as f:
                json.dump(self.device.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save state: {e}")

    def _load_state(self):
        """Load device state from file"""
        try:
            if os.path.exists(cfg.STATE_FILE):
                with open(cfg.STATE_FILE, "r") as f:
                    data = json.load(f)
                    self.device = Device(**data)
                    self.logger.info(
                        f"Loaded previous device state: {self.device.mac_address}"
                    )
        except Exception as e:
            self.logger.warning(f"Failed to load state: {e}")

    def _check_link_states(self):
        """
        Check for cable unplug/replug events on LAN and WAN interfaces.
        Triggers immediate discovery/reconfiguration on link state changes.
        """
        try:
            # Check WAN link state
            wan_link = self._get_link_state(self.wan_interface)
            if wan_link is not None:
                if self.wan_link_up is None:
                    # First check - just record state
                    self.wan_link_up = wan_link
                    status = "UP" if wan_link else "DOWN"
                    self.logger.info(
                        f"WAN ({self.wan_interface}) initial link state: {status}"
                    )
                elif self.wan_link_up != wan_link:
                    # Link state changed!
                    old_state = "UP" if self.wan_link_up else "DOWN"
                    new_state = "UP" if wan_link else "DOWN"
                    self.logger.warning(
                        f"🔌 WAN cable event: {old_state} → {new_state} on {self.wan_interface}"
                    )
                    self.wan_link_up = wan_link

                    if wan_link:
                        # Cable plugged back in - trigger WAN reconfiguration
                        if self.device and self.device.status == "configured":
                            self.logger.info(
                                "WAN cable reconnected - initiating fast reconfiguration..."
                            )
                            reconfig_thread = threading.Thread(
                                target=self._configure_device,
                                args=(
                                    self.device.mac_address,
                                    self.device.lan_ipv4,
                                    True,
                                ),
                                daemon=True,
                            )
                            reconfig_thread.start()
                    else:
                        # Cable unplugged
                        self.logger.warning(
                            "WAN cable unplugged - device will lose WAN connectivity"
                        )

            # Check LAN link state
            lan_link = self._get_link_state(self.lan_interface)
            if lan_link is not None:
                if self.lan_link_up is None:
                    # First check - just record state
                    self.lan_link_up = lan_link
                    status = "UP" if lan_link else "DOWN"
                    self.logger.info(
                        f"LAN ({self.lan_interface}) initial link state: {status}"
                    )
                elif self.lan_link_up != lan_link:
                    # Link state changed!
                    old_state = "UP" if self.lan_link_up else "DOWN"
                    new_state = "UP" if lan_link else "DOWN"
                    self.logger.warning(
                        f"🔌 LAN cable event: {old_state} → {new_state} on {self.lan_interface}"
                    )
                    self.lan_link_up = lan_link

                    if lan_link:
                        # Cable plugged back in - trigger device discovery
                        self.logger.info(
                            "LAN cable reconnected - running immediate device discovery..."
                        )
                        # Give device a moment to get DHCP
                        time.sleep(1)
                        device_info = self._discover_device()
                        if device_info:
                            mac, lan_ip = device_info
                            if not self.device or self.device.mac_address != mac:
                                self.logger.info(
                                    f"Device detected after LAN reconnect: {mac} at {lan_ip}"
                                )
                                config_thread = threading.Thread(
                                    target=self._configure_device,
                                    args=(mac, lan_ip),
                                    daemon=True,
                                )
                                config_thread.start()
                    else:
                        # Cable unplugged
                        if self.device:
                            self.logger.warning(
                                f"LAN cable unplugged - device {self.device.mac_address} will disconnect shortly"
                            )

        except Exception as e:
            self.logger.debug(f"Error checking link states: {e}")

    def _get_link_state(self, interface: str) -> Optional[bool]:
        """
        Get link state of interface (cable plugged in or not).

        Returns:
            True if link is up (cable connected)
            False if link is down (cable disconnected)
            None if unable to determine
        """
        try:
            result = subprocess.run(
                [cfg.CMD_IP, "link", "show", interface],
                capture_output=True,
                text=True,
                check=True,
                timeout=2,
            )

            # Check for state flags
            # Output contains: "state UP" or "state DOWN"
            if "state UP" in result.stdout:
                return True
            elif "state DOWN" in result.stdout:
                return False

            # Fallback: check for NO-CARRIER flag
            if "NO-CARRIER" in result.stdout:
                return False

            # Check for LOWER_UP flag (link layer is up)
            if "LOWER_UP" in result.stdout:
                return True

            return None

        except Exception as e:
            self.logger.debug(f"Failed to get link state for {interface}: {e}")
            return None

    def _cleanup_device(self):
        """Clean up when device disconnects"""
        if not self.device:
            return

        mac = self.device.mac_address
        self.logger.info(f"Cleaning up device {mac}")

        # Stop IPv6 proxy if running
        if self.device.wan_ipv6:
            self._stop_proxy(mac)

        # Remove port forwarding rules
        if self.device.wan_ipv4 and self.device.lan_ipv4:
            self._remove_port_forwarding(self.device.lan_ipv4, self.device.wan_ipv4)

        # Restore original WAN MAC
        if self.original_wan_mac:
            self.logger.info(f"Restoring original WAN MAC: {self.original_wan_mac}")
            self._set_interface_mac(self.wan_interface, self.original_wan_mac)

        # Clear device state
        self.device = None

        # Remove state file
        try:
            if os.path.exists(cfg.STATE_FILE):
                os.remove(cfg.STATE_FILE)
        except Exception as e:
            self.logger.warning(f"Failed to remove state file: {e}")

        self.logger.info("Device cleanup complete")

    def _remove_port_forwarding(self, lan_ip: str, wan_ip: str):
        """Remove IPv4 NAT port forwarding rules"""
        self.logger.info(f"Removing IPv4 port forwarding for {lan_ip}")

        for gateway_port, device_port in cfg.PORT_FORWARDS.items():
            try:
                # Remove DNAT rule
                subprocess.run(
                    [
                        cfg.CMD_IPTABLES,
                        "-t",
                        "nat",
                        "-D",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "-d",
                        wan_ip,
                        "--dport",
                        str(gateway_port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"{lan_ip}:{device_port}",
                    ],
                    capture_output=True,
                )

                # Remove FORWARD rule
                subprocess.run(
                    [
                        cfg.CMD_IPTABLES,
                        "-D",
                        "FORWARD",
                        "-p",
                        "tcp",
                        "-d",
                        lan_ip,
                        "--dport",
                        str(device_port),
                        "-j",
                        "ACCEPT",
                    ],
                    capture_output=True,
                )

                self.logger.debug(f"Removed port forward for {gateway_port}")

            except Exception as e:
                self.logger.debug(f"Error removing port forward {gateway_port}: {e}")

    def _print_status(self):
        """Print current status"""
        if not self.device:
            print("\n" + "=" * 60)
            print("NO DEVICE CONFIGURED")
            print("=" * 60)
            return

        print("\n" + "=" * 60)
        print("DEVICE STATUS")
        print("=" * 60)
        print(f"MAC:       {self.device.mac_address}")
        print(f"LAN IPv4:  {self.device.lan_ipv4 or 'N/A'}")
        print(f"WAN IPv4:  {self.device.wan_ipv4 or 'N/A'}")
        print(f"WAN IPv6:  {self.device.wan_ipv6 or 'N/A'}")
        print(f"Status:    {self.device.status}")
        print(f"Updated:   {self.device.last_updated}")
        print("=" * 60)

        if self.device.wan_ipv4:
            print("\nAccess device via IPv4:")
            for gw_port, dev_port in cfg.PORT_FORWARDS.items():
                print(f"  {self.device.wan_ipv4}:{gw_port} → device:{dev_port}")

        if self.device.wan_ipv6:
            print("\nAccess device via IPv6:")
            for port in cfg.IPV6_PROXY_PORTS.keys():
                print(f"  [{self.device.wan_ipv6}]:{port} → device:{port}")

        print()


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("Simple Single-Device Gateway Starting")
    logger.info("=" * 60)

    gateway = SimpleGateway()

    if not gateway.initialize():
        logger.error("Failed to initialize gateway")
        sys.exit(1)

    gateway.start()


if __name__ == "__main__":
    main()
