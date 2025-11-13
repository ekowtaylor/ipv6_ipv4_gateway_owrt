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
    """Single device information"""

    mac_address: str
    lan_ipv4: Optional[str] = None  # LAN IP (192.168.1.x)
    wan_ipv4: Optional[str] = None  # WAN IPv4 from DHCP
    wan_ipv6: Optional[str] = None  # WAN IPv6 from DHCP/SLAAC
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
            self.device.wan_ipv6 = wan_ipv6
            self.logger.info(f"Got WAN IPv6: {wan_ipv6}")

        # Step 4: Setup port forwarding
        if wan_ipv4:
            self._setup_ipv4_port_forwarding(lan_ip, wan_ipv4)

        # Step 5: Setup IPv6 proxy (always, when IPv6 is available)
        # This allows IPv6 clients to access the device even on dual-stack networks
        if wan_ipv6:
            self._setup_ipv6_proxy(mac, lan_ip, wan_ipv6)

        # Mark as configured
        self.device.status = "configured"
        self.device.last_updated = datetime.now().isoformat()
        self._save_state()

        self.logger.info(f"Device {mac} configured successfully ({mode})")
        self._print_status()

    def _spoof_mac(self, mac: str, fast_mode: bool = False) -> bool:
        """
        Spoof MAC on WAN interface

        Args:
            mac: MAC address to spoof
            fast_mode: If True, use minimal wait time
        """
        self.logger.info(f"Spoofing WAN MAC to {mac}")

        try:
            # Step 1: Bring interface down
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.wan_interface, "down"],
                check=True,
                capture_output=True,
            )

            # Step 2: Flush ALL IPv6 addresses from interface (critical!)
            # This removes old SLAAC addresses generated from previous MAC
            subprocess.run(
                [cfg.CMD_IP, "-6", "addr", "flush", "dev", self.wan_interface],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Flushed old IPv6 addresses from {self.wan_interface}")

            # Step 3: Flush IPv4 addresses too
            subprocess.run(
                [cfg.CMD_IP, "-4", "addr", "flush", "dev", self.wan_interface],
                check=True,
                capture_output=True,
            )

            # Step 4: Set new MAC
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.wan_interface, "address", mac],
                check=True,
                capture_output=True,
            )
            self.logger.info(f"Set WAN MAC to {mac}")

            # Step 5: Bring interface up
            subprocess.run(
                [cfg.CMD_IP, "link", "set", self.wan_interface, "up"],
                check=True,
                capture_output=True,
            )

            # Wait for interface to come up and link negotiation
            # Fast mode: 0.5s (MAC already registered, just need link up)
            # Normal mode: 2s (wait for link negotiation + firewall registration)
            wait_time = 0.5 if fast_mode else 2
            self.logger.info(f"Waiting {wait_time}s for interface to come up...")
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

    def _setup_ipv4_port_forwarding(self, lan_ip: str, wan_ip: str):
        """Setup IPv4 NAT port forwarding"""
        self.logger.info(f"Setting up IPv4 port forwarding for {lan_ip}")

        for gateway_port, device_port in cfg.PORT_FORWARDS.items():
            try:
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
                        f"Port forward: {wan_ip}:{gateway_port} → {lan_ip}:{device_port}"
                    )

            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to setup port forward {gateway_port}: {e}")

    def _setup_ipv6_proxy(self, mac: str, lan_ip: str, wan_ipv6: str):
        """
        Setup IPv6→IPv4 proxy using socat with SNAT for return traffic

        SNAT ensures the device sees connections from the gateway (192.168.1.1)
        instead of random IPv6 addresses, which improves compatibility.
        """
        self.logger.info(f"Setting up IPv6→IPv4 proxy for {lan_ip}")

        # Kill existing socat processes for this device
        self._stop_proxy(mac)

        for ipv6_port, device_port in cfg.IPV6_PROXY_PORTS.items():
            try:
                # Add ip6tables SNAT rule for return traffic
                # This makes the device see requests from gateway IP (192.168.1.1)
                # instead of the IPv6 client's address

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
                except:
                    pass  # Rule doesn't exist yet

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
                    f"Added ip6tables SNAT rule for {lan_ip}:{device_port} (via {cfg.LAN_GATEWAY_IP})"
                )

                # Start socat in background
                # IPv6 client → [wan_ipv6]:ipv6_port → socat → lan_ip:device_port
                # Device sees traffic from 192.168.1.1 due to SNAT rule
                cmd = [
                    cfg.CMD_SOCAT,
                    f"TCP6-LISTEN:{ipv6_port},bind=[{wan_ipv6}],fork,reuseaddr",
                    f"TCP4:{lan_ip}:{device_port}",
                ]

                # Start in background
                subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )

                self.logger.info(
                    f"IPv6 proxy: [{wan_ipv6}]:{ipv6_port} → {lan_ip}:{device_port} (with SNAT)"
                )

            except subprocess.CalledProcessError as e:
                self.logger.warning(
                    f"Failed to setup IPv6 proxy on port {ipv6_port}: {e}"
                )
                self.logger.warning(
                    f"Hint: Install IPv6 NAT support with: opkg install kmod-ipt-nat6"
                )
            except Exception as e:
                self.logger.warning(
                    f"Error setting up IPv6 proxy on port {ipv6_port}: {e}"
                )

        time.sleep(1)  # Let socat start

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
        """Get global IPv6 address of interface (not link-local)"""
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
