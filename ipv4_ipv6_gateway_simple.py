#!/usr/bin/env python3
"""
Simplified IPv4↔IPv6 Gateway Service - Single Device Mode
NanoPi R5C - Auto-discover ONE device and manage MAC spoofing + DHCP

Monitors for a single IPv4 device on eth1, discovers its MAC address,
spoofs it on eth0 to request DHCPv4 and DHCPv6, and maintains connectivity.

NO HTTP API SERVER - Use gateway-status-direct.sh and gateway-devices-direct.sh instead
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

import gateway_config as cfg

# Validate config before logging setup
cfg.validate_config()

# Configure logging
log_level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format=cfg.LOG_FORMAT,
    handlers=[logging.FileHandler(cfg.LOG_FILE)],
)

logger = logging.getLogger("SimpleGateway")


@dataclass
class Device:
    """Single device state"""
    mac_address: str
    ipv4_address: str  # LAN IPv4
    ipv4_wan_address: Optional[str] = None  # WAN IPv4
    ipv6_address: Optional[str] = None  # WAN IPv6
    discovered_at: str = ""
    status: str = "discovering"  # discovering, active, failed
    last_seen: str = ""


class SimpleGatewayService:
    """Simplified gateway for single device"""

    def __init__(self):
        self.logger = logging.getLogger("SimpleGateway")
        self.running = False
        self.device: Optional[Device] = None
        self.device_lock = threading.Lock()
        
        # Network interfaces
        self.eth0 = cfg.ETH0_INTERFACE  # WAN
        self.eth1 = cfg.ETH1_INTERFACE  # LAN
        
        # Device state file
        self.state_file = os.path.join(cfg.CONFIG_DIR, "current_device.json")
        
        # Original MAC (save once)
        self.original_mac_file = cfg.ORIGINAL_MAC_FILE
        self.original_mac = None
        
        # Threads
        self.monitor_thread = None
        self.discovery_thread = None

    def _run_command(self, cmd: str, timeout: int = 30) -> tuple:
        """Run shell command and return (success, output)"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {cmd}")
            return False, ""
        except Exception as e:
            self.logger.error(f"Command failed: {cmd} - {e}")
            return False, ""

    def _get_interface_mac(self, interface: str) -> Optional[str]:
        """Get MAC address of interface"""
        success, output = self._run_command(f"ip link show {interface}")
        if success:
            match = re.search(r"link/ether ([0-9a-f:]{17})", output)
            if match:
                return match.group(1)
        return None

    def _set_interface_mac(self, interface: str, mac: str) -> bool:
        """Set MAC address of interface"""
        self.logger.info(f"Setting {interface} MAC to {mac}")
        
        # Bring interface down
        success, _ = self._run_command(f"ip link set {interface} down")
        if not success:
            self.logger.error(f"Failed to bring down {interface}")
            return False
        
        # Set MAC
        success, _ = self._run_command(f"ip link set {interface} address {mac}")
        if not success:
            self.logger.error(f"Failed to set MAC on {interface}")
            return False
        
        # Bring interface up
        success, _ = self._run_command(f"ip link set {interface} up")
        if not success:
            self.logger.error(f"Failed to bring up {interface}")
            return False
        
        # Verify
        time.sleep(1)
        current_mac = self._get_interface_mac(interface)
        if current_mac == mac:
            self.logger.info(f"✓ Successfully set {interface} MAC to {mac}")
            return True
        else:
            self.logger.error(f"MAC verification failed: expected {mac}, got {current_mac}")
            return False

    def _save_original_mac(self):
        """Save original WAN MAC address"""
        if self.original_mac:
            return  # Already saved
        
        mac = self._get_interface_mac(self.eth0)
        if mac:
            try:
                os.makedirs(os.path.dirname(self.original_mac_file), exist_ok=True)
                with open(self.original_mac_file, "w") as f:
                    f.write(mac)
                self.original_mac = mac
                self.logger.info(f"Saved original WAN MAC: {mac}")
            except Exception as e:
                self.logger.error(f"Failed to save original MAC: {e}")

    def _restore_original_mac(self):
        """Restore original WAN MAC address"""
        if not self.original_mac:
            if os.path.exists(self.original_mac_file):
                with open(self.original_mac_file, "r") as f:
                    self.original_mac = f.read().strip()
        
        if self.original_mac:
            self.logger.info(f"Restoring original WAN MAC: {self.original_mac}")
            self._set_interface_mac(self.eth0, self.original_mac)

    def _request_dhcpv4(self, mac: str) -> Optional[str]:
        """Request DHCPv4 for device MAC"""
        self.logger.info(f"Requesting DHCPv4 for MAC: {mac}")
        
        for attempt in range(1, cfg.DHCPV4_RETRY_COUNT + 1):
            self.logger.debug(f"DHCPv4 attempt {attempt}/{cfg.DHCPV4_RETRY_COUNT}")
            
            # Kill any existing udhcpc
            subprocess.run("killall udhcpc 2>/dev/null", shell=True)
            time.sleep(1)
            
            # Request DHCP (removed -s /bin/true to actually apply IP)
            cmd = f"udhcpc -i {self.eth0} -t {cfg.DHCPV4_TIMEOUT} -n -q"
            success, output = self._run_command(cmd, timeout=cfg.DHCPV4_TIMEOUT + 5)
            
            if success:
                # Get IPv4 address assigned to eth0
                success, ip_output = self._run_command(f"ip -4 addr show {self.eth0}")
                if success:
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_output)
                    if match:
                        ipv4 = match.group(1)
                        self.logger.info(f"✓ Got DHCPv4: {ipv4} (attempt {attempt})")
                        return ipv4
            
            if attempt < cfg.DHCPV4_RETRY_COUNT:
                delay = cfg.DHCPV4_RETRY_DELAY * (2 ** (attempt - 1))  # Exponential backoff
                self.logger.debug(f"Retrying in {delay}s...")
                time.sleep(delay)
        
        self.logger.error(f"Failed to get DHCPv4 after {cfg.DHCPV4_RETRY_COUNT} attempts")
        return None

    def _request_dhcpv6(self, mac: str) -> Optional[str]:
        """Request DHCPv6 for device MAC"""
        self.logger.info(f"Requesting DHCPv6 for MAC: {mac}")
        
        # Enable IPv6 on interface
        subprocess.run(f"sysctl -w net.ipv6.conf.{self.eth0}.disable_ipv6=0", shell=True)
        subprocess.run(f"sysctl -w net.ipv6.conf.{self.eth0}.accept_ra=2", shell=True)
        subprocess.run(f"sysctl -w net.ipv6.conf.{self.eth0}.autoconf=1", shell=True)
        time.sleep(2)
        
        # Try SLAAC first
        self.logger.debug("Waiting for SLAAC...")
        time.sleep(3)
        
        success, output = self._run_command(f"ip -6 addr show {self.eth0}")
        if success:
            # Look for global IPv6 (not link-local fe80::)
            matches = re.findall(r"inet6 ([0-9a-f:]+)/\d+ scope global", output)
            if matches:
                ipv6 = matches[0]
                self.logger.info(f"✓ Got IPv6 via SLAAC: {ipv6}")
                return ipv6
        
        # Fall back to DHCPv6
        self.logger.debug("SLAAC failed, trying DHCPv6...")
        
        for attempt in range(1, cfg.DHCPV6_RETRY_COUNT + 1):
            self.logger.debug(f"DHCPv6 attempt {attempt}/{cfg.DHCPV6_RETRY_COUNT}")
            
            # Kill any existing odhcp6c
            subprocess.run("killall odhcp6c 2>/dev/null", shell=True)
            time.sleep(1)
            
            # Request DHCPv6
            cmd = f"odhcp6c -v -t {cfg.DHCPV6_TIMEOUT} -s /bin/true {self.eth0}"
            success, output = self._run_command(cmd, timeout=cfg.DHCPV6_TIMEOUT + 5)
            
            if success:
                # Check for IPv6 address
                success, ip_output = self._run_command(f"ip -6 addr show {self.eth0}")
                if success:
                    matches = re.findall(r"inet6 ([0-9a-f:]+)/\d+ scope global", ip_output)
                    if matches:
                        ipv6 = matches[0]
                        self.logger.info(f"✓ Got DHCPv6: {ipv6} (attempt {attempt})")
                        return ipv6
            
            if attempt < cfg.DHCPV6_RETRY_COUNT:
                delay = cfg.DHCPV6_RETRY_DELAY * (2 ** (attempt - 1))
                self.logger.debug(f"Retrying in {delay}s...")
                time.sleep(delay)
        
        self.logger.warning(f"Failed to get DHCPv6 after {cfg.DHCPV6_RETRY_COUNT} attempts")
        return None

    def _discover_device_arp(self) -> Optional[tuple]:
        """Discover device from ARP table - returns (mac, ip) or None"""
        success, output = self._run_command(f"ip neigh show dev {self.eth1}")
        if not success:
            return None
        
        # Parse ARP entries
        for line in output.split('\n'):
            match = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-f:]{17})", line)
            if match:
                ip, mac = match.group(1), match.group(2)
                # Skip gateway address
                if ip != cfg.ETH1_IP:
                    self.logger.info(f"Discovered device: MAC={mac}, IP={ip}")
                    return (mac, ip)
        
        return None

    def _configure_device(self, mac: str, lan_ip: str):
        """Configure device with DHCP on WAN"""
        with self.device_lock:
            if self.device and self.device.status == "active":
                self.logger.info("Device already configured, skipping")
                return
            
            # Create device object
            now = datetime.now().isoformat()
            self.device = Device(
                mac_address=mac,
                ipv4_address=lan_ip,
                discovered_at=now,
                last_seen=now,
                status="discovering"
            )
        
        self.logger.info(f"=" * 60)
        self.logger.info(f"Configuring device: {mac}")
        self.logger.info(f"=" * 60)
        
        # Save original MAC before spoofing
        self._save_original_mac()
        
        # Spoof MAC on WAN interface
        if not self._set_interface_mac(self.eth0, mac):
            self.logger.error("Failed to spoof MAC, aborting")
            with self.device_lock:
                self.device.status = "failed"
            self._save_device_state()
            return
        
        # Request DHCPv4
        ipv4_wan = self._request_dhcpv4(mac)
        if ipv4_wan:
            with self.device_lock:
                self.device.ipv4_wan_address = ipv4_wan
        else:
            self.logger.warning("DHCPv4 failed - device may not have IPv4 WAN access")
        
        # Request DHCPv6
        ipv6 = self._request_dhcpv6(mac)
        if ipv6:
            with self.device_lock:
                self.device.ipv6_address = ipv6
        else:
            self.logger.warning("DHCPv6 failed - device may not have IPv6 WAN access")
        
        # Mark as active if we got at least one address
        with self.device_lock:
            if self.device.ipv4_wan_address or self.device.ipv6_address:
                self.device.status = "active"
                self.logger.info(f"✓ Device configured successfully!")
                self.logger.info(f"  MAC: {mac}")
                self.logger.info(f"  LAN IPv4: {lan_ip}")
                if self.device.ipv4_wan_address:
                    self.logger.info(f"  WAN IPv4: {self.device.ipv4_wan_address}")
                if self.device.ipv6_address:
                    self.logger.info(f"  WAN IPv6: {self.device.ipv6_address}")
            else:
                self.device.status = "failed"
                self.logger.error("Failed to get any WAN address")
        
        self._save_device_state()

    def _save_device_state(self):
        """Save current device state to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with self.device_lock:
                if self.device:
                    with open(self.state_file, "w") as f:
                        json.dump(asdict(self.device), f, indent=2)
                    self.logger.debug(f"Saved device state to {self.state_file}")
        except Exception as e:
            self.logger.error(f"Failed to save device state: {e}")

    def _load_device_state(self):
        """Load device state from JSON file"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                with self.device_lock:
                    self.device = Device(**data)
                self.logger.info(f"Loaded device state: {self.device.mac_address}")
        except Exception as e:
            self.logger.error(f"Failed to load device state: {e}")

    def _monitor_loop(self):
        """Monitor for device connection"""
        self.logger.info("Starting device monitor...")
        
        while self.running:
            try:
                # Check if we already have an active device
                with self.device_lock:
                    if self.device and self.device.status == "active":
                        # Update last_seen
                        self.device.last_seen = datetime.now().isoformat()
                        self._save_device_state()
                        time.sleep(cfg.ARP_MONITOR_INTERVAL)
                        continue
                
                # Look for new device
                result = self._discover_device_arp()
                if result:
                    mac, lan_ip = result
                    
                    # Check if this is a new device or same device
                    with self.device_lock:
                        if self.device and self.device.mac_address == mac:
                            # Same device, already configured
                            self.device.last_seen = datetime.now().isoformat()
                            self._save_device_state()
                        else:
                            # New device - configure it
                            self.logger.info(f"New device detected: {mac}")
                            # Configure in separate thread to not block monitoring
                            self.discovery_thread = threading.Thread(
                                target=self._configure_device,
                                args=(mac, lan_ip),
                                daemon=True
                            )
                            self.discovery_thread.start()
                
                time.sleep(cfg.ARP_MONITOR_INTERVAL)
                
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}")
                time.sleep(cfg.ARP_MONITOR_INTERVAL)

    def initialize(self) -> bool:
        """Initialize the service"""
        self.logger.info("Initializing Simple Gateway Service...")
        
        # Verify interfaces exist
        for iface in [self.eth0, self.eth1]:
            success, _ = self._run_command(f"ip link show {iface}")
            if not success:
                self.logger.error(f"Interface {iface} not found!")
                return False
        
        # Load previous device state if exists
        self._load_device_state()
        
        self.logger.info("✓ Service initialized")
        return True

    def start(self):
        """Start the service"""
        if self.running:
            self.logger.warning("Service already running")
            return
        
        self.logger.info("Starting Simple Gateway Service...")
        self.running = True
        
        # Start monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("✓ Service started")

    def stop(self):
        """Stop the service"""
        if not self.running:
            return
        
        self.logger.info("Stopping Simple Gateway Service...")
        self.running = False
        
        # Wait for threads
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.discovery_thread:
            self.discovery_thread.join(timeout=5)
        
        # Restore original MAC
        self._restore_original_mac()
        
        # Save final state
        self._save_device_state()
        
        self.logger.info("✓ Service stopped")


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("Simple IPv4↔IPv6 Gateway Service Starting (Single Device)")
    logger.info("=" * 60)
    
    service = SimpleGatewayService()
    
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
