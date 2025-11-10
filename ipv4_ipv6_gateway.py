#!/usr/bin/env python3
"""
Dynamic IPv4↔IPv6 Gateway Service
NanoPi R5C - Plug-and-Play MAC Learning with DHCPv6 Discovery

Monitors IPv4 devices on eth0, discovers their MAC addresses,
spoofs them on eth1 to request DHCPv6, learns IPv6 assignments,
and maintains transparent IPv4↔IPv6 translation via 464XLAT.
"""

import os
import sys
import json
import logging
import time
import threading
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ipv4-ipv6-gateway.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class DeviceMapping:
    """Represents an IPv4 device and its discovered IPv6 address"""
    mac_address: str
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    discovered_at: str = None
    last_seen: str = None
    status: str = "pending"  # pending, discovering, active, inactive

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now().isoformat()
        if self.last_seen is None:
            self.last_seen = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'DeviceMapping':
        return cls(**data)


class NetworkInterface:
    """Wrapper for network interface operations"""

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.logger = logging.getLogger(f'NetworkInterface[{interface_name}]')

    def get_mac_address(self) -> Optional[str]:
        """Get current MAC address of interface"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            match = re.search(r'([0-9a-f]{2}:){5}([0-9a-f]{2})', result.stdout, re.IGNORECASE)
            if match:
                return match.group(0).lower()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get MAC: {e}")
        return None

    def set_mac_address(self, mac: str) -> bool:
        """Set MAC address on interface"""
        try:
            subprocess.run(
                ['ip', 'link', 'set', self.interface_name, 'address', mac],
                check=True,
                capture_output=True
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
                ['ip', 'link', 'show', self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            return 'UP' in result.stdout
        except subprocess.CalledProcessError:
            return False

    def bring_up(self) -> bool:
        """Bring interface up"""
        try:
            subprocess.run(
                ['ip', 'link', 'set', self.interface_name, 'up'],
                check=True,
                capture_output=True
            )
            self.logger.info(f"Brought {self.interface_name} up")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to bring up interface: {e}")
            return False

    def get_ipv6_addresses(self) -> List[str]:
        """Get all IPv6 addresses on interface"""
        try:
            result = subprocess.run(
                ['ip', '-6', 'addr', 'show', self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            # Extract inet6 addresses, exclude link-local (fe80::)
            addresses = []
            for line in result.stdout.split('\n'):
                match = re.search(r'inet6\s+([0-9a-f:]+)', line)
                if match:
                    addr = match.group(1)
                    if not addr.startswith('fe80:'):
                        addresses.append(addr)
            return addresses
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get IPv6 addresses: {e}")
            return []

    def flush_ipv6_addresses(self) -> bool:
        """Remove all IPv6 addresses from interface"""
        try:
            subprocess.run(
                ['ip', '-6', 'addr', 'flush', 'dev', self.interface_name],
                check=True,
                capture_output=True
            )
            self.logger.info(f"Flushed IPv6 addresses from {self.interface_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to flush IPv6 addresses: {e}")
            return False


class ARPMonitor:
    """Monitors ARP table for new devices on eth0"""

    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
        self.logger = logging.getLogger('ARPMonitor')
        self.known_macs = set()

    def get_arp_entries(self) -> List[str]:
        """Get all MAC addresses in ARP table for this interface"""
        try:
            result = subprocess.run(
                ['arp', '-i', self.interface, '-n'],
                capture_output=True,
                text=True,
                check=True
            )

            macs = []
            for line in result.stdout.split('\n'):
                # Extract MAC addresses (format: xx:xx:xx:xx:xx:xx)
                match = re.search(r'([0-9a-f]{2}:){5}([0-9a-f]{2})', line, re.IGNORECASE)
                if match:
                    mac = match.group(0).lower()
                    # Skip broadcast and multicast
                    if mac not in ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']:
                        macs.append(mac)

            return list(set(macs))  # Remove duplicates
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get ARP entries: {e}")
            return []

    def get_new_macs(self) -> List[str]:
        """Get newly discovered MAC addresses since last call"""
        current_macs = set(self.get_arp_entries())
        new_macs = list(current_macs - self.known_macs)
        self.known_macs = current_macs

        if new_macs:
            self.logger.info(f"Discovered new MACs: {new_macs}")

        return new_macs


class DHCPv6Manager:
    """Manages DHCPv6 requests with MAC spoofing"""

    def __init__(self, interface: str = 'eth1', timeout: int = 10):
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger('DHCPv6Manager')
        self.iface = NetworkInterface(interface)

    def request_ipv6_for_mac(self, mac: str) -> Optional[str]:
        """
        Spoof MAC on eth1, request DHCPv6, return assigned IPv6 address

        Args:
            mac: MAC address to spoof

        Returns:
            IPv6 address if successful, None otherwise
        """
        self.logger.info(f"Requesting IPv6 for MAC: {mac}")

        # Save original MAC
        original_mac = self.iface.get_mac_address()

        try:
            # Flush existing IPv6 addresses
            self.iface.flush_ipv6_addresses()

            # Spoof MAC
            if not self.iface.set_mac_address(mac):
                self.logger.error(f"Failed to spoof MAC {mac}")
                return None

            time.sleep(1)  # Brief wait for MAC change to take effect

            # Request DHCPv6
            if not self._request_dhcpv6():
                self.logger.error(f"DHCPv6 request failed for MAC {mac}")
                return None

            # Get assigned IPv6 address
            time.sleep(2)  # Wait for address assignment
            addresses = self.iface.get_ipv6_addresses()

            if addresses:
                ipv6 = addresses[0]
                self.logger.info(f"Successfully obtained IPv6 {ipv6} for MAC {mac}")
                return ipv6
            else:
                self.logger.warning(f"No IPv6 address assigned for MAC {mac}")
                return None

        except Exception as e:
            self.logger.error(f"Exception during DHCPv6 request: {e}")
            return None
        finally:
            # Restore original MAC
            if original_mac:
                self.iface.set_mac_address(original_mac)

    def _request_dhcpv6(self) -> bool:
        """Execute DHCPv6 request using odhcp6c"""
        try:
            # Run odhcp6c with timeout
            process = subprocess.Popen(
                ['odhcp6c', '-P', '0', self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait for specified timeout then terminate
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()

            return True
        except Exception as e:
            self.logger.error(f"DHCPv6 request error: {e}")
            return False


class DeviceStore:
    """Persistent storage for device mappings"""

    def __init__(self, config_dir: str = '/etc/ipv4-ipv6-gateway'):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.devices_file = self.config_dir / 'devices.json'
        self.logger = logging.getLogger('DeviceStore')
        self._lock = threading.Lock()

    def load_devices(self) -> Dict[str, DeviceMapping]:
        """Load all device mappings from disk"""
        with self._lock:
            if not self.devices_file.exists():
                self.logger.info("No existing devices file, starting fresh")
                return {}

            try:
                with open(self.devices_file, 'r') as f:
                    data = json.load(f)
                    return {
                        mac: DeviceMapping.from_dict(device)
                        for mac, device in data.items()
                    }
            except Exception as e:
                self.logger.error(f"Failed to load devices: {e}")
                return {}

    def save_devices(self, devices: Dict[str, DeviceMapping]) -> bool:
        """Save device mappings to disk"""
        with self._lock:
            try:
                with open(self.devices_file, 'w') as f:
                    data = {mac: device.to_dict() for mac, device in devices.items()}
                    json.dump(data, f, indent=2)
                return True
            except Exception as e:
                self.logger.error(f"Failed to save devices: {e}")
                return False

    def add_device(self, device: DeviceMapping) -> bool:
        """Add or update a device mapping"""
        devices = self.load_devices()
        devices[device.mac_address] = device
        return self.save_devices(devices)


class FirewallManager:
    """Manages firewall rules for translation"""

    def __init__(self):
        self.logger = logging.getLogger('FirewallManager')

    def enable_forwarding(self) -> bool:
        """Enable IPv4 and IPv6 forwarding"""
        try:
            # IPv4 forwarding
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                check=True,
                capture_output=True
            )

            # IPv6 forwarding
            subprocess.run(
                ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'],
                check=True,
                capture_output=True
            )

            self.logger.info("Forwarding enabled")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to enable forwarding: {e}")
            return False

    def add_iptables_rule(self, rule_spec: List[str]) -> bool:
        """Add an iptables rule"""
        try:
            subprocess.run(
                ['iptables'] + rule_spec,
                check=True,
                capture_output=True
            )
            self.logger.debug(f"Added iptables rule: {' '.join(rule_spec)}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to add iptables rule: {e}")
            return False

    def allow_eth0_to_eth1(self) -> bool:
        """Allow traffic from eth0 to eth1 and vice versa"""
        rules = [
            ['-A', 'FORWARD', '-i', 'eth0', '-o', 'eth1', '-j', 'ACCEPT'],
            ['-A', 'FORWARD', '-i', 'eth1', '-o', 'eth0', '-j', 'ACCEPT'],
        ]

        for rule in rules:
            if not self.add_iptables_rule(rule):
                return False

        return True


class GatewayService:
    """Main gateway service orchestrating all components"""

    def __init__(self, config_dir: str = '/etc/ipv4-ipv6-gateway'):
        self.logger = logging.getLogger('GatewayService')
        self.config_dir = config_dir

        # Initialize components
        self.arp_monitor = ARPMonitor(interface='eth0')
        self.dhcpv6_manager = DHCPv6Manager(interface='eth1')
        self.device_store = DeviceStore(config_dir)
        self.firewall = FirewallManager()
        self.eth0 = NetworkInterface('eth0')
        self.eth1 = NetworkInterface('eth1')

        # State
        self.devices: Dict[str, DeviceMapping] = {}
        self.running = False
        self.discovery_thread = None
        self.monitor_thread = None

    def initialize(self) -> bool:
        """Initialize the gateway service"""
        self.logger.info("Initializing gateway service...")

        # Load existing devices
        self.devices = self.device_store.load_devices()
        self.logger.info(f"Loaded {len(self.devices)} existing device mappings")

        # Ensure interfaces are up
        if not self.eth0.is_up():
            self.logger.info("Bringing eth0 up...")
            self.eth0.bring_up()

        if not self.eth1.is_up():
            self.logger.info("Bringing eth1 up...")
            self.eth1.bring_up()

        # Enable forwarding
        if not self.firewall.enable_forwarding():
            self.logger.error("Failed to enable forwarding")
            return False

        # Allow eth0 ↔ eth1 traffic
        if not self.firewall.allow_eth0_to_eth1():
            self.logger.error("Failed to configure firewall rules")
            return False

        self.logger.info("Gateway service initialized successfully")
        return True

    def start(self):
        """Start the gateway service"""
        if self.running:
            self.logger.warning("Service already running")
            return

        self.running = True
        self.logger.info("Starting gateway service...")

        # Start discovery thread
        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.logger.info("Gateway service started")

    def stop(self):
        """Stop the gateway service"""
        self.running = False
        self.logger.info("Stopping gateway service...")

        if self.discovery_thread:
            self.discovery_thread.join(timeout=5)
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        # Save state
        self.device_store.save_devices(self.devices)

        self.logger.info("Gateway service stopped")

    def _discovery_loop(self):
        """Main loop: discover new MACs and request IPv6"""
        self.logger.info("Discovery loop started")

        while self.running:
            try:
                # Get newly discovered MACs
                new_macs = self.arp_monitor.get_new_macs()

                for mac in new_macs:
                    # Check if we already have this device
                    if mac not in self.devices:
                        device = DeviceMapping(mac_address=mac)
                        self.devices[mac] = device
                        self.logger.info(f"New device discovered: {mac}")

                        # Request IPv6 for this MAC in a separate thread
                        thread = threading.Thread(
                            target=self._discover_ipv6_for_device,
                            args=(mac,),
                            daemon=True
                        )
                        thread.start()

                time.sleep(10)  # Check for new devices every 10 seconds

            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                time.sleep(5)

    def _discover_ipv6_for_device(self, mac: str):
        """Discover IPv6 address for a specific MAC"""
        try:
            device = self.devices[mac]
            device.status = "discovering"

            # Request DHCPv6
            ipv6 = self.dhcpv6_manager.request_ipv6_for_mac(mac)

            if ipv6:
                device.ipv6_address = ipv6
                device.status = "active"
                self.logger.info(f"Device {mac} → {ipv6}")
            else:
                device.status = "failed"
                self.logger.warning(f"Failed to discover IPv6 for {mac}")

            # Save updated device
            self.device_store.add_device(device)

        except Exception as e:
            self.logger.error(f"Error discovering IPv6 for {mac}: {e}")
            if mac in self.devices:
                self.devices[mac].status = "error"

    def _monitoring_loop(self):
        """Monitor active devices and update status"""
        self.logger.info("Monitoring loop started")

        while self.running:
            try:
                current_arp = set(self.arp_monitor.get_arp_entries())
                current_time = datetime.now().isoformat()

                for mac, device in self.devices.items():
                    if mac in current_arp:
                        device.last_seen = current_time
                        if device.status == "pending":
                            device.status = "active"
                    else:
                        if device.status == "active":
                            device.status = "inactive"

                # Save state periodically
                self.device_store.save_devices(self.devices)

                time.sleep(30)  # Update status every 30 seconds

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

    def get_status(self) -> dict:
        """Get current gateway status"""
        return {
            'running': self.running,
            'devices': {mac: device.to_dict() for mac, device in self.devices.items()},
            'device_count': len(self.devices),
            'active_devices': sum(1 for d in self.devices.values() if d.status == 'active'),
            'eth0_up': self.eth0.is_up(),
            'eth1_up': self.eth1.is_up(),
            'timestamp': datetime.now().isoformat()
        }

    def get_device(self, mac: str) -> Optional[DeviceMapping]:
        """Get a specific device"""
        return self.devices.get(mac)

    def list_devices(self) -> List[DeviceMapping]:
        """List all devices"""
        return list(self.devices.values())


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("IPv4↔IPv6 Gateway Service Starting")
    logger.info("=" * 60)

    # Create service
    service = GatewayService()

    # Initialize
    if not service.initialize():
        logger.error("Failed to initialize service")
        sys.exit(1)

    # Start service
    service.start()

    # Keep running
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


if __name__ == '__main__':
    main()