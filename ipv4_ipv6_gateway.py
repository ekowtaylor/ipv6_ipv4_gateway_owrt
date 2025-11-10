#!/usr/bin/env python3
"""
Dynamic IPv4↔IPv6 Gateway Service
NanoPi R5C - Plug-and-Play MAC Learning with DHCPv6 Discovery

Monitors IPv4 devices on eth0, discovers their MAC addresses,
spoofs them on eth1 to request DHCPv6, learns IPv6 assignments,
and maintains transparent IPv4↔IPv6 translation via 464XLAT.
"""

import sys
import json
import logging
import time
import threading
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
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
    """Represents an IPv4 device and its discovered IPv6 address"""
    mac_address: str
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
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


class ARPMonitor:
    """Monitors ARP table for new devices on eth0"""

    def __init__(self, interface: str):
        self.interface = interface
        self.logger = logging.getLogger("ARPMonitor")
        self.known_macs = set()

    def get_arp_entries(self) -> List[str]:
        """Get all MAC addresses in ARP table for this interface"""
        try:
            result = subprocess.run(
                [cfg.CMD_ARP, "-i", self.interface, "-n"],
                capture_output=True,
                text=True,
                check=True,
            )

            macs: List[str] = []
            for line in result.stdout.splitlines():
                match = re.search(
                    r"([0-9a-f]{2}:){5}([0-9a-f]{2})", line, re.IGNORECASE
                )
                if match:
                    mac = match.group(0).lower()
                    if mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                        macs.append(mac)

            return list(set(macs))
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

    def __init__(self, interface: str, timeout: int = cfg.DHCPV6_TIMEOUT):
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger("DHCPv6Manager")
        self.iface = NetworkInterface(interface)

    def request_ipv6_for_mac(self, mac: str) -> Optional[str]:
        """
        Spoof MAC on interface, request DHCPv6, return assigned IPv6 address.
        """
        self.logger.info(f"Requesting IPv6 for MAC: {mac}")

        original_mac = self.iface.get_mac_address()

        try:
            self.iface.flush_ipv6_addresses()

            if not self.iface.set_mac_address(mac):
                self.logger.error(f"Failed to spoof MAC {mac}")
                return None

            time.sleep(1)

            if not self._request_dhcpv6():
                self.logger.error(f"DHCPv6 request failed for MAC {mac}")
                return None

            time.sleep(2)
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

        self.arp_monitor = ARPMonitor(interface=cfg.ETH0_INTERFACE)
        self.dhcpv6_manager = DHCPv6Manager(interface=cfg.ETH1_INTERFACE)
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

    # ---- Public API used by REST layer ----

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
            if not self.firewall.allow_eth0_to_eth1(cfg.ETH0_INTERFACE, cfg.ETH1_INTERFACE):
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
                new_macs = self.arp_monitor.get_new_macs()

                for mac in new_macs:
                    with self._devices_lock:
                        if mac in self.devices:
                            continue
                        if len(self.devices) >= cfg.MAX_DEVICES:
                            self.logger.warning(
                                "Max devices reached (%d); ignoring new MAC %s",
                                cfg.MAX_DEVICES,
                                mac,
                            )
                            continue
                        device = DeviceMapping(mac_address=mac)
                        self.devices[mac] = device
                    self.logger.info("New device discovered: %s", mac)

                    thread = threading.Thread(
                        target=self._discover_ipv6_for_device,
                        args=(mac,),
                        daemon=True,
                    )
                    thread.start()

                time.sleep(cfg.ARP_MONITOR_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                time.sleep(5)

    def _discover_ipv6_for_device(self, mac: str) -> None:
        """Discover IPv6 address for a specific MAC"""
        try:
            with self._devices_lock:
                device = self.devices.get(mac)
                if not device:
                    return
                device.status = "discovering"

            ipv6 = self.dhcpv6_manager.request_ipv6_for_mac(mac)

            with self._devices_lock:
                device = self.devices.get(mac)
                if not device:
                    return

                if ipv6:
                    device.ipv6_address = ipv6
                    device.status = "active"
                    self.logger.info("Device %s → %s", mac, ipv6)
                else:
                    device.status = "failed"
                    self.logger.warning("Failed to discover IPv6 for %s", mac)

                self.device_store.add_device(device)

        except Exception as e:
            self.logger.error(f"Error discovering IPv6 for {mac}: {e}")
            with self._devices_lock:
                if mac in self.devices:
                    self.devices[mac].status = "error"

    def _monitoring_loop(self) -> None:
        """Monitor active devices and update status / timeouts"""
        self.logger.info("Monitoring loop started")
        timeout_delta = timedelta(seconds=cfg.DEVICE_STATUS_TIMEOUT)

        while self.running:
            try:
                current_arp = set(self.arp_monitor.get_arp_entries())
                now = datetime.now()

                with self._devices_lock:
                    for mac, device in self.devices.items():
                        if mac in current_arp:
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