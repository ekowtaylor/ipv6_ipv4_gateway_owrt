#!/usr/bin/env python3
"""
HAProxy Manager for IPv6→IPv4 Proxying
Production-grade alternative to socat for complex protocol handling
"""

import logging
import os
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, Optional

import gateway_config as cfg


class HAProxyManager:
    """
    Manages HAProxy-based IPv6→IPv4 proxying for devices.

    HAProxy is a production-grade TCP/HTTP proxy that:
    - Handles complex protocols better than socat
    - Provides detailed logging and statistics
    - Supports health checks and load balancing
    - More robust for production environments

    Example:
    IPv6 client → [gateway IPv6]:8080 → HAProxy → 192.168.1.128:80 → device
    """

    def __init__(self):
        self.logger = logging.getLogger("HAProxyManager")
        self.devices: Dict[str, Dict] = {}  # {mac: {"ipv4": "...", "ipv6": "...", "ports": {...}}}
        self._lock = threading.Lock()
        self.haproxy_process: Optional[subprocess.Popen] = None
        self.haproxy_log_file: Optional[object] = None  # Track log file handle
        self.config_file = cfg.HAPROXY_CONFIG_FILE

    def start_proxy_for_device(self, mac: str, device_ipv4: str, device_ipv6: str, port_map: Dict[int, int]) -> bool:
        """
        Add device to HAProxy configuration and reload.

        Args:
            mac: Device MAC address
            device_ipv4: Device's LAN IPv4 address (e.g., "192.168.1.128")
            device_ipv6: Device's WAN IPv6 address (e.g., "2620:10d:c050:100:46b7:d0ff:fea6:6dfc")
            port_map: Port mapping {gateway_port: device_port}

        Returns:
            True if proxy configuration updated successfully
        """
        self.logger.info(f"Adding IPv6→IPv4 HAProxy config for device {device_ipv4} (IPv6: {device_ipv6}, MAC: {mac})")

        with self._lock:
            # Store device config
            self.devices[mac] = {
                "ipv4": device_ipv4,
                "ipv6": device_ipv6,
                "ports": port_map
            }

            # Regenerate full HAProxy config
            if not self._generate_haproxy_config():
                self.logger.error("Failed to generate HAProxy configuration")
                return False

            # Reload HAProxy (or start if not running)
            if not self._reload_haproxy():
                self.logger.error("Failed to reload HAProxy")
                return False

            self.logger.info(
                f"HAProxy configuration updated with {len(port_map)} ports for {mac}"
            )
            return True

    def stop_proxies_for_device(self, mac: str) -> None:
        """Remove device from HAProxy configuration and reload"""
        with self._lock:
            if mac not in self.devices:
                return

            self.logger.info(f"Removing IPv6→IPv4 HAProxy config for {mac}")
            del self.devices[mac]

            # Regenerate config without this device
            self._generate_haproxy_config()
            self._reload_haproxy()

    def stop_all_proxies(self) -> None:
        """Stop HAProxy completely"""
        with self._lock:
            self.logger.info("Stopping HAProxy")

            if self.haproxy_process:
                try:
                    self.haproxy_process.terminate()
                    self.haproxy_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.haproxy_process.kill()
                    self.haproxy_process.wait()  # Wait after kill to prevent zombie
                except Exception as e:
                    self.logger.error(f"Error stopping HAProxy: {e}")

                self.haproxy_process = None

            # CRITICAL FIX: Close log file handle
            if self.haproxy_log_file:
                try:
                    self.haproxy_log_file.close()
                    self.haproxy_log_file = None
                except Exception as e:
                    self.logger.error(f"Error closing HAProxy log file: {e}")

            # Also try system service stop
            try:
                subprocess.run(
                    ["/etc/init.d/haproxy", "stop"],
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                pass

            self.devices.clear()

    def get_proxy_status(self, mac: Optional[str] = None) -> Dict:
        """Get status of HAProxy configuration"""
        with self._lock:
            if mac:
                if mac not in self.devices:
                    return {"mac": mac, "configured": False}
                return {
                    "mac": mac,
                    "configured": True,
                    "device_ip": self.devices[mac]["ipv4"],
                    "ports": self.devices[mac]["ports"],
                    "haproxy_running": self._is_haproxy_running()
                }
            else:
                return {
                    "devices": {
                        mac: {
                            "device_ip": info["ipv4"],
                            "ports": info["ports"]
                        }
                        for mac, info in self.devices.items()
                    },
                    "haproxy_running": self._is_haproxy_running()
                }

    def _generate_haproxy_config(self) -> bool:
        """Generate HAProxy configuration file for all devices"""
        try:
            # Ensure config directory exists
            config_dir = os.path.dirname(self.config_file)
            Path(config_dir).mkdir(parents=True, exist_ok=True)

            # Build configuration
            config = self._build_haproxy_config()

            # Write to file
            with open(self.config_file, 'w') as f:
                f.write(config)

            self.logger.debug(f"Generated HAProxy config: {self.config_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to generate HAProxy config: {e}")
            return False

    def _build_haproxy_config(self) -> str:
        """Build complete HAProxy configuration"""
        import ipaddress  # For IP validation

        lines = []

        # Global section
        lines.append("global")
        lines.append("    log stdout local0 debug")
        lines.append("    maxconn 2048")
        lines.append("    # daemon mode disabled - managed by our service")
        lines.append("    # Debug mode enabled for detailed connection logging")
        lines.append("")

        # Defaults section
        lines.append("defaults")
        lines.append("    mode tcp")
        lines.append("    log global")
        lines.append("    option tcplog")
        lines.append("    # Log everything - including null connections")
        lines.append("    # Enhanced logging with detailed connection info")
        lines.append("    log-format \"HAPROXY[%pid]: Client=%ci:%cp Frontend=%ft Backend=%b/%s ConnTime=%Tc/%Tw/%Tt Bytes=%B Status=%ts Counters=%ac/%fc/%bc/%sc/%rc Queues=%sq/%bq\"")
        lines.append("    timeout connect 5000ms")
        lines.append("    timeout client 50000ms")
        lines.append("    timeout server 50000ms")
        lines.append("")

        # Stats page (if enabled)
        if cfg.HAPROXY_STATS_ENABLE:
            lines.append("listen stats")
            lines.append(f"    bind *:{cfg.HAPROXY_STATS_PORT}")
            lines.append("    mode http")
            lines.append("    stats enable")
            lines.append(f"    stats uri {cfg.HAPROXY_STATS_URI}")
            lines.append("    stats refresh 10s")
            lines.append("    stats show-legends")
            lines.append("    stats show-node")
            lines.append("")

        # Frontend/backend for each device and port
        for mac, info in self.devices.items():
            device_ip = info["ipv4"]
            device_ipv6 = info["ipv6"]
            port_map = info["ports"]

            # CRITICAL FIX: Validate IP addresses to prevent config injection
            try:
                ipaddress.IPv4Address(device_ip)
                ipaddress.IPv6Address(device_ipv6)
            except ValueError as e:
                self.logger.error(f"Invalid IP address for device {mac}: IPv4={device_ip}, IPv6={device_ipv6}. Error: {e}")
                continue  # Skip this device

            # Sanitize MAC for use in names (replace : with _)
            safe_mac = mac.replace(":", "_")

            for gateway_port, device_port in port_map.items():
                # Determine service name for better identification
                service_name = self._get_service_name(device_port)
                frontend_name = f"ipv6_{service_name}_{safe_mac}_{gateway_port}"
                backend_name = f"ipv4_{service_name}_{safe_mac}"

                # Frontend (IPv6 listener) - BIND TO DEVICE-SPECIFIC IPv6 ADDRESS
                lines.append(f"frontend {frontend_name}")
                lines.append(f"    bind [{device_ipv6}]:{gateway_port} v6only")
                lines.append(f"    # Device IPv6: {device_ipv6}:{gateway_port} → IPv4: {device_ip}:{device_port}")
                lines.append(f"    # MAC: {mac}")
                lines.append(f"    default_backend {backend_name}")
                lines.append("")

                # Backend (IPv4 target)
                lines.append(f"backend {backend_name}")
                lines.append(f"    # Target device: {device_ip}:{device_port} (MAC: {mac})")
                lines.append(f"    # Health checks disabled - allow connections even if device is slow/down")
                lines.append(f"    # Increased timeouts for slow devices")
                lines.append(f"    timeout connect 10s")
                lines.append(f"    timeout server 300s")
                lines.append(f"    # Source from LAN interface for proper routing")
                lines.append(f"    source 192.168.1.1")
                lines.append(f"    server device_{safe_mac} {device_ip}:{device_port}")
                lines.append("")

        return "\n".join(lines)

    def _get_service_name(self, port: int) -> str:
        """Get service name for a port number"""
        port_names = {
            80: "http",
            443: "https",
            23: "telnet",
            22: "ssh",
            5900: "vnc",
            3389: "rdp"
        }
        return port_names.get(port, f"port{port}")

    def _reload_haproxy(self) -> bool:
        """Reload HAProxy with new configuration"""
        try:
            # Test configuration first
            test_result = subprocess.run(
                ["haproxy", "-c", "-f", self.config_file],
                capture_output=True,
                text=True
            )

            if test_result.returncode != 0:
                self.logger.error(f"HAProxy config test failed: {test_result.stderr}")
                return False

            # Wait for IPv6 DAD (Duplicate Address Detection) to complete
            # This ensures IPv6 addresses are fully usable before binding
            self.logger.info("Waiting 3 seconds for IPv6 DAD to complete...")
            time.sleep(3)

            # Kill any existing HAProxy processes first
            self._kill_all_haproxy_processes()

            # Start HAProxy directly with output capture
            self.logger.info("Starting HAProxy with configuration...")

            # CRITICAL FIX: Ensure log path exists and handle errors
            log_path = Path(cfg.LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                log_file = open(log_path, "a")
            except IOError as e:
                self.logger.error(f"Cannot open log file {log_path}: {e}")
                # Fallback to /dev/null
                log_file = open("/dev/null", "a")

            # Close any previously open log file
            if self.haproxy_log_file:
                try:
                    self.haproxy_log_file.close()
                except Exception:
                    pass

            # Store log file handle for cleanup
            self.haproxy_log_file = log_file

            self.haproxy_process = subprocess.Popen(
                ["haproxy", "-f", self.config_file],
                stdout=log_file,
                stderr=subprocess.STDOUT,  # Merge stderr to stdout to catch bind errors
                start_new_session=True  # Detach from parent
            )

            # Wait a moment and check if it's still running
            time.sleep(2)

            if self.haproxy_process.poll() is not None:
                self.logger.error(f"HAProxy failed to start (exit code: {self.haproxy_process.returncode})")
                self.logger.error("Check /var/log/ipv4-ipv6-gateway.log for HAProxy errors")
                return False

            # Verify HAProxy is actually listening on the configured ports
            if not self._verify_haproxy_listening():
                self.logger.error("HAProxy started but is not listening on configured ports")
                self.logger.error("This usually means bind failed - check logs for 'Cannot bind' errors")
                return False

            self.logger.info(f"HAProxy started successfully (PID: {self.haproxy_process.pid})")
            return True

        except Exception as e:
            self.logger.error(f"Failed to reload HAProxy: {e}")
            return False

    def _kill_all_haproxy_processes(self) -> None:
        """Kill all existing HAProxy processes"""
        try:
            # Find all haproxy processes
            result = subprocess.run(
                ["ps", "-w"],
                capture_output=True,
                text=True
            )

            for line in result.stdout.splitlines():
                if "haproxy" in line and "grep" not in line:
                    # Extract PID (first column)
                    parts = line.split()
                    if parts:
                        try:
                            pid = int(parts[0])
                            self.logger.info(f"Killing existing HAProxy process (PID: {pid})")
                            subprocess.run(["kill", str(pid)], timeout=2)
                        except (ValueError, subprocess.TimeoutExpired):
                            pass

            # Give processes time to die
            time.sleep(1)

        except Exception as e:
            self.logger.warning(f"Error killing HAProxy processes: {e}")

    def _verify_haproxy_listening(self) -> bool:
        """Verify HAProxy is listening on configured ports"""
        try:
            # Get all listening ports from netstat
            result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True,
                text=True
            )

            # Check if haproxy is in the output
            haproxy_lines = [line for line in result.stdout.splitlines() if "haproxy" in line]

            if not haproxy_lines:
                self.logger.warning("HAProxy process exists but no listening sockets found")
                return False

            # Log what ports HAProxy is listening on
            self.logger.info("HAProxy listening sockets:")
            for line in haproxy_lines:
                self.logger.info(f"  {line.strip()}")

            return True

        except Exception as e:
            self.logger.warning(f"Could not verify HAProxy listening status: {e}")
            # Don't fail if we can't verify - process is running
            return True

    def _is_haproxy_running(self) -> bool:
        """Check if HAProxy is running"""
        try:
            # Check via ps
            result = subprocess.run(
                ["ps", "-w"],
                capture_output=True,
                text=True
            )
            return "haproxy" in result.stdout
        except Exception:
            return False
