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
        self.devices: Dict[str, Dict] = {}  # {mac: {"ipv4": "...", "ports": {...}}}
        self._lock = threading.Lock()
        self.haproxy_process: Optional[subprocess.Popen] = None
        self.config_file = cfg.HAPROXY_CONFIG_FILE

    def start_proxy_for_device(self, mac: str, device_ipv4: str, port_map: Dict[int, int]) -> bool:
        """
        Add device to HAProxy configuration and reload.

        Args:
            mac: Device MAC address
            device_ipv4: Device's LAN IPv4 address (e.g., "192.168.1.128")
            port_map: Port mapping {gateway_port: device_port}

        Returns:
            True if proxy configuration updated successfully
        """
        self.logger.info(f"Adding IPv6→IPv4 HAProxy config for device {device_ipv4} (MAC: {mac})")

        with self._lock:
            # Store device config
            self.devices[mac] = {
                "ipv4": device_ipv4,
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
                    self.haproxy_process.wait()
                except Exception as e:
                    self.logger.error(f"Error stopping HAProxy: {e}")

                self.haproxy_process = None

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
        lines = []

        # Global section
        lines.append("global")
        lines.append("    log stdout local0 " + cfg.HAPROXY_LOG_LEVEL)
        lines.append("    maxconn 2048")
        lines.append("    daemon")
        lines.append("")

        # Defaults section
        lines.append("defaults")
        lines.append("    mode tcp")
        lines.append("    log global")
        lines.append("    option tcplog")
        lines.append("    option dontlognull")
        lines.append("    # Enhanced logging - log every connection")
        lines.append("    log-format \"%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq\"")
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
            port_map = info["ports"]

            # Sanitize MAC for use in names (replace : with _)
            safe_mac = mac.replace(":", "_")

            for gateway_port, device_port in port_map.items():
                # Determine service name for better identification
                service_name = self._get_service_name(device_port)
                frontend_name = f"ipv6_{service_name}_{gateway_port}"
                backend_name = f"ipv4_{service_name}_{safe_mac}"

                # Frontend (IPv6 listener)
                lines.append(f"frontend {frontend_name}")
                lines.append(f"    bind :::{gateway_port} v6only")
                lines.append(f"    # Proxy: IPv6 clients → {device_ip}:{device_port}")
                lines.append(f"    default_backend {backend_name}")
                lines.append("")

                # Backend (IPv4 target)
                lines.append(f"backend {backend_name}")
                lines.append(f"    # Target device: {device_ip}:{device_port} (MAC: {mac})")
                lines.append(f"    server device_{safe_mac} {device_ip}:{device_port} check inter 5s fall 2 rise 1")
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

            # Try to reload using init script (graceful reload)
            reload_result = subprocess.run(
                ["/etc/init.d/haproxy", "reload"],
                capture_output=True,
                timeout=5
            )

            if reload_result.returncode == 0:
                self.logger.info("HAProxy reloaded successfully")
                return True

            # If reload failed, try restart
            self.logger.warning("HAProxy reload failed, attempting restart")
            restart_result = subprocess.run(
                ["/etc/init.d/haproxy", "restart"],
                capture_output=True,
                timeout=10
            )

            if restart_result.returncode == 0:
                self.logger.info("HAProxy restarted successfully")
                return True

            # Last resort: start haproxy directly
            self.logger.warning("HAProxy service management failed, starting directly")

            # Kill previous process if it exists
            if hasattr(self, 'haproxy_process') and self.haproxy_process and self.haproxy_process.poll() is None:
                self.logger.warning("Terminating previous HAProxy process...")
                self.haproxy_process.terminate()
                try:
                    self.haproxy_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.logger.error("HAProxy didn't stop gracefully, killing...")
                    self.haproxy_process.kill()
                    self.haproxy_process.wait()

            self.haproxy_process = subprocess.Popen(
                ["haproxy", "-f", self.config_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(1)
            if self.haproxy_process.poll() is None:
                self.logger.info("HAProxy started directly")
                return True

            self.logger.error("Failed to start HAProxy")
            return False

        except Exception as e:
            self.logger.error(f"Failed to reload HAProxy: {e}")
            return False

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
