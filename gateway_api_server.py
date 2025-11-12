#!/usr/bin/env python3
"""
REST API Server for IPv4↔IPv6 Gateway
Provides endpoints for monitoring, status, and device management
"""

import json
import logging
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("GatewayAPI")


class GatewayAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for gateway API"""

    # Class variable - will be set by server
    gateway_service: Any = None

    # ------------- Core HTTP helpers -------------

    def log_message(self, format_str: str, *args) -> None:
        """
        Override to use logger instead of stderr.
        (Keep signature compatible with BaseHTTPRequestHandler.log_message)
        """
        logger.debug(format_str % args)

    def send_json_response(self, data: Dict[Any, Any], status_code: int = 200) -> None:
        """Send JSON response with CORS headers"""
        response_bytes = json.dumps(data, indent=2).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_bytes)

    def send_error_response(self, message: str, status_code: int = 400) -> None:
        """Send error response as JSON"""
        payload = {"error": message}
        self.send_json_response(payload, status_code)

    # ------------- HTTP verbs -------------

    def do_HEAD(self) -> None:
        """Basic HEAD handler (useful for some health checks)"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path in ("/", "/health", "/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_string = parse_qs(parsed_path.query)

        try:
            # Status endpoint
            if path == "/status":
                self.handle_status()

            # Devices endpoint
            elif path == "/devices":
                self.handle_devices(query_string)

            # Device detail endpoint
            elif path.startswith("/devices/"):
                mac = path.split("/")[-1]
                self.handle_device_detail(mac)

            # Health check
            elif path == "/health":
                self.handle_health()

            # API info
            elif path == "/":
                self.handle_root()

            else:
                self.send_error_response("Not found", 404)

        except Exception as e:
            logger.error("Error handling GET %s: %s", path, e, exc_info=True)
            self.send_error_response(f"Internal error: {str(e)}", 500)

    def do_POST(self) -> None:
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""
            data: Dict[str, Any] = {}

            if body:
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON payload on %s: %r", path, body[:200])
                    self.send_error_response("Invalid JSON payload", 400)
                    return

            # Clear device cache (admin action)
            if path == "/admin/clear-cache":
                self.handle_clear_cache(data)

            # Export devices
            elif path == "/admin/export":
                self.handle_export()

            else:
                self.send_error_response("Not found", 404)

        except Exception as e:
            logger.error("Error handling POST %s: %s", path, e, exc_info=True)
            self.send_error_response(f"Internal error: {str(e)}", 500)

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ------------- Route handlers -------------

    def handle_root(self) -> None:
        """GET / - API info"""
        info = {
            "name": "IPv4↔IPv6 Gateway API",
            "version": "1.0",
            "endpoints": {
                "GET /": "This information",
                "GET /health": "Health check with detailed metrics",
                "GET /status": "Gateway status and statistics",
                "GET /devices": "List all devices (supports ?status=active|inactive|all)",
                "GET /devices/<mac>": "Get specific device details",
                "POST /admin/export": "Export all device mappings",
                "POST /admin/clear-cache": "Clear device cache (requires confirmation)",
            },
        }
        self.send_json_response(info)

    def handle_status(self) -> None:
        """GET /status - Return gateway status"""
        if not self.gateway_service:
            self.send_error_response("Gateway service not available", 503)
            return

        status = self.gateway_service.get_status()
        self.send_json_response(status)

    def handle_health(self) -> None:
        """GET /health - Health check with detailed metrics"""
        if not self.gateway_service:
            self.send_error_response("Gateway service not available", 503)
            return

        health = self.gateway_service.get_health()
        self.send_json_response(health)

    def handle_devices(self, query_string: Dict[str, List[str]]) -> None:
        """GET /devices - List devices with optional filtering"""
        if not self.gateway_service:
            self.send_error_response("Gateway service not available", 503)
            return

        # Get filter parameter
        status_filter = query_string.get("status", ["all"])[0].lower()

        devices = self.gateway_service.list_devices()

        # Filter by status (expects device.status to be a string like 'active'/'inactive')
        if status_filter != "all":
            devices = [
                d for d in devices if getattr(d, "status", "").lower() == status_filter
            ]

        device_list = [d.to_dict() for d in devices]

        self.send_json_response(
            {
                "total": len(device_list),
                "devices": device_list,
            }
        )

    def handle_device_detail(self, mac: str) -> None:
        """GET /devices/<mac> - Get specific device"""
        if not self.gateway_service:
            self.send_error_response("Gateway service not available", 503)
            return

        device = self.gateway_service.get_device(mac)

        if not device:
            self.send_error_response(f"Device {mac} not found", 404)
            return

        self.send_json_response(device.to_dict())

    def handle_export(self) -> None:
        """Export all devices as JSON (for backup/restore)"""
        try:
            devices = self.gateway_service.list_devices()
            # CRITICAL FIX: Add error handling for device serialization
            try:
                device_dict = {d.mac_address: d.to_dict() for d in devices}
            except Exception as e:
                self.send_error_response(f"Failed to serialize devices: {e}", 500)
                return

            self.send_json_response({
                "exported_at": datetime.now().isoformat(),
                "device_count": len(devices),
                "devices": device_dict,
            })
        except Exception as e:
            self.send_error_response(f"Failed to export devices: {e}", 500)

    def handle_clear_cache(self, data: Dict[str, Any]) -> None:
        """POST /admin/clear-cache - Clear device cache"""
        if not self.gateway_service:
            self.send_error_response("Gateway service not available", 503)
            return

        confirmation = data.get("confirm", False)

        if not confirmation:
            self.send_error_response(
                'Confirmation required: send {"confirm": true}', 400
            )
            return

        # If the gateway service exposes a clear_cache() method, call it.
        clear_fn = getattr(self.gateway_service, "clear_cache", None)
        if callable(clear_fn):
            result = clear_fn()
            payload: Dict[str, Any] = {
                "message": "Cache cleared successfully",
                "status": "ok",
            }
            if isinstance(result, dict):
                payload.update(result)
            self.send_json_response(payload)
        else:
            # Fallback: not yet implemented by the service
            self.send_json_response(
                {
                    "message": "Cache clear not yet implemented on gateway service",
                    "status": "pending",
                }
            )


class GatewayAPIServer:
    """API Server for gateway service"""

    def __init__(self, gateway_service: Any, host: str = "127.0.0.1", port: int = 5050):
        self.gateway_service = gateway_service
        self.host = host
        self.port = port
        self.logger = logging.getLogger("GatewayAPIServer")
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the API server"""
        # Set the gateway service on the handler class
        GatewayAPIHandler.gateway_service = self.gateway_service

        try:
            self.server = HTTPServer((self.host, self.port), GatewayAPIHandler)
            self.logger.info("API Server starting on %s:%d", self.host, self.port)

            # Run server in a thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True,
            )
            self.server_thread.start()
            self.logger.info("API Server started successfully")

        except Exception as e:
            self.logger.error("Failed to start API server: %s", e, exc_info=True)
            raise

    def stop(self) -> None:
        """Stop the API server"""
        if self.server:
            self.logger.info("Stopping API server...")
            self.server.shutdown()
            if self.server_thread:
                self.server_thread.join(timeout=5)
            self.logger.info("API server stopped")


def test_api_client() -> None:
    """Simple test client for the API"""
    import urllib.request

    base_url = "http://127.0.0.1:5050"

    try:
        # Test health
        print("Testing /health endpoint...")
        response = urllib.request.urlopen(f"{base_url}/health", timeout=3)
        print(f"Response: {json.loads(response.read())}\n")

        # Test status
        print("Testing /status endpoint...")
        response = urllib.request.urlopen(f"{base_url}/status", timeout=3)
        data = json.loads(response.read())
        print(f"Gateway running: {data.get('running')}")
        print(f"Active devices: {data.get('active_devices')}\n")

        # Test devices list
        print("Testing /devices endpoint...")
        response = urllib.request.urlopen(f"{base_url}/devices", timeout=3)
        data = json.loads(response.read())
        print(f"Total devices: {data.get('total')}\n")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Run test client
    test_api_client()
