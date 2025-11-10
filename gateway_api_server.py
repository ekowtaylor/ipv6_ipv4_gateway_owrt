#!/usr/bin/env python3
"""
REST API Server for IPv4↔IPv6 Gateway
Provides endpoints for monitoring, status, and device management
"""

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Any
import threading

logger = logging.getLogger('GatewayAPI')


class GatewayAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for gateway API"""

    # Class variable - will be set by server
    gateway_service = None

    def log_message(self, format, *args):
        """Override to use logger instead of stderr"""
        logger.debug(format % args)

    def send_json_response(self, data: Dict[Any, Any], status_code: int = 200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def send_error_response(self, message: str, status_code: int = 400):
        """Send error response"""
        self.send_json_response({'error': message}, status_code)

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_string = parse_qs(parsed_path.query)

        try:
            # Status endpoint
            if path == '/status':
                self.handle_status()

            # Devices endpoint
            elif path == '/devices':
                self.handle_devices(query_string)

            # Device detail endpoint
            elif path.startswith('/devices/'):
                mac = path.split('/')[-1]
                self.handle_device_detail(mac)

            # Health check
            elif path == '/health':
                self.send_json_response({'status': 'ok'})

            # API info
            elif path == '/':
                self.handle_root()

            else:
                self.send_error_response('Not found', 404)

        except Exception as e:
            logger.error(f"Error handling GET {path}: {e}")
            self.send_error_response(f'Internal error: {str(e)}', 500)

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body) if body else {}

            # Clear device cache (admin action)
            if path == '/admin/clear-cache':
                self.handle_clear_cache(data)

            # Export devices
            elif path == '/admin/export':
                self.handle_export()

            else:
                self.send_error_response('Not found', 404)

        except Exception as e:
            logger.error(f"Error handling POST {path}: {e}")
            self.send_error_response(f'Internal error: {str(e)}', 500)

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def handle_root(self):
        """Handle root endpoint - API info"""
        info = {
            'name': 'IPv4↔IPv6 Gateway API',
            'version': '1.0',
            'endpoints': {
                'GET /': 'This information',
                'GET /health': 'Health check',
                'GET /status': 'Gateway status and statistics',
                'GET /devices': 'List all devices (supports ?status=active|inactive|all)',
                'GET /devices/<mac>': 'Get specific device details',
                'POST /admin/export': 'Export all device mappings',
                'POST /admin/clear-cache': 'Clear device cache (requires confirmation)',
            }
        }
        self.send_json_response(info)

    def handle_status(self):
        """GET /status - Return gateway status"""
        if not self.gateway_service:
            self.send_error_response('Gateway service not available', 503)
            return

        status = self.gateway_service.get_status()
        self.send_json_response(status)

    def handle_devices(self, query_string: Dict[str, list]):
        """GET /devices - List devices with optional filtering"""
        if not self.gateway_service:
            self.send_error_response('Gateway service not available', 503)
            return

        # Get filter parameter
        status_filter = query_string.get('status', ['all'])[0].lower()

        devices = self.gateway_service.list_devices()

        # Filter by status
        if status_filter != 'all':
            devices = [d for d in devices if d.status == status_filter]

        device_list = [d.to_dict() for d in devices]

        self.send_json_response({
            'total': len(device_list),
            'devices': device_list
        })

    def handle_device_detail(self, mac: str):
        """GET /devices/<mac> - Get specific device"""
        if not self.gateway_service:
            self.send_error_response('Gateway service not available', 503)
            return

        device = self.gateway_service.get_device(mac)

        if not device:
            self.send_error_response(f'Device {mac} not found', 404)
            return

        self.send_json_response(device.to_dict())

    def handle_export(self):
        """POST /admin/export - Export all device mappings"""
        if not self.gateway_service:
            self.send_error_response('Gateway service not available', 503)
            return

        devices = self.gateway_service.list_devices()
        device_dict = {d.mac_address: d.to_dict() for d in devices}

        self.send_json_response({
            'exported_at': __import__('datetime').datetime.now().isoformat(),
            'device_count': len(devices),
            'devices': device_dict
        })

    def handle_clear_cache(self, data: Dict):
        """POST /admin/clear-cache - Clear device cache"""
        confirmation = data.get('confirm', False)

        if not confirmation:
            self.send_error_response('Confirmation required: send {"confirm": true}', 400)
            return

        # This would require implementing cache clearing in the service
        self.send_json_response({
            'message': 'Cache clear not yet implemented',
            'status': 'pending'
        })


class GatewayAPIServer:
    """API Server for gateway service"""

    def __init__(self, gateway_service, host: str = '127.0.0.1', port: int = 8080):
        self.gateway_service = gateway_service
        self.host = host
        self.port = port
        self.logger = logging.getLogger('GatewayAPIServer')
        self.server = None
        self.server_thread = None

    def start(self):
        """Start the API server"""
        # Set the gateway service on the handler class
        GatewayAPIHandler.gateway_service = self.gateway_service

        try:
            self.server = HTTPServer((self.host, self.port), GatewayAPIHandler)
            self.logger.info(f"API Server starting on {self.host}:{self.port}")

            # Run server in a thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            self.logger.info("API Server started successfully")

        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}")
            raise

    def stop(self):
        """Stop the API server"""
        if self.server:
            self.logger.info("Stopping API server...")
            self.server.shutdown()
            if self.server_thread:
                self.server_thread.join(timeout=5)
            self.logger.info("API server stopped")


def test_api_client():
    """Simple test client for the API"""
    import urllib.request
    import json

    base_url = 'http://127.0.0.1:8080'

    try:
        # Test health
        print("Testing /health endpoint...")
        response = urllib.request.urlopen(f'{base_url}/health')
        print(f"Response: {json.loads(response.read())}\n")

        # Test status
        print("Testing /status endpoint...")
        response = urllib.request.urlopen(f'{base_url}/status')
        data = json.loads(response.read())
        print(f"Gateway running: {data.get('running')}")
        print(f"Active devices: {data.get('active_devices')}\n")

        # Test devices list
        print("Testing /devices endpoint...")
        response = urllib.request.urlopen(f'{base_url}/devices')
        data = json.loads(response.read())
        print(f"Total devices: {data.get('total')}\n")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    # Run test client
    test_api_client()