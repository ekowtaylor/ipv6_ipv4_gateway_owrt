#!/usr/bin/env python3
"""
Tests and Example Usage for IPv4↔IPv6 Gateway Service
"""

import unittest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import sys
import os

# --- Import path setup -------------------------------------------------------

# Prefer local project root (repo layout), but fall back to /opt for installed deployment.
THIS_DIR = Path(__file__).resolve().parent
CANDIDATE_ROOTS = [
    THIS_DIR.parent,
    Path("/opt/ipv4-ipv6-gateway"),
]

for root in CANDIDATE_ROOTS:
    if root.exists() and str(root) not in sys.path:
        sys.path.insert(0, str(root))
        break

from ipv4_ipv6_gateway import (
    DeviceMapping,
    NetworkInterface,
    ARPMonitor,
    DHCPv6Manager,
    DeviceStore,
    GatewayService,
)


class TestDeviceMapping(unittest.TestCase):
    """Tests for DeviceMapping dataclass"""

    def test_device_creation(self):
        """Test creating a device mapping"""
        device = DeviceMapping(mac_address="aa:bb:cc:dd:ee:01")
        self.assertEqual(device.mac_address, "aa:bb:cc:dd:ee:01")
        self.assertEqual(device.status, "pending")
        self.assertIsNotNone(device.discovered_at)

    def test_device_to_dict(self):
        """Test serializing device to dict"""
        device = DeviceMapping(
            mac_address="aa:bb:cc:dd:ee:01",
            ipv6_address="fd00::1",
        )
        data = device.to_dict()
        self.assertIn("mac_address", data)
        self.assertIn("ipv6_address", data)
        self.assertEqual(data["mac_address"], "aa:bb:cc:dd:ee:01")

    def test_device_from_dict(self):
        """Test deserializing device from dict"""
        data = {
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ipv6_address": "fd00::1",
            "status": "active",
            "discovered_at": "2025-01-01T00:00:00",
            "last_seen": "2025-01-01T00:01:00",
        }
        device = DeviceMapping.from_dict(data)
        self.assertEqual(device.mac_address, "aa:bb:cc:dd:ee:01")
        self.assertEqual(device.ipv6_address, "fd00::1")


class TestNetworkInterface(unittest.TestCase):
    """Tests for NetworkInterface class"""

    @patch("subprocess.run")
    def test_get_mac_address(self, mock_run):
        """Test getting MAC address"""
        mock_run.return_value = MagicMock(
            stdout="link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff"
        )
        iface = NetworkInterface("eth0")
        mac = iface.get_mac_address()
        self.assertEqual(mac, "aa:bb:cc:dd:ee:01")

    @patch("subprocess.run")
    def test_set_mac_address(self, mock_run):
        """Test setting MAC address"""
        mock_run.return_value = MagicMock()
        iface = NetworkInterface("eth0")
        result = iface.set_mac_address("aa:bb:cc:dd:ee:02")
        self.assertTrue(result)
        mock_run.assert_called()

    @patch("subprocess.run")
    def test_is_up(self, mock_run):
        """Test checking if interface is up"""
        mock_run.return_value = MagicMock(stdout="... UP BROADCAST RUNNING ...")
        iface = NetworkInterface("eth0")
        self.assertTrue(iface.is_up())


class TestARPMonitor(unittest.TestCase):
    """Tests for ARPMonitor class"""

    @patch("subprocess.run")
    def test_get_arp_entries(self, mock_run):
        """Test getting ARP entries"""
        arp_output = """
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.2              ether   aa:bb:cc:dd:ee:01   C                     eth0
192.168.1.3              ether   aa:bb:cc:dd:ee:02   C                     eth0
        """
        mock_run.return_value = MagicMock(stdout=arp_output)
        monitor = ARPMonitor("eth0")
        macs = monitor.get_arp_entries()
        self.assertEqual(len(macs), 2)
        self.assertIn("aa:bb:cc:dd:ee:01", macs)
        self.assertIn("aa:bb:cc:dd:ee:02", macs)

    @patch("subprocess.run")
    def test_get_new_macs(self, mock_run):
        """Test detecting new MACs"""
        arp_output = """
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.2              ether   aa:bb:cc:dd:ee:01   C                     eth0
        """
        mock_run.return_value = MagicMock(stdout=arp_output)
        monitor = ARPMonitor("eth0")

        # First call - should detect as new
        new_macs = monitor.get_new_macs()
        self.assertEqual(len(new_macs), 1)
        self.assertEqual(new_macs[0], "aa:bb:cc:dd:ee:01")

        # Second call - should not detect as new
        new_macs = monitor.get_new_macs()
        self.assertEqual(len(new_macs), 0)


class TestDeviceStore(unittest.TestCase):
    """Tests for DeviceStore class"""

    def setUp(self):
        """Create temporary directory for test"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory"""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_save_and_load_devices(self):
        """Test saving and loading devices"""
        store = DeviceStore(self.temp_dir)

        # Create device
        device = DeviceMapping(
            mac_address="aa:bb:cc:dd:ee:01",
            ipv6_address="fd00::1",
        )

        # Save
        devices = {"aa:bb:cc:dd:ee:01": device}
        store.save_devices(devices)

        # Load
        loaded = store.load_devices()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(
            loaded["aa:bb:cc:dd:ee:01"].mac_address, "aa:bb:cc:dd:ee:01"
        )

    def test_add_device(self):
        """Test adding a device"""
        store = DeviceStore(self.temp_dir)

        device = DeviceMapping(mac_address="aa:bb:cc:dd:ee:01")
        store.add_device(device)

        # Verify it was saved
        loaded = store.load_devices()
        self.assertIn("aa:bb:cc:dd:ee:01", loaded)


class TestGatewayService(unittest.TestCase):
    """Tests for GatewayService class"""

    def setUp(self):
        """Create temporary directory for test"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up"""
        import shutil

        shutil.rmtree(self.temp_dir)

    @patch("ipv4_ipv6_gateway.ARPMonitor")
    @patch("ipv4_ipv6_gateway.DHCPv6Manager")
    @patch("ipv4_ipv6_gateway.NetworkInterface")
    def test_service_initialization(self, mock_iface, mock_dhcp, mock_arp):
        """Test service initialization basic structure"""
        # Setup mocks
        mock_iface.return_value.is_up.return_value = True

        service = GatewayService(self.temp_dir)

        self.assertIsNotNone(service.devices)
        self.assertFalse(service.running)
        self.assertIsNotNone(service.arp_monitor)
        self.assertIsNotNone(service.dhcpv6_manager)
        self.assertIsNotNone(service.device_store)


class ExampleUsage:
    """Examples of using the gateway service"""

    @staticmethod
    def _urlopen(url: str, method: str = "GET", timeout: int = 3):
        """Helper wrapper around urllib.request.urlopen with timeout."""
        import urllib.request

        if method == "GET":
            req = urllib.request.Request(url, method="GET")
        else:
            req = urllib.request.Request(url, method=method)
        return urllib.request.urlopen(req, timeout=timeout)

    @staticmethod
    def example_1_basic_status():
        """Example: Get gateway status via API"""
        import json

        print("=" * 60)
        print("Example 1: Get Gateway Status")
        print("=" * 60)

        url = "http://127.0.0.1:8080/status"

        try:
            response = ExampleUsage._urlopen(url)
            data = json.loads(response.read())

            print(f"Gateway Running: {data.get('running')}")
            print(f"Total Devices: {data.get('device_count')}")
            print(f"Active Devices: {data.get('active_devices')}")
            print(f"eth0 Status: {'UP' if data.get('eth0_up') else 'DOWN'}")
            print(f"eth1 Status: {'UP' if data.get('eth1_up') else 'DOWN'}")

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def example_2_list_devices():
        """Example: List all devices"""
        import json

        print("\n" + "=" * 60)
        print("Example 2: List All Devices")
        print("=" * 60)

        url = "http://127.0.0.1:8080/devices"

        try:
            response = ExampleUsage._urlopen(url)
            data = json.loads(response.read())

            print(f"Total Devices: {data.get('total')}\n")

            for device in data.get("devices", []):
                print(f"MAC: {device['mac_address']}")
                print(f"  IPv4: {device.get('ipv4_address', 'N/A')}")
                print(f"  IPv6: {device.get('ipv6_address', 'N/A')}")
                print(f"  Status: {device['status']}")
                print(f"  Discovered: {device['discovered_at']}")
                print(f"  Last Seen: {device['last_seen']}")
                print()

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def example_3_filter_devices():
        """Example: List only active devices"""
        import json

        print("\n" + "=" * 60)
        print("Example 3: List Active Devices Only")
        print("=" * 60)

        url = "http://127.0.0.1:8080/devices?status=active"

        try:
            response = ExampleUsage._urlopen(url)
            data = json.loads(response.read())

            print(f"Active Devices: {data.get('total')}\n")

            for device in data.get("devices", []):
                mac = device["mac_address"]
                ipv6 = device.get("ipv6_address", "N/A")
                print(f"{mac} → {ipv6}")

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def example_4_device_detail():
        """Example: Get specific device details"""
        import json

        print("\n" + "=" * 60)
        print("Example 4: Get Specific Device Details")
        print("=" * 60)

        mac = "aa:bb:cc:dd:ee:01"
        url = f"http://127.0.0.1:8080/devices/{mac}"

        try:
            response = ExampleUsage._urlopen(url)
            device = json.loads(response.read())
            print(json.dumps(device, indent=2))
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def example_5_export_devices():
        """Example: Export all device mappings"""
        import json

        print("\n" + "=" * 60)
        print("Example 5: Export All Devices")
        print("=" * 60)

        url = "http://127.0.0.1:8080/admin/export"

        try:
            response = ExampleUsage._urlopen(url, method="POST")
            data = json.loads(response.read())

            print(f"Exported {data.get('device_count')} devices")
            print(f"Export Time: {data.get('exported_at')}\n")

            for mac, device in list(data.get("devices", {}).items())[:3]:
                print(f"{mac}:")
                print(f"  IPv6: {device.get('ipv6_address')}")
                print(f"  Status: {device.get('status')}")

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def example_6_monitoring_loop():
        """Example: Continuous monitoring"""
        import json

        print("\n" + "=" * 60)
        print("Example 6: Continuous Monitoring")
        print("=" * 60)

        url = "http://127.0.0.1:8080/status"

        try:
            for i in range(5):  # Monitor for 5 iterations
                response = ExampleUsage._urlopen(url)
                data = json.loads(response.read())

                # Clear screen
                os.system("clear" if os.name != "nt" else "cls")

                print(f"IPv4↔IPv6 Gateway Monitor (Iteration {i + 1})")
                print("=" * 60)
                print(f"Time: {data.get('timestamp')}")
                print(f"Status: {'RUNNING' if data.get('running') else 'STOPPED'}")
                print(f"Total Devices: {data.get('device_count')}")
                print(f"Active Devices: {data.get('active_devices')}")
                print(f"eth0: {'UP' if data.get('eth0_up') else 'DOWN'}")
                print(f"eth1: {'UP' if data.get('eth1_up') else 'DOWN'}")
                print("\nPress Ctrl+C to stop monitoring")

                time.sleep(5)

        except KeyboardInterrupt:
            print("\nMonitoring stopped")
        except Exception as e:
            print(f"Error: {e}")


def run_tests():
    """Run unit tests"""
    print("\n" + "=" * 60)
    print("Running Unit Tests")
    print("=" * 60 + "\n")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDeviceMapping))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkInterface))
    suite.addTests(loader.loadTestsFromTestCase(TestARPMonitor))
    suite.addTests(loader.loadTestsFromTestCase(TestDeviceStore))
    suite.addTests(loader.loadTestsFromTestCase(TestGatewayService))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


def run_examples():
    """Run example usage"""
    print("\n" + "=" * 60)
    print("Example Usage - REST API Calls")
    print("=" * 60)
    print("\nMake sure the gateway service is running on http://127.0.0.1:8080\n")

    examples = ExampleUsage()

    try:
        examples.example_1_basic_status()
        examples.example_2_list_devices()
        examples.example_3_filter_devices()
        examples.example_4_device_detail()
        examples.example_5_export_devices()
        examples.example_6_monitoring_loop()
    except Exception as e:
        print(f"Error running examples: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Gateway Service Tests & Examples"
    )
    parser.add_argument("--tests", action="store_true", help="Run unit tests")
    parser.add_argument("--examples", action="store_true", help="Run example usage")
    parser.add_argument("--all", action="store_true", help="Run all tests and examples")

    args = parser.parse_args()

    if args.tests or args.all:
        success = run_tests()
        if not success:
            sys.exit(1)

    if args.examples or args.all:
        run_examples()

    if not any([args.tests, args.examples, args.all]):
        # Default: show help
        parser.print_help()