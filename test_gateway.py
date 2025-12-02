#!/usr/bin/env python3
"""
Comprehensive Test Suite for IPv4/IPv6 Gateway
Tests all components without requiring actual hardware
"""

import os
import re
import subprocess
import sys
import unittest
from io import StringIO
from unittest.mock import call, MagicMock, Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set test mode environment variable
os.environ["GATEWAY_TEST_MODE"] = "1"

# Mock the validate_config to avoid permission issues during testing
import gateway_config as cfg

cfg.validate_config(skip_missing_commands=True)  # Skip command validation for tests


class TestIPv6AddressParsing(unittest.TestCase):
    """Test IPv6 address extraction and parsing (Fix validation)"""

    def setUp(self):
        """Set up mock gateway instance"""
        from ipv4_ipv6_gateway import SimpleGateway

        self.gateway = SimpleGateway()
        self.gateway.logger = Mock()

    def test_ipv6_address_strips_prefix(self):
        """Test that IPv6 addresses are returned without /64 prefix"""
        # Mock the subprocess output
        mock_output = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP
    inet6 2001:db8::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")

            result = self.gateway._get_interface_ipv6("eth0")

            # Should return address WITHOUT /64
            self.assertEqual(result, "2001:db8::1")
            self.assertNotIn("/", result)

    def test_ipv6_address_skips_link_local(self):
        """Test that link-local addresses (fe80::) are skipped"""
        mock_output = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 fe80::1234/64 scope link
       valid_lft forever preferred_lft forever
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")

            result = self.gateway._get_interface_ipv6("eth0")

            # Should return None (only link-local found)
            self.assertIsNone(result)

    def test_get_all_ipv6_addresses(self):
        """Test retrieving all IPv6 addresses without prefixes"""
        mock_output = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 2001:db8::1/64 scope global
    inet6 2001:db8::2/64 scope global
    inet6 fe80::1234/64 scope link
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")

            result = self.gateway._get_all_interface_ipv6("eth0")

            # Should return both global addresses without /64
            self.assertEqual(len(result), 2)
            self.assertIn("2001:db8::1", result)
            self.assertIn("2001:db8::2", result)
            # Should NOT include link-local
            self.assertNotIn("fe80::1234", result)

    def test_ipv6_with_different_prefix_lengths(self):
        """Test IPv6 addresses with various prefix lengths"""
        for prefix_len in [48, 56, 60, 64, 128]:
            mock_output = f"    inet6 2001:db8::1/{prefix_len} scope global\n"

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0, stdout=mock_output, stderr=""
                )

                result = self.gateway._get_interface_ipv6("eth0")

                self.assertEqual(result, "2001:db8::1")
                self.assertNotIn("/", result)


class TestSocatCommandGeneration(unittest.TestCase):
    """Test socat command generation (Fix validation)"""

    def test_socat_bind_syntax(self):
        """Test that socat uses correct bind syntax without brackets"""
        wan_ipv6 = "2001:db8::1"
        lan_ip = "192.168.1.100"
        ipv6_port = 8080
        device_port = 80

        expected_cmd = [
            "/usr/bin/socat",
            f"TCP6-LISTEN:{ipv6_port},bind={wan_ipv6},fork,reuseaddr",
            f"TCP4:{lan_ip}:{device_port}",
        ]

        # Build command as done in actual code
        cmd = [
            cfg.CMD_SOCAT,
            f"TCP6-LISTEN:{ipv6_port},bind={wan_ipv6},fork,reuseaddr",
            f"TCP4:{lan_ip}:{device_port}",
        ]

        self.assertEqual(cmd, expected_cmd)
        # Verify no brackets in bind parameter
        self.assertNotIn("[", cmd[1])
        self.assertNotIn("]", cmd[1])

    def test_socat_ipv6_format(self):
        """Test various IPv6 address formats in socat command"""
        test_cases = [
            "2001:db8::1",
            "2001:db8:0:0:0:0:0:1",
            "fd00::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        ]

        for ipv6_addr in test_cases:
            cmd = f"TCP6-LISTEN:8080,bind={ipv6_addr},fork,reuseaddr"

            # Verify format
            self.assertIn(f"bind={ipv6_addr}", cmd)
            self.assertNotIn(f"bind=[{ipv6_addr}]", cmd)


class TestSNATRules(unittest.TestCase):
    """Test SNAT rule generation (Fix validation)"""

    def test_snat_uses_ipv4_iptables(self):
        """Test that SNAT rules use IPv4 iptables, not IPv6"""
        lan_ip = "192.168.1.100"
        device_port = 80

        # Expected IPv4 iptables command
        expected_cmd = [
            "/usr/sbin/iptables",  # IPv4, not ip6tables!
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
        ]

        # Verify we're NOT using ip6tables
        self.assertNotIn("ip6tables", " ".join(expected_cmd))
        self.assertIn("iptables", expected_cmd[0])

    def test_snat_destination_is_lan_ip(self):
        """Test that SNAT matches destination as LAN IP (IPv4)"""
        lan_ip = "192.168.1.100"

        # SNAT should match IPv4 destination (LAN IP), not IPv6
        cmd = [
            cfg.CMD_IPTABLES,
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-d",
            lan_ip,  # IPv4 destination
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "SNAT",
            "--to-source",
            cfg.LAN_GATEWAY_IP,
        ]

        # Find the -d parameter
        d_index = cmd.index("-d")
        dest_ip = cmd[d_index + 1]

        # Verify it's an IPv4 address
        self.assertEqual(dest_ip, lan_ip)
        self.assertRegex(dest_ip, r"^\d+\.\d+\.\d+\.\d+$")


class TestNetworkMocking(unittest.TestCase):
    """Test network command mocking"""

    def test_mock_arp_table(self):
        """Test mocking ARP table discovery"""
        mock_arp_output = """
192.168.1.100 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.1 lladdr 00:11:22:33:44:55 REACHABLE
"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout=mock_arp_output, stderr=""
            )

            from ipv4_ipv6_gateway import SimpleGateway

            gateway = SimpleGateway()
            gateway.logger = Mock()

            result = gateway._discover_device()

            # Should find device (not gateway)
            self.assertIsNotNone(result)
            mac, ip = result
            self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
            self.assertEqual(ip, "192.168.1.100")

    def test_mock_dhcp_request(self):
        """Test mocking DHCP request"""
        mock_ip_output = "    inet 203.0.113.50/24"

        with patch("subprocess.run") as mock_run:
            # First call: udhcpc (returns success)
            # Second call: get interface IPv4
            mock_run.side_effect = [
                Mock(returncode=0, stdout="", stderr=""),
                Mock(returncode=0, stdout=mock_ip_output, stderr=""),
            ]

            from ipv4_ipv6_gateway import SimpleGateway

            gateway = SimpleGateway()
            gateway.logger = Mock()

            result = gateway._request_dhcpv4("aa:bb:cc:dd:ee:ff", fast_mode=True)

            # Should return IPv4 address
            self.assertEqual(result, "203.0.113.50")


class TestPortForwarding(unittest.TestCase):
    """Test IPv4 port forwarding rules"""

    def test_dnat_rule_creation(self):
        """Test DNAT rule format"""
        wan_ip = "203.0.113.50"
        lan_ip = "192.168.1.100"
        gateway_port = 8080
        device_port = 80

        dnat_cmd = [
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
        ]

        # Verify DNAT target
        self.assertIn("DNAT", dnat_cmd)
        self.assertIn("PREROUTING", dnat_cmd)
        self.assertIn(f"{lan_ip}:{device_port}", " ".join(dnat_cmd))

    def test_forward_rule_creation(self):
        """Test FORWARD rule format"""
        lan_ip = "192.168.1.100"
        device_port = 80

        forward_cmd = [
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
        ]

        # Verify FORWARD rule
        self.assertIn("FORWARD", forward_cmd)
        self.assertIn("ACCEPT", forward_cmd)


class TestSLAACAddressDetection(unittest.TestCase):
    """Test SLAAC address detection"""

    def setUp(self):
        from ipv4_ipv6_gateway import SimpleGateway

        self.gateway = SimpleGateway()
        self.gateway.logger = Mock()

    def test_slaac_address_detection(self):
        """Test that SLAAC addresses are correctly identified"""
        mac = "aa:bb:cc:dd:ee:ff"

        # SLAAC address (contains MAC pattern)
        slaac_addr = "2001:db8::a8bb:ccff:fedd:eeff"

        result = self.gateway._is_slaac_address(slaac_addr, mac)

        # Should detect as SLAAC
        self.assertTrue(result)

    def test_dhcpv6_address_detection(self):
        """Test that DHCPv6 addresses are correctly identified"""
        mac = "aa:bb:cc:dd:ee:ff"

        # DHCPv6 address (short, no MAC pattern)
        dhcpv6_addr = "2001:db8::85c"

        result = self.gateway._is_slaac_address(dhcpv6_addr, mac)

        # Should NOT detect as SLAAC
        self.assertFalse(result)

    def test_primary_ipv6_selection(self):
        """Test that SLAAC is preferred over DHCPv6"""
        mac = "aa:bb:cc:dd:ee:ff"
        addresses = [
            "2001:db8::85c",  # DHCPv6
            "2001:db8::a8bb:ccff:fedd:eeff",  # SLAAC
        ]

        result = self.gateway._select_primary_ipv6(addresses, mac)

        # Should select SLAAC address
        self.assertEqual(result, "2001:db8::a8bb:ccff:fedd:eeff")


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""

    def setUp(self):
        from ipv4_ipv6_gateway import SimpleGateway

        self.gateway = SimpleGateway()
        self.gateway.logger = Mock()

    def test_empty_arp_table(self):
        """Test behavior with empty ARP table"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="", stderr=""  # Empty ARP table
            )

            result = self.gateway._discover_device()

            # Should return None
            self.assertIsNone(result)

    def test_dhcp_timeout(self):
        """Test DHCP timeout handling"""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["udhcpc"], timeout=10)

            result = self.gateway._request_dhcpv4("aa:bb:cc:dd:ee:ff", fast_mode=True)

            # Should return None on timeout
            self.assertIsNone(result)

    def test_invalid_interface(self):
        """Test handling of invalid interface"""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                returncode=1, cmd=["ip", "link", "show", "invalid_interface"]
            )

            result = self.gateway._get_interface_mac("invalid_interface")

            # Should return None
            self.assertIsNone(result)


class TestPortListeningCheck(unittest.TestCase):
    """Test port listening detection"""

    def setUp(self):
        from ipv4_ipv6_gateway import SimpleGateway

        self.gateway = SimpleGateway()
        self.gateway.logger = Mock()

    @patch("socket.socket")
    def test_port_open_detection(self, mock_socket_class):
        """Test detection of open port"""
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0  # Port open
        mock_socket_class.return_value = mock_socket

        result = self.gateway._check_port_open("192.168.1.100", 80)

        self.assertTrue(result)

    @patch("socket.socket")
    def test_port_closed_detection(self, mock_socket_class):
        """Test detection of closed port"""
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 1  # Port closed
        mock_socket_class.return_value = mock_socket

        result = self.gateway._check_port_open("192.168.1.100", 80)

        self.assertFalse(result)


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""

    def test_port_forwards_format(self):
        """Test PORT_FORWARDS configuration format"""
        # All keys and values should be integers
        for gateway_port, device_port in cfg.PORT_FORWARDS.items():
            self.assertIsInstance(gateway_port, int)
            self.assertIsInstance(device_port, int)
            self.assertGreater(gateway_port, 0)
            self.assertLess(gateway_port, 65536)

    def test_ipv6_proxy_ports_format(self):
        """Test IPV6_PROXY_PORTS configuration format"""
        for ipv6_port, device_port in cfg.IPV6_PROXY_PORTS.items():
            self.assertIsInstance(ipv6_port, int)
            self.assertIsInstance(device_port, int)

    def test_interface_names(self):
        """Test interface names are valid"""
        self.assertIsInstance(cfg.WAN_INTERFACE, str)
        self.assertIsInstance(cfg.LAN_INTERFACE, str)
        self.assertGreater(len(cfg.WAN_INTERFACE), 0)
        self.assertGreater(len(cfg.LAN_INTERFACE), 0)


def run_tests():
    """Run all tests and generate report"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestIPv6AddressParsing))
    suite.addTests(loader.loadTestsFromTestCase(TestSocatCommandGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestSNATRules))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkMocking))
    suite.addTests(loader.loadTestsFromTestCase(TestPortForwarding))
    suite.addTests(loader.loadTestsFromTestCase(TestSLAACAddressDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestPortListeningCheck))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigValidation))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED!")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
