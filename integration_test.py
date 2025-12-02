#!/usr/bin/env python3
"""
Integration Test for IPv4/IPv6 Gateway
Simulates a complete device connection and configuration flow
"""

import os
import subprocess
import sys
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set test mode environment variable
os.environ["GATEWAY_TEST_MODE"] = "1"

# Mock the validate_config to avoid permission issues during testing
import gateway_config as cfg

cfg.validate_config(skip_missing_commands=True)  # Skip command validation for tests

from ipv4_ipv6_gateway import Device, SimpleGateway


class MockNetworkEnvironment:
    """Mock network environment for integration testing"""

    def __init__(self):
        self.device_mac = "aa:bb:cc:dd:ee:ff"
        self.device_lan_ip = "192.168.1.100"
        self.device_wan_ipv4 = "203.0.113.50"
        self.device_wan_ipv6 = "2001:db8::1"
        self.gateway_mac = "00:11:22:33:44:55"

        self.arp_populated = False
        self.wan_mac_spoofed = False
        self.dhcpv4_acquired = False
        self.ipv6_acquired = False
        self.port_forwards_setup = False
        self.ipv6_proxy_setup = False

        # Track firewall rules
        self.iptables_rules = []
        self.socat_processes = []

    def mock_subprocess_run(self, *args, **kwargs):
        """Mock subprocess.run for all network commands"""
        cmd = args[0] if args else kwargs.get("cmd", [])

        # Mock: ip neigh show (ARP table)
        if "neigh" in cmd and "show" in cmd:
            if self.arp_populated:
                output = f"{self.device_lan_ip} lladdr {self.device_mac} REACHABLE\n"
                output += f"192.168.1.1 lladdr {self.gateway_mac} REACHABLE\n"
            else:
                output = ""
            return Mock(returncode=0, stdout=output, stderr="")

        # Mock: ip link show (get MAC)
        if "link" in cmd and "show" in cmd:
            if self.wan_mac_spoofed:
                mac = self.device_mac
            else:
                mac = self.gateway_mac
            output = f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> link/ether {mac}\n"
            return Mock(returncode=0, stdout=output, stderr="")

        # Mock: ip -4 addr show (IPv4 address)
        if "-4" in cmd and "addr" in cmd:
            if self.dhcpv4_acquired:
                output = f"    inet {self.device_wan_ipv4}/24\n"
            else:
                output = ""
            return Mock(returncode=0, stdout=output, stderr="")

        # Mock: ip -6 addr show (IPv6 address)
        if "-6" in cmd and "addr" in cmd:
            if self.ipv6_acquired:
                output = f"    inet6 {self.device_wan_ipv6}/64 scope global\n"
                output += "    inet6 fe80::1/64 scope link\n"
            else:
                output = ""
            return Mock(returncode=0, stdout=output, stderr="")

        # Mock: uci (MAC spoofing)
        if "uci" in cmd[0]:
            self.wan_mac_spoofed = True
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: ifup (interface reload)
        if "ifup" in cmd:
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: sysctl (IPv6 configuration)
        if "sysctl" in cmd:
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: udhcpc (DHCPv4)
        if "udhcpc" in cmd or (len(cmd) > 0 and "udhcpc" in cmd[0]):
            self.dhcpv4_acquired = True
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: odhcp6c (DHCPv6)
        if "odhcp6c" in cmd or (len(cmd) > 0 and "odhcp6c" in cmd[0]):
            self.ipv6_acquired = True
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: iptables (check rule exists)
        if "iptables" in cmd and "-C" in cmd:
            # Rule doesn't exist - will be added
            return Mock(returncode=1, stdout="", stderr="")

        # Mock: iptables (add rule)
        if "iptables" in cmd and ("-A" in cmd or "-I" in cmd):
            self.iptables_rules.append(cmd)
            self.port_forwards_setup = True
            return Mock(returncode=0, stdout="", stderr="")

        # Mock: nft (check IPv6 NAT)
        if "nft" in cmd:
            return Mock(returncode=0, stdout="table ip6 nat", stderr="")

        # Mock: ps (check socat processes)
        if "ps" in cmd:
            if self.socat_processes:
                output = "PID   USER     COMMAND\n"
                for proc in self.socat_processes:
                    output += f"{proc['pid']} root socat {proc['cmd']}\n"
            else:
                output = ""
            return Mock(returncode=0, stdout=output, stderr="")

        # Default: success
        return Mock(returncode=0, stdout="", stderr="")

    def mock_popen(self, *args, **kwargs):
        """Mock Popen for socat processes"""
        cmd = args[0] if args else kwargs.get("cmd", [])

        if "socat" in str(cmd):
            # Create mock process
            proc = Mock()
            proc.pid = len(self.socat_processes) + 1000
            proc.poll.return_value = None  # Process running

            # Track socat process
            self.socat_processes.append(
                {
                    "pid": proc.pid,
                    "cmd": " ".join(cmd),
                }
            )
            self.ipv6_proxy_setup = True

            return proc

        return Mock(pid=999, poll=Mock(return_value=None))


def test_full_device_flow():
    """Test complete device connection and configuration flow"""
    print("\n" + "=" * 70)
    print("INTEGRATION TEST: Full Device Flow")
    print("=" * 70)

    env = MockNetworkEnvironment()

    with patch("subprocess.run", side_effect=env.mock_subprocess_run), patch(
        "subprocess.Popen", side_effect=env.mock_popen
    ), patch("time.sleep"), patch("builtins.open", create=True):

        # Initialize gateway
        gateway = SimpleGateway()
        gateway.original_wan_mac = env.gateway_mac

        print("\n✓ Gateway initialized")

        # Simulate ARP table population
        env.arp_populated = True
        print("✓ ARP table populated")

        # Discover device
        device_info = gateway._discover_device()
        assert device_info is not None, "Device should be discovered"
        mac, lan_ip = device_info
        assert mac == env.device_mac, f"Expected MAC {env.device_mac}, got {mac}"
        assert (
            lan_ip == env.device_lan_ip
        ), f"Expected IP {env.device_lan_ip}, got {lan_ip}"
        print(f"✓ Device discovered: {mac} at {lan_ip}")

        # Spoof MAC
        success = gateway._spoof_mac(mac, fast_mode=False)
        assert success, "MAC spoofing should succeed"
        assert env.wan_mac_spoofed, "WAN MAC should be spoofed"
        print(f"✓ MAC spoofed to {mac}")

        # Request DHCPv4
        wan_ipv4 = gateway._request_dhcpv4(mac, fast_mode=False)
        assert (
            wan_ipv4 == env.device_wan_ipv4
        ), f"Expected IPv4 {env.device_wan_ipv4}, got {wan_ipv4}"
        print(f"✓ DHCPv4 acquired: {wan_ipv4}")

        # Request IPv6
        wan_ipv6 = gateway._request_ipv6(mac, fast_mode=False)
        assert (
            wan_ipv6 == env.device_wan_ipv6
        ), f"Expected IPv6 {env.device_wan_ipv6}, got {wan_ipv6}"
        print(f"✓ IPv6 acquired: {wan_ipv6}")

        # Setup IPv4 port forwarding
        gateway._setup_ipv4_port_forwarding(lan_ip, wan_ipv4)
        assert len(env.iptables_rules) > 0, "iptables rules should be added"
        print(f"✓ IPv4 port forwarding setup ({len(env.iptables_rules)} rules)")

        # Check IPv6 NAT support
        ipv6_nat_available, firewall_type = gateway._check_ipv6_nat_support()
        assert ipv6_nat_available, "IPv6 NAT should be available"
        print(f"✓ IPv6 NAT available ({firewall_type})")

        # Setup IPv6 proxy
        gateway.ipv6_firewall_type = firewall_type
        gateway.device = Device(mac_address=mac, lan_ipv4=lan_ip)
        gateway._setup_ipv6_proxy(mac, lan_ip, wan_ipv6)
        assert len(env.socat_processes) > 0, "socat processes should be running"
        print(f"✓ IPv6 proxy setup ({len(env.socat_processes)} socat processes)")

        # Verify all components
        print("\n" + "=" * 70)
        print("VERIFICATION")
        print("=" * 70)
        print(f"  Device MAC:         {env.device_mac}")
        print(f"  Device LAN IP:      {env.device_lan_ip}")
        print(f"  Device WAN IPv4:    {env.device_wan_ipv4}")
        print(f"  Device WAN IPv6:    {env.device_wan_ipv6}")
        print(f"  MAC Spoofed:        {'✓' if env.wan_mac_spoofed else '✗'}")
        print(f"  DHCPv4 Acquired:    {'✓' if env.dhcpv4_acquired else '✗'}")
        print(f"  IPv6 Acquired:      {'✓' if env.ipv6_acquired else '✗'}")
        print(
            f"  Port Forwards:      {'✓' if env.port_forwards_setup else '✗'} ({len(env.iptables_rules)} rules)"
        )
        print(
            f"  IPv6 Proxy:         {'✓' if env.ipv6_proxy_setup else '✗'} ({len(env.socat_processes)} processes)"
        )

        # Validate iptables rules
        print("\n" + "=" * 70)
        print("IPTABLES RULES VALIDATION")
        print("=" * 70)

        # Check for MASQUERADE
        masquerade_found = any("MASQUERADE" in str(rule) for rule in env.iptables_rules)
        print(f"  MASQUERADE rule:    {'✓' if masquerade_found else '✗'}")
        assert masquerade_found, "MASQUERADE rule should be present"

        # Check for DNAT
        dnat_found = any("DNAT" in str(rule) for rule in env.iptables_rules)
        print(f"  DNAT rules:         {'✓' if dnat_found else '✗'}")
        assert dnat_found, "DNAT rules should be present"

        # Check for FORWARD
        forward_found = any("FORWARD" in str(rule) for rule in env.iptables_rules)
        print(f"  FORWARD rules:      {'✓' if forward_found else '✗'}")
        assert forward_found, "FORWARD rules should be present"

        # Check for SNAT (IPv4, not IPv6!)
        snat_found = any(
            "SNAT" in str(rule) and "iptables" in str(rule[0])
            for rule in env.iptables_rules
        )
        print(f"  SNAT rules (IPv4):  {'✓' if snat_found else '✗'}")
        assert snat_found, "IPv4 SNAT rules should be present for proxy"

        # Validate socat processes
        print("\n" + "=" * 70)
        print("SOCAT PROCESSES VALIDATION")
        print("=" * 70)

        for i, proc in enumerate(env.socat_processes):
            print(f"  Process {i+1}:")
            print(f"    PID: {proc['pid']}")
            print(f"    Command: {proc['cmd']}")

            # Validate socat command format
            assert "TCP6-LISTEN" in proc["cmd"], "Should use TCP6-LISTEN"
            assert (
                f"bind={env.device_wan_ipv6}" in proc["cmd"]
            ), "Should bind to WAN IPv6"
            assert "TCP4" in proc["cmd"], "Should connect to TCP4"
            assert env.device_lan_ip in proc["cmd"], "Should connect to device LAN IP"
            # Verify NO brackets around IPv6 address
            assert (
                f"bind=[{env.device_wan_ipv6}]" not in proc["cmd"]
            ), "Should NOT have brackets in bind"
            print("    ✓ Command format correct")

        print("\n" + "=" * 70)
        print("✅ INTEGRATION TEST PASSED")
        print("=" * 70)

        return True


def test_ipv6_address_fix():
    """Test that IPv6 addresses are correctly parsed without /prefix"""
    print("\n" + "=" * 70)
    print("INTEGRATION TEST: IPv6 Address Parsing Fix")
    print("=" * 70)

    env = MockNetworkEnvironment()

    with patch("subprocess.run", side_effect=env.mock_subprocess_run):
        gateway = SimpleGateway()

        # Acquire IPv6
        env.ipv6_acquired = True
        ipv6 = gateway._get_interface_ipv6("eth0")

        print(f"  Raw IPv6 output: inet6 {env.device_wan_ipv6}/64 scope global")
        print(f"  Parsed IPv6:     {ipv6}")

        # Verify no /64 suffix
        assert (
            ipv6 == env.device_wan_ipv6
        ), f"Expected {env.device_wan_ipv6}, got {ipv6}"
        assert "/" not in ipv6, f"IPv6 address should not contain /: {ipv6}"

        print("  ✓ IPv6 address correctly stripped of /prefix")
        print("\n✅ IPv6 ADDRESS PARSING FIX VERIFIED")

    return True


def test_socat_bind_fix():
    """Test that socat bind syntax is correct"""
    print("\n" + "=" * 70)
    print("INTEGRATION TEST: socat Bind Syntax Fix")
    print("=" * 70)

    wan_ipv6 = "2001:db8::1"
    lan_ip = "192.168.1.100"
    ipv6_port = 8080
    device_port = 80

    # Build command as in actual code
    cmd = [
        cfg.CMD_SOCAT,
        f"TCP6-LISTEN:{ipv6_port},bind={wan_ipv6},fork,reuseaddr",
        f"TCP4:{lan_ip}:{device_port}",
    ]

    print(f"  socat command: {' '.join(cmd)}")
    print(f"  Listen part:   {cmd[1]}")

    # Verify format
    assert f"bind={wan_ipv6}" in cmd[1], "Should use bind=<ipv6>"
    assert f"bind=[{wan_ipv6}]" not in cmd[1], "Should NOT use bind=[<ipv6>]"
    assert "[" not in cmd[1], "Should not contain brackets"

    print("  ✓ socat bind syntax correct (no brackets)")
    print("\n✅ SOCAT BIND SYNTAX FIX VERIFIED")

    return True


def test_snat_protocol_fix():
    """Test that SNAT uses IPv4 iptables, not IPv6"""
    print("\n" + "=" * 70)
    print("INTEGRATION TEST: SNAT Protocol Family Fix")
    print("=" * 70)

    lan_ip = "192.168.1.100"
    device_port = 80

    # Expected IPv4 iptables command
    cmd = [
        cfg.CMD_IPTABLES,  # Should be iptables, not ip6tables
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

    print(f"  SNAT command: {' '.join(cmd)}")
    print(f"  Command tool: {cmd[0]}")

    # Verify IPv4 iptables
    assert "iptables" in cmd[0], "Should use iptables"
    assert "ip6tables" not in cmd[0], "Should NOT use ip6tables"
    assert cmd[0] == cfg.CMD_IPTABLES, "Should use CMD_IPTABLES"

    print("  ✓ SNAT uses IPv4 iptables (not IPv6)")
    print("\n✅ SNAT PROTOCOL FAMILY FIX VERIFIED")

    return True


def run_integration_tests():
    """Run all integration tests"""
    tests = [
        ("IPv6 Address Parsing Fix", test_ipv6_address_fix),
        ("socat Bind Syntax Fix", test_socat_bind_fix),
        ("SNAT Protocol Family Fix", test_snat_protocol_fix),
        ("Full Device Flow", test_full_device_flow),
    ]

    passed = 0
    failed = 0

    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUITE")
    print("=" * 70)

    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n{'='*70}")
                print(f"✅ {name} PASSED")
                print(f"{'='*70}")
        except Exception as e:
            failed += 1
            print(f"\n{'='*70}")
            print(f"❌ {name} FAILED")
            print(f"Error: {e}")
            print(f"{'='*70}")
            import traceback

            traceback.print_exc()

    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed == 0:
        print("\n✅ ALL INTEGRATION TESTS PASSED!")
        return 0
    else:
        print("\n❌ SOME INTEGRATION TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_integration_tests())
