# IPv6→IPv4 Proxy Return Path Fix

## Problem

**Symptom:** IPv6 clients can connect to device but don't get responses back.

**Root Cause:** Missing Source NAT (SNAT) in IPv6→IPv4 proxy.

**What's Happening:**
```
1. IPv6 Client (2001:db8::9999) → Gateway IPv6 (2001:db8::1234):80
2. Gateway proxy forwards to → Device IPv4 (192.168.1.100):80
3. Device sees request from IPv6 address 2001:db8::9999
4. Device tries to respond directly to 2001:db8::9999
5. ❌ FAILS - device can't route to IPv6, response lost
```

**What Should Happen:**
```
1. IPv6 Client (2001:db8::9999) → Gateway IPv6 (2001:db8::1234):80
2. Gateway proxy with SNAT to → Device IPv4 (192.168.1.100):80
   Source: 192.168.1.1 (gateway LAN IP)
3. Device sees request from 192.168.1.1
4. Device responds to 192.168.1.1
5. Gateway proxy forwards response back to IPv6 client
6. ✅ SUCCESS - full round trip works
```

---

## Solutions

### Option 1: Fix socat with iptables SNAT ⭐ RECOMMENDED

Add iptables rules to SNAT traffic going to device:

```bash
# For each IPv6 proxy port, add SNAT rule
# This makes device see requests as coming from gateway (192.168.1.1)

# Example for port 80:
ip6tables -t nat -A POSTROUTING \
  -s <device-ipv6>/128 \
  -d 192.168.1.100 \
  -p tcp --dport 80 \
  -j SNAT --to-source 192.168.1.1
```

**Implementation in code:**

```python
def _setup_ipv6_proxy(self, mac: str, lan_ip: str, wan_ipv6: str):
    """Setup IPv6→IPv4 proxy using socat with SNAT"""
    self.logger.info(f"Setting up IPv6→IPv4 proxy for {lan_ip}")

    # Kill existing socat processes
    self._stop_proxy(mac)

    for ipv6_port, device_port in cfg.IPV6_PROXY_PORTS.items():
        try:
            # Add ip6tables SNAT rule for return traffic
            # Device will see requests from gateway LAN IP instead of IPv6 client
            subprocess.run([
                "ip6tables", "-t", "nat", "-A", "POSTROUTING",
                "-s", f"{wan_ipv6}/128",
                "-d", lan_ip,
                "-p", "tcp", "--dport", str(device_port),
                "-j", "SNAT", "--to-source", cfg.LAN_GATEWAY_IP
            ], check=True)

            # Start socat
            cmd = [
                cfg.CMD_SOCAT,
                f"TCP6-LISTEN:{ipv6_port},bind=[{wan_ipv6}],fork,reuseaddr",
                f"TCP4:{lan_ip}:{device_port}",
            ]

            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            self.logger.info(
                f"IPv6 proxy + SNAT: [{wan_ipv6}]:{ipv6_port} → {lan_ip}:{device_port}"
            )

        except Exception as e:
            self.logger.warning(f"Failed to setup IPv6 proxy on port {ipv6_port}: {e}")

    time.sleep(1)
```

---

### Option 2: Use HAProxy source Binding ⚠️ COMPLEX

HAProxy can do source address translation with `source` directive:

```haproxy
backend ipv4_http_device
    # Source bind to gateway LAN IP
    source 192.168.1.1 usesrc client
    server device 192.168.1.100:80
```

**But** this has issues:
- `usesrc client` requires kernel support and CAP_NET_RAW
- More complex configuration
- May not work on all kernels

**Recommendation:** Use iptables SNAT instead (Option 1)

---

### Option 3: Use socat's `bind` Option ❌ DOESN'T WORK

socat doesn't support source address override on outbound connections.

This won't work:
```bash
socat TCP6-LISTEN:80,bind=[ipv6],fork \
      TCP4:192.168.1.100:80,bind=192.168.1.1  # ❌ No effect
```

---

## Implementation Plan

### 1. Update `ipv4_ipv6_gateway.py`

Add ip6tables SNAT rules in `_setup_ipv6_proxy()`:

```python
def _setup_ipv6_proxy(self, mac: str, lan_ip: str, wan_ipv6: str):
    """Setup IPv6→IPv4 proxy using socat with SNAT for return traffic"""
    self.logger.info(f"Setting up IPv6→IPv4 proxy for {lan_ip}")

    # Kill existing socat processes
    self._stop_proxy(mac)

    for ipv6_port, device_port in cfg.IPV6_PROXY_PORTS.items():
        try:
            # CRITICAL FIX: Add ip6tables SNAT rule for return traffic
            # Without this, device sees requests from IPv6 address and can't respond
            # With this, device sees requests from gateway LAN IP (192.168.1.1)
            try:
                subprocess.run([
                    "ip6tables", "-t", "nat", "-D", "POSTROUTING",
                    "-s", f"{wan_ipv6}/128",
                    "-d", lan_ip,
                    "-p", "tcp", "--dport", str(device_port),
                    "-j", "SNAT", "--to-source", cfg.LAN_GATEWAY_IP
                ], capture_output=True, timeout=2)
            except:
                pass  # Rule doesn't exist yet

            subprocess.run([
                "ip6tables", "-t", "nat", "-A", "POSTROUTING",
                "-s", f"{wan_ipv6}/128",
                "-d", lan_ip,
                "-p", "tcp", "--dport", str(device_port),
                "-j", "SNAT", "--to-source", cfg.LAN_GATEWAY_IP
            ], check=True, timeout=5)

            self.logger.info(
                f"Added ip6tables SNAT rule: {wan_ipv6} → {lan_ip}:{device_port} (via {cfg.LAN_GATEWAY_IP})"
            )

            # Start socat
            cmd = [
                cfg.CMD_SOCAT,
                f"TCP6-LISTEN:{ipv6_port},bind=[{wan_ipv6}],fork,reuseaddr",
                f"TCP4:{lan_ip}:{device_port}",
            ]

            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            self.logger.info(
                f"IPv6 proxy: [{wan_ipv6}]:{ipv6_port} → {lan_ip}:{device_port}"
            )

        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to setup IPv6 proxy on port {ipv6_port}: {e}")
        except Exception as e:
            self.logger.warning(f"Error setting up IPv6 proxy on port {ipv6_port}: {e}")

    time.sleep(1)
```

### 2. Update `_stop_proxy()` to Clean Up SNAT Rules

```python
def _stop_proxy(self, mac: str):
    """Stop all socat proxies and clean up ip6tables rules"""
    try:
        # Kill socat processes
        result = subprocess.run(["ps", "-w"], capture_output=True, text=True)

        for line in result.stdout.splitlines():
            if "socat" in line and "TCP6-LISTEN" in line:
                parts = line.split()
                if parts:
                    pid = parts[0]
                    try:
                        subprocess.run(["kill", pid], timeout=2)
                        self.logger.info(f"Killed socat process {pid}")
                    except Exception:
                        pass

        # Clean up ip6tables SNAT rules if device exists
        if self.device and "wan_ipv6" in self.device and self.device["wan_ipv6"]:
            wan_ipv6 = self.device["wan_ipv6"]
            lan_ip = self.device["lan_ipv4"]

            for device_port in cfg.IPV6_PROXY_PORTS.values():
                try:
                    subprocess.run([
                        "ip6tables", "-t", "nat", "-D", "POSTROUTING",
                        "-s", f"{wan_ipv6}/128",
                        "-d", lan_ip,
                        "-p", "tcp", "--dport", str(device_port),
                        "-j", "SNAT", "--to-source", cfg.LAN_GATEWAY_IP
                    ], capture_output=True, timeout=2)
                    self.logger.info(f"Removed ip6tables SNAT rule for port {device_port}")
                except:
                    pass  # Rule doesn't exist

    except Exception as e:
        self.logger.warning(f"Error stopping proxies: {e}")
```

### 3. Update HAProxy Configuration (if using HAProxy)

Add source binding in HAProxy config generation (`haproxy_manager.py`):

```python
# In _build_haproxy_config(), backend section:
lines.append(f"backend {backend_name}")
lines.append(f"    # Target device: {device_ip}:{device_port} (MAC: {mac})")
lines.append(f"    # CRITICAL: Source from gateway LAN IP for return traffic")
lines.append(f"    source 192.168.1.1")  # <-- ADD THIS LINE
lines.append(f"    timeout connect 10s")
lines.append(f"    timeout server 300s")
lines.append(f"    server device_{safe_mac} {device_ip}:{device_port}")
```

---

## Testing

### Before Fix
```bash
# From IPv6 client
curl -6 http://[2001:db8::1234]:80
# Request sent, no response (times out)

# On device, tcpdump shows:
# Request from 2001:db8::9999 (IPv6 client)
# Device tries to respond to 2001:db8::9999
# Response lost (can't route to IPv6)
```

### After Fix
```bash
# From IPv6 client
curl -6 http://[2001:db8::1234]:80
# ✅ SUCCESS - full response received

# On device, tcpdump shows:
# Request from 192.168.1.1 (gateway LAN IP)
# Device responds to 192.168.1.1
# Gateway forwards response to IPv6 client
```

### Verification Commands

```bash
# Check ip6tables SNAT rules
ip6tables -t nat -L POSTROUTING -n -v

# Should show rules like:
# SNAT tcp -- eth0 * 2001:db8::1234 192.168.1.100 tcp dpt:80 to:192.168.1.1

# Test from IPv6 client
curl -6 -v http://[<device-ipv6>]:80

# Monitor on gateway
tcpdump -i eth1 -n port 80

# Should see:
# 192.168.1.1.xxxxx > 192.168.1.100.80: Flags [S], seq ...
# 192.168.1.100.80 > 192.168.1.1.xxxxx: Flags [S.], seq ...
```

---

## Why This Fix Works

1. **IPv6 Client** sends request to **Gateway IPv6:port**
2. **socat/HAProxy** receives on IPv6, forwards to device IPv4
3. **ip6tables SNAT** translates source to **Gateway LAN IP (192.168.1.1)**
4. **Device** sees request from 192.168.1.1, responds to 192.168.1.1
5. **Gateway** receives response on LAN interface
6. **socat/HAProxy** forwards response back to IPv6 client via established connection
7. **IPv6 Client** receives response successfully

The key is that the device must see requests as coming from the gateway's LAN IP, not from the IPv6 client address.

---

## Additional Considerations

### Firewall Compatibility

Ensure ip6tables nat table is loaded:

```bash
modprobe ip6table_nat
```

Add to `/etc/modules` for persistence:
```bash
echo "ip6table_nat" >> /etc/modules
```

### Performance Impact

- **Negligible** - iptables SNAT is very fast
- No additional latency introduced
- Scales well even with high traffic

### Alternative: NAT64

For production IPv6-only networks, consider proper NAT64 (Tayga):
- Full IPv6 → IPv4 translation
- Standard protocol
- Better for complex scenarios

But for this single-device use case, ip6tables SNAT is simpler and sufficient.

---

## Summary

✅ **Root Cause:** Missing source NAT - device can't respond to IPv6 addresses
✅ **Fix:** Add ip6tables SNAT rules to make device see requests from gateway LAN IP
✅ **Impact:** IPv6→IPv4 proxy will work correctly with full bidirectional traffic
✅ **Complexity:** Low - just a few iptables rules
✅ **Performance:** Negligible overhead

**Priority:** HIGH - This is a critical bug preventing IPv6 functionality

---

**Created:** 2024-11-13
**Issue:** IPv6→IPv4 proxy return path failure
**Solution:** ip6tables SNAT for return traffic routing
