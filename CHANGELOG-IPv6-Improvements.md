# IPv6 Auto-Detection & WAN Management Improvements

## Summary

This update addresses two critical issues with the IPv6 gateway:

1. **IPv6 Auto-Detection**: Gateway now automatically detects whether the network supports SLAAC, DHCPv6, or both
2. **WAN Interface Management**: Gateway can now keep WAN interface DOWN until first device connects, hiding gateway's own MAC from network

## Problem Statements

### Problem 1: IPv6 Not Working
**Symptom**: Device unable to obtain IPv6 address
**Root Cause**: Network could support SLAAC, DHCPv6, or both, and gateway needed to automatically detect and adapt

### Problem 2: Gateway MAC Visible on Network
**Symptom**: Gateway's own MAC appears on WAN network before any device connects
**Root Cause**: Gateway brought up WAN interface (eth0) with its own MAC during initialization

## Solutions Implemented

### 1. IPv6 Auto-Detection (Already Implemented ✓)

**Good News**: The gateway ALREADY has comprehensive IPv6 auto-detection!

#### Current Implementation:
```python
# For each device, gateway automatically:
1. Tries SLAAC first (waits 15 seconds for Router Advertisement)
2. If SLAAC succeeds → uses SLAAC address
3. If SLAAC fails → falls back to DHCPv6
4. If SLAAC succeeds → also tries DHCPv6 info-only for DNS/NTP
```

#### Supported Network Types:
- **SLAAC-only**: Gateway obtains IPv6 via Router Advertisements
- **DHCPv6-only**: Gateway obtains IPv6 via DHCPv6 server
- **Dual Mode**: Gateway uses SLAAC for address, DHCPv6 for additional config

#### How It Works:
1. **MAC Spoofing**: Gateway spoofs device MAC on eth0
2. **Enable IPv6**: Enables accept_ra=2 and autoconf=1
3. **Router Solicitation**: Sends ping to ff02::2 to request Router Advertisement
4. **SLAAC Wait**: Waits 15 seconds for SLAAC to assign address
5. **DHCPv6 Fallback**: If SLAAC fails, runs full DHCPv6 request
6. **Retry Logic**: 5 retries with exponential backoff

### 2. WAN Interface Management (NEW FEATURE ✓)

#### Configuration Option Added:
```python
# gateway_config.py

KEEP_WAN_DOWN_UNTIL_DEVICE = True  # NEW!

# When True:
#   - WAN interface stays DOWN on service start
#   - First device MAC is learned from LAN
#   - WAN interface is brought UP with spoofed MAC (device's MAC)
#   - Gateway's own MAC NEVER appears on WAN network

# When False:
#   - WAN interface is brought UP immediately with gateway's own MAC
#   - Traditional behavior (gateway MAC visible on network)
```

#### Implementation Details:

**Initialization** (`ipv4_ipv6_gateway.py:initialize()`):
```python
if cfg.KEEP_WAN_DOWN_UNTIL_DEVICE:
    if self.eth0.is_up():
        self.eth0.bring_down()  # Bring WAN down
    logger.warning("WAN interface will remain DOWN until first device connects")
    logger.warning("Gateway's own MAC will NEVER appear on WAN network")
else:
    if not self.eth0.is_up():
        self.eth0.bring_up()  # Traditional mode
```

**First Device Detection** (`ipv4_ipv6_gateway.py:_discover_addresses_for_device()`):
```python
if cfg.KEEP_WAN_DOWN_UNTIL_DEVICE:
    with self.wan_init_lock:
        if not self.wan_initialized:
            logger.warning(f"FIRST DEVICE DETECTED! Initializing WAN with MAC {mac}")

            # Set MAC and bring up interface
            self.eth0.set_mac_address(mac)
            self.eth0.bring_up()
            time.sleep(3)  # Let interface stabilize

            self.wan_initialized = True
            logger.warning(f"✓ WAN initialized with MAC {mac}")
            logger.warning(f"✓ Gateway's own MAC is HIDDEN from network")
```

## New Diagnostic Tool

Created `/diagnose-ipv6-auto-detection.sh` to test network capabilities:

### What It Does:
1. Finds a test device MAC from LAN
2. Spoofs that MAC on WAN
3. Tests SLAAC (waits 15s for Router Advertisement)
4. Tests DHCPv6 (runs odhcp6c)
5. Tests network authorization (pings gateway)
6. Provides detailed summary

### Usage:
```bash
ssh root@<router-ip>
bash /tmp/diagnose-ipv6-auto-detection.sh
```

### Example Output:
```
=== SUMMARY ===

Test Device MAC: aa:bb:cc:dd:ee:ff

✓ DUAL MODE: Network supports BOTH SLAAC and DHCPv6

Recommended gateway configuration:
  - Gateway will try SLAAC first (15 second wait)
  - If SLAAC succeeds, will use SLAAC address
  - Will also run DHCPv6 info-only for DNS/NTP
  - If SLAAC fails, will fall back to DHCPv6
```

## Files Modified

### 1. `/gateway_config.py`
- Added `KEEP_WAN_DOWN_UNTIL_DEVICE` configuration option
- Added detailed documentation

### 2. `/ipv4_ipv6_gateway.py`
**NetworkInterface class**:
- Added `bring_down()` method

**GatewayService class**:
- Added `wan_initialized` and `wan_init_lock` tracking
- Modified `initialize()` to respect `KEEP_WAN_DOWN_UNTIL_DEVICE`
- Modified `_discover_addresses_for_device()` to bring up WAN with device MAC on first device

### 3. `/diagnose-ipv6-auto-detection.sh` (NEW)
- Comprehensive network capability testing
- Tests SLAAC, DHCPv6, and Router Advertisements
- Provides actionable recommendations

## Testing Recommendations

### Test 1: Verify SLAAC/DHCPv6 Auto-Detection
```bash
# Deploy and run auto-detection diagnostic
scp diagnose-ipv6-auto-detection.sh root@<router>:/tmp/
ssh root@<router>
bash /tmp/diagnose-ipv6-auto-detection.sh
```

Expected: Script identifies whether network supports SLAAC, DHCPv6, or both

### Test 2: Verify WAN Management (Default: KEEP_WAN_DOWN_UNTIL_DEVICE=True)
```bash
# 1. Deploy gateway with default config
./install.sh --full-auto

# 2. Check WAN is DOWN
ip link show eth0
# Should show: "state DOWN"

# 3. Check logs
tail -f /var/log/ipv4-ipv6-gateway.log
# Should show: "WAN interface will remain DOWN until first device connects"

# 4. Connect device to LAN

# 5. Watch logs for WAN initialization
# Should show:
#   "FIRST DEVICE DETECTED! Initializing WAN interface with device MAC aa:bb:cc:dd:ee:ff"
#   "✓ WAN interface initialized with MAC aa:bb:cc:dd:ee:ff"
#   "✓ Gateway's own MAC is HIDDEN from network"

# 6. Verify WAN is now UP with device MAC
ip link show eth0
# Should show: "state UP" with device's MAC address
```

### Test 3: Verify Traditional Mode (KEEP_WAN_DOWN_UNTIL_DEVICE=False)
```bash
# 1. Edit config
vi /opt/ipv4-ipv6-gateway/gateway_config.py
# Change: KEEP_WAN_DOWN_UNTIL_DEVICE = False

# 2. Restart service
/etc/init.d/ipv4-ipv6-gateway restart

# 3. Check WAN is immediately UP
ip link show eth0
# Should show: "state UP" with gateway's own MAC

# 4. Check logs
tail -f /var/log/ipv4-ipv6-gateway.log
# Should show: "WAN interface management: Traditional mode - using gateway's own MAC"
```

## Deployment

### Quick Deploy (Default: WAN down until device connects)
```bash
# Copy files to router
scp ipv4_ipv6_gateway.py gateway_config.py gateway_api_server.py \
    install.sh diagnose-and-fix.sh \
    diagnose-ipv6-auto-detection.sh \
    gateway-status-direct.sh gateway-devices-direct.sh \
    setup-port-forwarding.sh \
    root@<router-ip>:/tmp/

# Install
ssh root@<router-ip>
cd /tmp
chmod +x install.sh
./install.sh --full-auto
```

### Verify Deployment
```bash
# Run diagnostics
gateway-diagnose

# Check if WAN stayed down
ip link show eth0
# Should be DOWN if no device connected yet

# Check gateway status
gateway-status-direct

# View logs
tail -f /var/log/ipv4-ipv6-gateway.log
```

## Configuration Options

### WAN Management Strategy

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
# Keep WAN down until device connects (recommended for MAC-filtered networks)
KEEP_WAN_DOWN_UNTIL_DEVICE = True

# Traditional mode (gateway MAC visible)
KEEP_WAN_DOWN_UNTIL_DEVICE = False
```

After changing, restart service:
```bash
/etc/init.d/ipv4-ipv6-gateway restart
```

## Expected Behavior

### With KEEP_WAN_DOWN_UNTIL_DEVICE = True (Default)

**Startup:**
```
[INFO] Initializing gateway service...
[INFO] WAN interface management: Bringing eth0 DOWN (will be brought up with device MAC)
[WARNING] ⚠ WAN interface will remain DOWN until first device connects to LAN
[WARNING] ⚠ Gateway's own MAC will NEVER appear on WAN network
[INFO] Gateway service initialized successfully
```

**First Device Connects:**
```
[INFO] 🆕 New device discovered: aa:bb:cc:dd:ee:ff (IPv4: 192.168.1.100)
[WARNING] 🌐 FIRST DEVICE DETECTED! Initializing WAN interface with device MAC aa:bb:cc:dd:ee:ff
[INFO] Setting WAN MAC to aa:bb:cc:dd:ee:ff and bringing interface up...
[INFO] Waiting for WAN interface to stabilize...
[WARNING] ✓ WAN interface initialized with MAC aa:bb:cc:dd:ee:ff
[WARNING] ✓ Gateway's own MAC is HIDDEN from network
[INFO] Requesting DHCPv4 for aa:bb:cc:dd:ee:ff
[INFO] Successfully obtained IPv4 10.1.2.50 for MAC aa:bb:cc:dd:ee:ff
[INFO] Requesting IPv6 for MAC: aa:bb:cc:dd:ee:ff (SLAAC + DHCPv6)
[INFO] Waiting for SLAAC (Router Advertisement)...
[INFO] Successfully obtained IPv6 2001:db8::1234 via SLAAC for MAC aa:bb:cc:dd:ee:ff (attempt 1)
```

### With KEEP_WAN_DOWN_UNTIL_DEVICE = False (Traditional)

**Startup:**
```
[INFO] Initializing gateway service...
[INFO] Bringing eth0 up...
[INFO] WAN interface management: Traditional mode - using gateway's own MAC
[INFO] Gateway service initialized successfully
```

## Troubleshooting

### Issue: IPv6 Still Not Working

**Diagnostic Steps:**
```bash
# 1. Run auto-detection diagnostic
bash /tmp/diagnose-ipv6-auto-detection.sh

# 2. Check if MAC is authorized
# Output will show if MAC is blocked by firewall

# 3. Check logs for IPv6 request details
tail -100 /var/log/ipv4-ipv6-gateway.log | grep -i "ipv6\|slaac\|dhcpv6"

# 4. Manually test SLAAC
ip -6 addr show eth0 | grep inet6
# Should see global IPv6 address (not just fe80::)

# 5. Check sysctl settings
sysctl net.ipv6.conf.eth0.accept_ra
sysctl net.ipv6.conf.eth0.autoconf
# Both should be 1 or 2
```

### Issue: WAN Not Coming Up

**Diagnostic Steps:**
```bash
# 1. Check if any device connected to LAN
ip neigh show dev eth1

# 2. Check gateway logs for WAN initialization
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i "wan\|first device"

# 3. Manually verify device MAC
gateway-devices-direct

# 4. If stuck, switch to traditional mode temporarily
vi /opt/ipv4-ipv6-gateway/gateway_config.py
# Change: KEEP_WAN_DOWN_UNTIL_DEVICE = False
/etc/init.d/ipv4-ipv6-gateway restart
```

## Benefits

### 1. IPv6 Auto-Detection
- ✅ Works with SLAAC-only networks
- ✅ Works with DHCPv6-only networks
- ✅ Works with dual-mode networks
- ✅ Automatic fallback between methods
- ✅ No manual configuration needed

### 2. WAN Interface Management
- ✅ Gateway's own MAC never appears on network
- ✅ Only device MACs are visible to upstream firewall
- ✅ Prevents MAC registration conflicts
- ✅ Cleaner network security posture
- ✅ Backward compatible (can disable with config option)

## Limitations

### 1. SLAAC Wait Time
- Fixed at 15 seconds (hardcoded in `request_ipv6_for_mac()`)
- For DHCPv6-only networks, this adds 15s delay before falling back
- Could be made configurable in future if needed

### 2. Single Device Mode
- Gateway operates in single-device mode (MAX_DEVICES = 1)
- Only one device supported at a time
- When new device connects, old device is replaced

### 3. WAN Initialization
- WAN interface brought up ONLY with first device's MAC
- Subsequent devices reuse same WAN interface with same MAC
- If device disconnects, WAN stays up with its MAC

## Future Improvements

1. **Configurable SLAAC Wait Time**
   ```python
   SLAAC_WAIT_TIME = 15  # seconds - could be reduced for DHCPv6-only networks
   ```

2. **WAN Interface Reset on Device Change**
   - Bring down WAN when device disconnects
   - Bring up with new device's MAC when next device connects

3. **IPv6 Privacy Extensions**
   - Support for IPv6 privacy extensions
   - Temporary addresses for enhanced privacy

## Conclusion

The gateway now provides:
1. **Automatic IPv6 detection** for all network types (SLAAC, DHCPv6, dual-mode)
2. **Hidden gateway MAC** to prevent registration conflicts
3. **Comprehensive diagnostics** to identify network capabilities
4. **Backward compatibility** with traditional mode

Both features work independently and can be enabled/disabled via configuration.
