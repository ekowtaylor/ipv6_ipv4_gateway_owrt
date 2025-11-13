# OpenWrt MAC Protection

## Problem

OpenWrt has several services that can interfere with permanent MAC spoofing:

1. **netifd** - Network interface daemon that manages network interfaces
2. **hotplug scripts** - Scripts that run on network events (interface up/down)
3. **odhcp6c/odhcpd** - DHCP services may reset MAC
4. **Network restart scripts** - Can reset MAC to default

If any of these services reset the MAC address back to the gateway's original MAC, it creates a loop:

```
1. Gateway sets device MAC on eth0
2. OpenWrt service resets MAC to gateway's original MAC
3. WAN monitor detects MAC change
4. WAN monitor restores device MAC
5. OpenWrt service resets again → INFINITE LOOP
```

## Solution

The gateway implements **two layers of protection**:

### Layer 1: WAN Monitor MAC Protection (Automatic)

The `WANMonitor` class actively monitors the WAN interface MAC address and automatically restores it if changed:

```python
def check_for_changes(self) -> bool:
    # Check MAC address first (before IP addresses)
    if self.expected_mac:
        current_mac = self.iface.get_mac_address()
        if current_mac and current_mac.lower() != self.expected_mac:
            # Immediately restore the expected MAC
            self.iface.bring_down()
            if self.iface.set_mac_address(self.expected_mac):
                self.iface.bring_up()
                # Don't trigger rediscovery - just fixed it
                return False
```

**Features:**
- Runs every 15 seconds (configurable via `WAN_MONITOR_INTERVAL`)
- Detects MAC changes immediately
- Automatically restores device MAC
- Includes 30-second cooldown to prevent loops
- Logs all MAC changes for debugging

**Logs to watch for:**
```
⚠️ WAN MAC ADDRESS CHANGED! Expected aa:bb:cc:dd:ee:ff, found 11:22:33:44:55:66
⚠️ This suggests OpenWrt service (netifd/hotplug) reset the MAC!
🔧 Restoring correct MAC aa:bb:cc:dd:ee:ff...
✓ Restored WAN MAC to aa:bb:cc:dd:ee:ff
```

### Layer 2: Disable netifd Management (Recommended)

For maximum reliability, **disable OpenWrt's netifd management of eth0**:

```bash
# Run the disable script
chmod +x disable-netifd-eth0.sh
./disable-netifd-eth0.sh
```

**What this does:**
1. Backs up `/etc/config/network`
2. Removes eth0 from all network interfaces (WAN, WAN6, etc.)
3. Creates a dummy interface (`network.eth0_custom`) with `proto='none'` and `auto='0'`
4. Restarts network service

**Result:**
- netifd will no longer manage eth0
- Gateway service has full control over eth0's MAC address
- No more MAC resets from OpenWrt

**To revert:**
```bash
# Restore original network config
cp /etc/config/network.backup.* /etc/config/network
/etc/init.d/network reload
```

## Testing MAC Protection

### Test 1: Automatic MAC Restoration

1. Start the gateway service
2. Wait for device to connect (MAC will be set)
3. Manually change MAC back to original:
   ```bash
   ip link set eth0 down
   ip link set eth0 address 11:22:33:44:55:66  # Gateway's original MAC
   ip link set eth0 up
   ```
4. Watch the logs - within 15 seconds you should see:
   ```
   ⚠️ WAN MAC ADDRESS CHANGED! Expected aa:bb:cc:dd:ee:ff, found 11:22:33:44:55:66
   🔧 Restoring correct MAC aa:bb:cc:dd:ee:ff...
   ✓ Restored WAN MAC to aa:bb:cc:dd:ee:ff
   ```

### Test 2: Prevent OpenWrt Interference

1. Run `disable-netifd-eth0.sh`
2. Verify netifd no longer manages eth0:
   ```bash
   uci show network | grep eth0
   # Should show: network.eth0_custom.proto='none'
   ```
3. Restart network service:
   ```bash
   /etc/init.d/network restart
   ```
4. Verify MAC is NOT reset:
   ```bash
   cat /sys/class/net/eth0/address
   # Should still show device MAC, not gateway MAC
   ```

## Configuration

### WAN Monitor Settings

In `gateway_config.py`:

```python
# WAN network monitoring (automatic network change detection)
ENABLE_WAN_MONITOR = True  # Enable MAC and IP monitoring
WAN_MONITOR_INTERVAL = 15  # Check every 15 seconds
WAN_CHANGE_REDISCOVERY_DELAY = 5  # Wait 5s before rediscovering devices
```

### Cooldown Protection

The WAN monitor includes a 30-second cooldown to prevent infinite loops:

```python
# In WANMonitor class
self.cooldown_seconds = 30  # Minimum time between detecting changes
```

**How it works:**
- If a change was detected recently (within 30 seconds), subsequent changes are ignored
- This prevents the loop: IP appears → triggers rediscovery → IP cleared → triggers again
- MAC restoration happens immediately (no cooldown), but logs the event

## Troubleshooting

### Problem: MAC keeps getting reset

**Symptom:** Logs show repeated MAC changes every few seconds

**Solution:**
1. Run `disable-netifd-eth0.sh` to prevent netifd interference
2. Check for custom hotplug scripts:
   ```bash
   ls /etc/hotplug.d/net/
   ls /etc/hotplug.d/iface/
   ```
3. Disable any scripts that might reset MAC

### Problem: Network connectivity lost after disabling netifd

**Symptom:** Can't access gateway after running `disable-netifd-eth0.sh`

**Solution:**
1. The gateway service manages eth0, not netifd
2. Ensure gateway service is running:
   ```bash
   /etc/init.d/ipv4-ipv6-gateway status
   ```
3. If needed, restore original config:
   ```bash
   cp /etc/config/network.backup.* /etc/config/network
   /etc/init.d/network reload
   ```

### Problem: WAN monitor not detecting MAC changes

**Symptom:** MAC changes but no restoration logs appear

**Check:**
1. Verify WAN monitor is enabled:
   ```bash
   grep "WAN network monitoring started" /var/log/ipv4-ipv6-gateway.log
   ```
2. Check if expected MAC is set:
   ```bash
   grep "WAN monitor will maintain MAC" /var/log/ipv4-ipv6-gateway.log
   ```
3. Verify monitor interval:
   ```bash
   grep "ENABLE_WAN_MONITOR = True" /usr/local/bin/gateway_config.py
   ```

## Security Implications

### Why MAC protection is critical:

1. **Network Authentication:** Many networks use 802.1X or MAC filtering
   - Only device MACs are authenticated, not gateway MAC
   - If gateway MAC appears on network, traffic is blocked
   - Permanent device MAC ensures continuous authentication

2. **MAC-Filtered VLANs:**
   - Enterprise networks often filter by MAC address
   - Gateway MAC is not in the allowed list
   - Device MAC must remain permanent

3. **Firewall Rules:**
   - Upstream firewalls may have MAC-based rules
   - Changing MAC breaks existing connections
   - Permanent MAC maintains firewall state

### What happens if MAC protection fails:

1. Gateway MAC appears on network → traffic blocked by MAC filter
2. DHCP lease lost → all WAN addresses cleared
3. Device loses IPv4 and IPv6 connectivity
4. Gateway must re-request DHCP with device MAC
5. Delay of 30+ seconds while re-configuring

**Result:** Intermittent connectivity, dropped connections, poor user experience

## Best Practices

1. **Always run `disable-netifd-eth0.sh`** during installation
2. **Monitor logs** for MAC change warnings
3. **Test MAC protection** before deploying to production
4. **Document original MAC** in case manual restoration is needed
5. **Keep backups** of `/etc/config/network`

## Summary

| Protection Layer | Purpose | When Active | Reliability |
|-----------------|---------|-------------|-------------|
| WAN Monitor | Automatic MAC restoration | After first device connects | High (30s cooldown) |
| Disable netifd | Prevent OpenWrt interference | After running disable script | Very High |

**Recommendation:** Use **both layers** for maximum reliability:
- WAN monitor provides automatic recovery if MAC is changed
- Disabling netifd prevents MAC changes from happening in the first place
