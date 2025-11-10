# Troubleshooting: Service Not Starting

If the service fails to start with `/etc/init.d/ipv4-ipv6-gateway start`, follow these steps:

## Step 1: Check if Python is installed

```bash
which python3
python3 --version
```

**Expected**: Should show path like `/usr/bin/python3` and version 3.7+

**If missing**: Install Python
```bash
opkg update
opkg install python3 python3-light
```

---

## Step 2: Check if required commands exist

```bash
which ip
which arp
which odhcp6c
which iptables
which sysctl
```

**If any are missing**:
```bash
opkg update
opkg install ip-full odhcp6c iptables
```

---

## Step 3: Test the Python script directly

```bash
# Try to run the script manually
cd /opt/ipv4-ipv6-gateway
python3 ipv4_ipv6_gateway.py
```

**Look for error messages**. Common issues:

### Error: "No module named 'gateway_config'"

**Fix**: Ensure `gateway_config.py` is in the same directory
```bash
ls -la /opt/ipv4-ipv6-gateway/
# Should show:
# ipv4_ipv6_gateway.py
# gateway_config.py
# gateway_api_server.py
```

### Error: "Permission denied"

**Fix**: Set execute permissions
```bash
chmod +x /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py
```

### Error: Command not found (ip, arp, etc.)

**Fix**: Edit `/opt/ipv4-ipv6-gateway/gateway_config.py` and update paths
```python
# Find the actual paths
which ip        # e.g., /sbin/ip
which arp       # e.g., /usr/sbin/arp
which odhcp6c   # e.g., /sbin/odhcp6c

# Update in gateway_config.py:
CMD_IP = "/sbin/ip"
CMD_ARP = "/usr/sbin/arp"
CMD_ODHCP6C = "/sbin/odhcp6c"
```

### Error: "Failed to validate config"

**Fix**: Check directory permissions
```bash
mkdir -p /etc/ipv4-ipv6-gateway
mkdir -p /var/log
mkdir -p /var/run/ipv4-ipv6-gateway
chmod 755 /etc/ipv4-ipv6-gateway
```

---

## Step 4: Check logs

```bash
# Check if log file exists and has errors
tail -50 /var/log/ipv4-ipv6-gateway.log

# If no log file exists, check system log
logread | grep ipv4-ipv6-gateway
```

---

## Step 5: Check init.d script

```bash
# Verify script exists and is executable
ls -la /etc/init.d/ipv4-ipv6-gateway

# Should show: -rwxr-xr-x (executable)
# If not executable:
chmod +x /etc/init.d/ipv4-ipv6-gateway
```

---

## Step 6: Test init.d script manually

```bash
# Run in foreground to see errors
/etc/init.d/ipv4-ipv6-gateway start

# Check status
/etc/init.d/ipv4-ipv6-gateway status
```

---

## Step 7: Check if process is running

```bash
# Look for the Python process
ps | grep ipv4_ipv6_gateway
ps | grep python3

# Check PID file
cat /var/run/ipv4-ipv6-gateway.pid

# If PID exists, check if process is actually running
ps | grep $(cat /var/run/ipv4-ipv6-gateway.pid)
```

---

## Step 8: Check network interfaces

```bash
# Verify interfaces exist
ip link show eth0
ip link show eth1

# If interfaces have different names (e.g., lan, wan):
ip link show

# Update gateway_config.py with actual interface names:
# ETH0_INTERFACE = 'wan'  # or whatever eth0 is called
# ETH1_INTERFACE = 'lan'  # or whatever eth1 is called
```

---

## Step 9: Run with debug mode

Edit `/opt/ipv4-ipv6-gateway/gateway_config.py`:

```python
LOG_LEVEL = 'DEBUG'
DEBUG_MODE = True
DEBUG_ARP_QUERIES = True
DEBUG_DHCPV6_REQUESTS = True
```

Then try starting again:
```bash
/etc/init.d/ipv4-ipv6-gateway restart
tail -f /var/log/ipv4-ipv6-gateway.log
```

---

## Step 10: Common OpenWrt Issues

### Issue: Service starts but immediately stops

**Cause**: Procd service definition might be wrong

**Fix**: Edit `/etc/init.d/ipv4-ipv6-gateway` and check:

```bash
#!/bin/sh /etc/rc.common

START=99
STOP=01

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command "/usr/bin/python3" /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

Note: Added `stdout` and `stderr` capture.

### Issue: "Error: Failed to enable forwarding"

**Cause**: sysctl not available or wrong path

**Fix**:
```bash
# Find sysctl
which sysctl

# If missing:
opkg install procps-ng-sysctl

# Or manually enable:
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
```

---

## Quick Diagnostic Script

Save this as `/root/diagnose-gateway.sh`:

```bash
#!/bin/bash

echo "=========================================="
echo "IPv4↔IPv6 Gateway Diagnostics"
echo "=========================================="

echo -e "\n1. Python version:"
python3 --version 2>&1

echo -e "\n2. Required commands:"
for cmd in ip arp odhcp6c iptables sysctl; do
    which $cmd 2>&1 || echo "  ✗ $cmd NOT FOUND"
done

echo -e "\n3. File structure:"
ls -la /opt/ipv4-ipv6-gateway/ 2>&1

echo -e "\n4. Configuration directory:"
ls -la /etc/ipv4-ipv6-gateway/ 2>&1

echo -e "\n5. Service status:"
/etc/init.d/ipv4-ipv6-gateway status 2>&1

echo -e "\n6. Process check:"
ps | grep ipv4_ipv6_gateway | grep -v grep

echo -e "\n7. Recent logs:"
tail -20 /var/log/ipv4-ipv6-gateway.log 2>&1

echo -e "\n8. Network interfaces:"
ip link show 2>&1

echo -e "\n9. Test Python import:"
python3 -c "import sys; sys.path.insert(0, '/opt/ipv4-ipv6-gateway'); import gateway_config; print('✓ Config imported successfully')" 2>&1

echo -e "\n10. Try running service:"
python3 /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py 2>&1 &
sleep 2
ps | grep python3

echo -e "\n=========================================="
```

Run it:
```bash
chmod +x /root/diagnose-gateway.sh
/root/diagnose-gateway.sh
```

---

## Most Common Issues & Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| Python not found | `opkg install python3` |
| Command not found | Update paths in `gateway_config.py` |
| Permission denied | `chmod +x /opt/ipv4-ipv6-gateway/ipv4_ipv6_gateway.py` |
| Service won't stay running | Check logs: `tail -f /var/log/ipv4-ipv6-gateway.log` |
| No log output | Check `/var/log` is writable: `touch /var/log/test.log` |
| Interface not found | Update interface names in `gateway_config.py` |

---

## Get Help

If none of the above works, collect this information:

```bash
# 1. System info
uname -a
cat /etc/openwrt_release

# 2. Python info
python3 --version
python3 -c "import sys; print(sys.path)"

# 3. Service output
/etc/init.d/ipv4-ipv6-gateway start
/etc/init.d/ipv4-ipv6-gateway status

# 4. Manual run output
cd /opt/ipv4-ipv6-gateway
python3 ipv4_ipv6_gateway.py

# 5. Logs
cat /var/log/ipv4-ipv6-gateway.log
logread | tail -50

# 6. Process list
ps | grep python
```

Post this information for further assistance.

---

## Emergency: Start Service Manually

If all else fails, start manually:

```bash
# Start in background
cd /opt/ipv4-ipv6-gateway
nohup python3 ipv4_ipv6_gateway.py > /var/log/ipv4-ipv6-gateway.log 2>&1 &

# Check it's running
ps | grep python3

# Check API
curl http://127.0.0.1:5050/health
```

**Note**: This won't survive reboots. Fix the init.d script for permanent solution.
