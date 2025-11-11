# Quick Fix Guide - IPv4↔IPv6 Gateway Issues

## 🚨 If You're Seeing Connection Errors

Based on the errors shown in your screenshot, here's what's happening and how to fix it:

### **Problem 1: eth1 Not Configured**
**Symptom**: Ping to `192.168.1.1` fails with 100% packet loss

**Cause**: The network configuration has not been applied to the router yet. The install script created the config files but didn't apply them (because `--apply-network` flag wasn't used).

**Fix**: Apply the network configuration

### **Problem 2: API Not Accessible**
**Symptom**: `gateway-status` and `gateway-devices` commands fail with "Failed to connect to API server"

**Cause**: Without eth1 having the 192.168.1.1 IP address, the API server can't be reached, even though it's running.

**Fix**: Apply the network configuration (same as Problem 1)

---

## 🔧 Solution: Run the Diagnostic & Fix Script

### Step 1: SSH to Your Router
```bash
ssh root@192.168.1.1
# Or whatever IP your router currently has
```

### Step 2: Run the Diagnostic Script
The quick-deploy.sh script should have copied `diagnose-and-fix.sh` to `/tmp/` on your router.

```bash
/tmp/diagnose-and-fix.sh
```

This will:
- Check all network configurations
- Check service status
- Check API connectivity
- Provide a detailed report

### Step 3: Apply All Fixes Automatically
```bash
/tmp/diagnose-and-fix.sh --fix-all
```

This will:
1. **Apply network configuration** - Sets eth1 to 192.168.1.1 and eth0 to DHCPv6
2. **Restart network** - Applies the changes
3. **Start DHCP server** - Ensures dnsmasq is running
4. **Start gateway service** - Ensures the gateway is running

### Step 4: Verify Everything Works
```bash
/tmp/diagnose-and-fix.sh
```

You should now see most checks passing.

---

## 📋 Alternative: Manual Fix

If you prefer to apply fixes manually:

### Fix Network Configuration
```bash
# Backup current config
uci export network > /root/network.backup.uci
uci export dhcp > /root/dhcp.backup.uci

# Apply gateway network config
uci import network < /etc/ipv4-ipv6-gateway/network-config.uci
uci import dhcp < /etc/ipv4-ipv6-gateway/dhcp-config.uci
uci commit

# Restart network
/etc/init.d/network restart
sleep 3

# Restart DHCP server
/etc/init.d/dnsmasq restart
```

### Start Gateway Service
```bash
/etc/init.d/ipv4-ipv6-gateway start
```

### Verify
```bash
# Check eth1 has correct IP
ip addr show eth1 | grep 192.168.1.1

# Test API
gateway-status

# Or use curl
curl http://192.168.1.1:5050/health
```

---

## 🔍 Diagnostic Script Options

```bash
# Run diagnostic only (no changes)
/tmp/diagnose-and-fix.sh

# Fix network configuration only
/tmp/diagnose-and-fix.sh --fix-network

# Fix service only (restart it)
/tmp/diagnose-and-fix.sh --fix-service

# Apply all fixes automatically
/tmp/diagnose-and-fix.sh --fix-all
```

---

## ✅ Expected Output After Fix

After running `--fix-all`, you should see:

```
Checks passed: 13/14 (or similar)
```

And commands should work:
```bash
$ gateway-status
{
  "running": true,
  "devices": {},
  "device_count": 0,
  ...
}

$ gateway-devices
Total devices: 0
No devices found

$ ping 192.168.1.1
PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: seq=0 ttl=64 time=0.123 ms
```

---

## 🆘 If Issues Persist

### Check Service Logs
```bash
tail -50 /var/log/ipv4-ipv6-gateway.log
```

### Check System Logs
```bash
logread | grep -i gateway
logread | grep -i network
```

### Verify Network Interfaces
```bash
ip addr show
ip link show
```

### Check if Services are Running
```bash
ps | grep python
ps | grep dnsmasq
netstat -tuln | grep 5050
```

### Manual Restart Everything
```bash
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
/etc/init.d/ipv4-ipv6-gateway restart
```

---

## 📞 Common Issues

### "Network config file not found"
The install script didn't create the network config files. Re-run:
```bash
cd /tmp
./install.sh --apply-network
```

### "Service starts but immediately stops"
Check dependencies are installed:
```bash
opkg update
opkg install python3 python3-pip odhcp6c iptables ip-full
```

### "API still not accessible after fix"
1. Check if process is running: `ps | grep ipv4_ipv6_gateway`
2. Check if port is open: `netstat -tuln | grep 5050`
3. Check firewall: `iptables -L INPUT -n | grep 5050`
4. Check logs: `tail -50 /var/log/ipv4-ipv6-gateway.log`

---

## 🎯 Quick Deploy Workflow (For Next Time)

To avoid this issue in future deployments:

```bash
# From your computer, run:
./quick-deploy.sh --full-auto
```

This will:
1. Copy files to router
2. Run install script with `--apply-network` and `--auto-start`
3. Apply network configuration automatically
4. Start service automatically
5. Test and display status

Then SSH to router and run diagnostic:
```bash
ssh root@192.168.1.1
/tmp/diagnose-and-fix.sh --fix-all
```

---

## 📝 Summary

**The core issue**: Network configuration wasn't applied during installation.

**The fix**: Run `/tmp/diagnose-and-fix.sh --fix-all` on the router.

**Prevention**: Use `./quick-deploy.sh --full-auto` and then run the diagnostic script to verify everything is configured correctly.
