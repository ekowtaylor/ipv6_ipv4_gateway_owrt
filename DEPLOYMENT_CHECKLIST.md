# Deployment Checklist

Use this checklist for deploying the IPv4↔IPv6 Gateway to your NanoPi R5C router.

---

## ✅ Pre-Deployment Checklist

### Hardware
- [ ] NanoPi R5C router powered on
- [ ] Ethernet cable connected to eth0 (will be IPv6 side)
- [ ] Ethernet cable connected to eth1 (will be IPv4 side)
- [ ] Computer connected to router for SSH access

### Network Information
- [ ] IPv6 network details confirmed (DHCP server available)
- [ ] Device MAC addresses registered on IPv6 firewall (if required)
- [ ] Static IP for eth1 decided (default: 192.168.1.1/24)

### Software Requirements
- [ ] OpenWrt installed on NanoPi R5C
- [ ] SSH access to router confirmed (ssh root@192.168.1.1)
- [ ] Root password set (if not already)

---

## 📦 Deployment Steps

### Option A: Fully Automatic (Recommended for Testing)

```bash
# 1. Copy all files to router
cd /path/to/ipv6_ipv4_gateway_owrt
scp *.py *.sh root@192.168.1.1:/tmp/

# 2. SSH and run full auto install
ssh root@192.168.1.1
cd /tmp
bash install.sh --full-auto

# 3. Verify
gateway-status
```

**Status**:
- [ ] Installation completed without errors
- [ ] Service started successfully
- [ ] Network configuration applied
- [ ] `gateway-status` returns JSON response

---

### Option B: Safe Manual Deployment (Recommended for Production)

```bash
# 1. Copy all files to router
cd /path/to/ipv6_ipv4_gateway_owrt
scp *.py *.sh root@192.168.1.1:/tmp/

# 2. SSH to router
ssh root@192.168.1.1
cd /tmp

# 3. Run installer (safe mode)
bash install.sh

# 4. Review network configuration
cat /etc/ipv4-ipv6-gateway/network-config.uci

# 5. Backup current network config (if not already backed up)
cp /etc/config/network /etc/config/network.backup.$(date +%s)

# 6. Apply network configuration
uci import < /etc/ipv4-ipv6-gateway/network-config.uci
uci commit network
/etc/init.d/network restart

# 7. Reconnect SSH (IP may have changed)
# If you can't reconnect, use serial console or factory reset

# 8. Start the service
/etc/init.d/ipv4-ipv6-gateway start

# 9. Verify service is running
/etc/init.d/ipv4-ipv6-gateway status
gateway-status
```

**Status**:
- [ ] Files copied successfully
- [ ] Installation completed
- [ ] Network config reviewed and understood
- [ ] Original network backed up
- [ ] Network config applied successfully
- [ ] SSH reconnected successfully
- [ ] Service started
- [ ] `gateway-status` returns valid JSON

---

## 🔍 Post-Deployment Verification

### 1. Service Health
```bash
# Check service is running
ps | grep ipv4_ipv6_gateway

# Check API is responding
gateway-status

# Check logs
tail -30 /var/log/ipv4-ipv6-gateway.log
```

**Expected**:
- [ ] Process is running
- [ ] API returns JSON with `"running": true`
- [ ] Logs show "Gateway service started"

---

### 2. Network Interfaces
```bash
# Check eth0 (IPv6 side)
ip link show eth0
ip -6 addr show eth0

# Check eth1 (IPv4 side)
ip link show eth1
ip -4 addr show eth1
```

**Expected**:
- [ ] eth0 is UP
- [ ] eth0 has IPv6 address (from DHCPv6)
- [ ] eth1 is UP
- [ ] eth1 has IPv4 address (192.168.1.1)

---

### 3. API Endpoints
```bash
# Health check
curl http://localhost:5050/health

# Status check
curl http://localhost:5050/status

# Device list
curl http://localhost:5050/devices
```

**Expected**:
- [ ] `/health` returns `{"status": "ok", ...}`
- [ ] `/status` returns `{"running": true, ...}`
- [ ] `/devices` returns `{"total": 0, "devices": []}`

---

### 4. Device Discovery Test
```bash
# 1. Connect a test device to eth1
# 2. Wait 10-15 seconds
# 3. Check if discovered

gateway-devices

# Or check logs
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i "discover"
```

**Expected**:
- [ ] Device MAC appears in ARP table
- [ ] Service discovers device
- [ ] DHCPv6 request succeeds
- [ ] IPv6 address assigned
- [ ] Device shows in `gateway-devices`

---

## 🛠️ Configuration Verification

### Confirm Critical Settings

```bash
# 1. API is set to bind to all interfaces (0.0.0.0)
grep "API_HOST" /opt/ipv4-ipv6-gateway/gateway_config.py
# Should show: API_HOST = "0.0.0.0"
```

**Status**:
- [ ] API_HOST is set to "0.0.0.0" (not "127.0.0.1")

```bash
# 2. Interfaces are correct
grep "INTERFACE" /opt/ipv4-ipv6-gateway/gateway_config.py
# Should show:
# ETH0_INTERFACE = "eth0"  # IPv6 side (network)
# ETH1_INTERFACE = "eth1"  # IPv4 side (devices)
```

**Status**:
- [ ] ETH0_INTERFACE = "eth0" (IPv6 side)
- [ ] ETH1_INTERFACE = "eth1" (IPv4 side)

```bash
# 3. Port is correct
grep "API_PORT" /opt/ipv4-ipv6-gateway/gateway_config.py
# Should show: API_PORT = 5050
```

**Status**:
- [ ] API_PORT = 5050

---

## 🔐 Security Checklist

### API Access
```bash
# Check what IP the API is listening on
netstat -tlnp | grep 5050
# Should show: 0.0.0.0:5050 or *:5050
```

**Status**:
- [ ] API listening on 0.0.0.0:5050 (accessible from network)
- [ ] Firewall rules added (if exposing to WAN)

**Note**: API has no authentication. Only expose to trusted networks!

### Firewall Rules (Optional - if exposing API)
```bash
# Restrict API to LAN only
iptables -A INPUT -p tcp --dport 5050 -i eth0 -j DROP
iptables -A INPUT -p tcp --dport 5050 -i eth1 -j ACCEPT

# Or restrict to specific subnet
iptables -A INPUT -p tcp --dport 5050 ! -s 192.168.1.0/24 -j DROP
```

**Status**:
- [ ] Firewall rules added (if needed)
- [ ] Rules tested and working

---

## 📊 Monitoring Setup

### Enable Auto-Start
```bash
# Ensure service starts on boot
/etc/init.d/ipv4-ipv6-gateway enable

# Verify
ls -la /etc/rc.d/S*ipv4-ipv6-gateway*
```

**Status**:
- [ ] Service enabled for auto-start
- [ ] Symlink exists in /etc/rc.d/

### Log Rotation (Optional)
```bash
# Create logrotate config
cat > /etc/logrotate.d/ipv4-ipv6-gateway << 'EOF'
/var/log/ipv4-ipv6-gateway.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 root root
}
EOF
```

**Status**:
- [ ] Log rotation configured

---

## 🧪 Final Testing

### Test Complete Workflow
```bash
# 1. Reboot router to test auto-start
reboot

# 2. Wait for boot (30-60 seconds)

# 3. Reconnect SSH
ssh root@192.168.1.1

# 4. Verify service auto-started
/etc/init.d/ipv4-ipv6-gateway status
gateway-status

# 5. Connect test device to eth1

# 6. Monitor discovery
tail -f /var/log/ipv4-ipv6-gateway.log

# 7. Verify device appears
gateway-devices
```

**Status**:
- [ ] Service auto-starts after reboot
- [ ] Network config persists after reboot
- [ ] Device discovery works
- [ ] DHCPv6 requests succeed
- [ ] API accessible

---

## 📝 Documentation

### Record Deployment Details
```
Deployment Date: _______________
Router Model: NanoPi R5C
Router IP (eth1): 192.168.1.1
IPv6 Network: _______________
Number of Devices: _______________
Notes: _______________
_______________
_______________
```

### Save Important Information
- [ ] Original network config backed up
- [ ] Router login credentials documented
- [ ] IPv6 network details recorded
- [ ] MAC addresses of devices documented
- [ ] Deployment notes saved

---

## 🚨 Troubleshooting

If anything fails, see:
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Comprehensive troubleshooting guide
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Detailed deployment instructions
- **[README.md](README.md)** - Project overview and quick reference

### Quick Checks
```bash
# 1. Service not starting
tail -50 /var/log/ipv4-ipv6-gateway.log

# 2. API not responding
netstat -tlnp | grep 5050
curl -v http://127.0.0.1:5050/health

# 3. Devices not discovered
tail -f /var/log/ipv4-ipv6-gateway.log | grep -i arp
ip neigh show dev eth1

# 4. DHCPv6 failing
grep -i dhcp /var/log/ipv4-ipv6-gateway.log
```

---

## ✅ Deployment Complete!

Once all items are checked:
- [ ] **All checklist items completed**
- [ ] **Service running and stable**
- [ ] **Devices being discovered**
- [ ] **No errors in logs**
- [ ] **Documentation saved**

🎉 **Your IPv4↔IPv6 Gateway is now operational!**

---

## 📞 Support

Need help? Check:
1. Service logs: `tail -f /var/log/ipv4-ipv6-gateway.log`
2. System logs: `logread | tail -50`
3. API status: `gateway-status`
4. Documentation: All .md files in project directory
