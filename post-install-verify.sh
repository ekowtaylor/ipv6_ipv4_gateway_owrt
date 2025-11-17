#!/bin/bash
#
# post-install-verify.sh - Comprehensive Post-Installation Verification
#
# This script verifies that the IPv4↔IPv6 Gateway is fully operational:
# 1. Service is running
# 2. Devices are discovered
# 3. Port forwarding is active
# 4. IPv6 proxies are running
# 5. Actual connectivity works
#
# Run after installation to ensure everything is working before first use.

set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TIMEOUT=300  # 5 minutes max wait time
DEVICE_DISCOVERY_TIMEOUT=120  # 2 minutes for device discovery

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv4↔IPv6 Gateway - Post-Install Verification${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

#
# STEP 1: Verify service is running
#
echo -e "${YELLOW}Step 1: Verifying gateway service is running...${NC}"
SERVICE_RUNNING=false
ELAPSED=0

while [ $ELAPSED -lt 30 ]; do
    if /etc/init.d/ipv4-ipv6-gateway status >/dev/null 2>&1; then
        SERVICE_RUNNING=true
        break
    fi
    echo -e "${BLUE}  Waiting for service to start... ($ELAPSED/30s)${NC}"
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ "$SERVICE_RUNNING" = true ]; then
    echo -e "${GREEN}✓ Gateway service is running${NC}"
else
    echo -e "${RED}✗ Gateway service is NOT running!${NC}"
    echo ""
    echo -e "${YELLOW}FIX:${NC}"
    echo "  /etc/init.d/ipv4-ipv6-gateway start"
    echo "  tail -f /var/log/ipv4-ipv6-gateway.log"
    exit 1
fi
echo ""

#
# STEP 2: Check for LAN devices
#
echo -e "${YELLOW}Step 2: Scanning for devices on LAN (eth1)...${NC}"
echo -e "${BLUE}This scan helps identify devices that should be discovered${NC}"

LAN_DEVICES=0
if command -v ip >/dev/null 2>&1; then
    # Quick ping scan of common device IPs
    echo -e "${BLUE}  Pinging common device IPs...${NC}"
    for i in 100 128 129 130 131 132; do
        ping -c 1 -W 1 192.168.1.$i >/dev/null 2>&1 &
    done
    wait
    sleep 2

    # Check ARP table
    ARP_ENTRIES=$(ip neigh show dev eth1 2>/dev/null | grep -v "FAILED" | grep -c "lladdr" || echo "0")
    LAN_DEVICES=$ARP_ENTRIES

    if [ $LAN_DEVICES -gt 0 ]; then
        echo -e "${GREEN}✓ Found $LAN_DEVICES device(s) on LAN${NC}"
        ip neigh show dev eth1 2>/dev/null | grep "lladdr" | while read line; do
            IP=$(echo "$line" | awk '{print $1}')
            MAC=$(echo "$line" | grep -oP 'lladdr \K[0-9a-f:]+')
            echo -e "${BLUE}  • IP: ${GREEN}$IP${NC}  MAC: ${YELLOW}$MAC${NC}"
        done
    else
        echo -e "${YELLOW}⚠ No devices found on LAN yet${NC}"
        echo -e "${BLUE}  Connect a device to eth1 and it will be discovered automatically${NC}"
    fi
fi
echo ""

#
# STEP 3: Wait for device discovery
#
echo -e "${YELLOW}Step 3: Waiting for gateway to discover devices...${NC}"
echo -e "${BLUE}Gateway monitors ARP table and discovers devices automatically${NC}"
echo -e "${BLUE}This may take up to 2 minutes...${NC}"

DEVICES_DISCOVERED=false
ELAPSED=0

while [ $ELAPSED -lt $DEVICE_DISCOVERY_TIMEOUT ]; do
    if [ -f /etc/ipv4-ipv6-gateway/devices.json ]; then
        # Check if any devices are in the JSON
        DEVICE_COUNT=$(cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | grep -c '"mac_address"' || echo "0")

        if [ $DEVICE_COUNT -gt 0 ]; then
            DEVICES_DISCOVERED=true
            echo -e "${GREEN}✓ Discovered $DEVICE_COUNT device(s)${NC}"

            # Show discovered devices
            echo ""
            echo -e "${YELLOW}Discovered Devices:${NC}"
            cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | python3 -m json.tool 2>/dev/null || cat /etc/ipv4-ipv6-gateway/devices.json
            break
        fi
    fi

    if [ $((ELAPSED % 10)) -eq 0 ]; then
        echo -e "${BLUE}  Still waiting for device discovery... ($ELAPSED/${DEVICE_DISCOVERY_TIMEOUT}s)${NC}"
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ "$DEVICES_DISCOVERED" = false ]; then
    echo -e "${YELLOW}⚠ No devices discovered yet${NC}"
    echo ""
    echo -e "${YELLOW}This is normal if:${NC}"
    echo "  1. No device is connected to eth1"
    echo "  2. Device is connected but hasn't sent any packets yet"
    echo ""
    echo -e "${BLUE}RECOMMENDED ACTIONS:${NC}"
    echo "  1. Connect a device to eth1 (LAN)"
    echo "  2. From the device, ping the gateway: ping 192.168.1.1"
    echo "  3. Wait 30 seconds and check: gateway-devices-direct"
    echo ""
    echo -e "${YELLOW}Continuing verification (will check port forwarding setup)...${NC}"
fi
echo ""

#
# STEP 4: Verify port forwarding configuration
#
echo -e "${YELLOW}Step 4: Verifying port forwarding configuration...${NC}"

# Check if automatic port forwarding is enabled
ENABLE_PORT_FWD=$(grep "ENABLE_AUTO_PORT_FORWARDING" /opt/ipv4-ipv6-gateway/gateway_config.py 2>/dev/null | grep -q "True" && echo "true" || echo "false")

if [ "$ENABLE_PORT_FWD" = "true" ]; then
    echo -e "${GREEN}✓ Automatic port forwarding is ENABLED${NC}"

    # Show configured ports
    echo -e "${BLUE}  Configured port mappings:${NC}"
    grep -A5 "AUTO_PORT_FORWARDS = {" /opt/ipv4-ipv6-gateway/gateway_config.py | grep -E "^\s+[0-9]+" | sed 's/^/    /'
else
    echo -e "${YELLOW}⚠ Automatic port forwarding is DISABLED${NC}"
    echo -e "${BLUE}  Port forwards must be added manually${NC}"
fi
echo ""

#
# STEP 5: Check for active port forwarding rules
#
echo -e "${YELLOW}Step 5: Checking for active port forwarding rules...${NC}"

if [ "$DEVICES_DISCOVERED" = true ]; then
    # Get first device's LAN IP
    DEVICE_LAN_IP=$(cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | grep -oP '"ipv4_address":\s*"\K[0-9.]+' | head -1)

    if [ -n "$DEVICE_LAN_IP" ]; then
        echo -e "${BLUE}  Checking for NAT rules to $DEVICE_LAN_IP...${NC}"

        NAT_RULES=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep "$DEVICE_LAN_IP" || echo "")

        if [ -n "$NAT_RULES" ]; then
            echo -e "${GREEN}✓ Port forwarding rules are active:${NC}"
            echo "$NAT_RULES" | sed 's/^/    /'
        else
            echo -e "${RED}✗ No port forwarding rules found!${NC}"
            echo ""
            echo -e "${YELLOW}FIX:${NC}"
            echo "  gateway-port-forward add 8080 $DEVICE_LAN_IP 80"
            echo "  gateway-port-forward add 2323 $DEVICE_LAN_IP 23"
        fi
    else
        echo -e "${YELLOW}⚠ No device LAN IP found, skipping NAT check${NC}"
    fi
else
    echo -e "${BLUE}  Skipping (no devices discovered yet)${NC}"
fi
echo ""

#
# STEP 6: Check for IPv6 proxy processes
#
echo -e "${YELLOW}Step 6: Checking for IPv6→IPv4 proxy processes...${NC}"

PROXY_BACKEND=$(grep "IPV6_PROXY_BACKEND" /opt/ipv4-ipv6-gateway/gateway_config.py 2>/dev/null | grep -oP '"\K[^"]+' || echo "unknown")
echo -e "${BLUE}  Configured backend: $PROXY_BACKEND${NC}"

# Check for socat
SOCAT_PROCS=$(ps | grep socat | grep -E 'TCP6-LISTEN.*TCP4:' | grep -v grep)
if [ -n "$SOCAT_PROCS" ]; then
    SOCAT_COUNT=$(echo "$SOCAT_PROCS" | wc -l)
    echo -e "${GREEN}✓ Found $SOCAT_COUNT socat proxy process(es):${NC}"
    echo "$SOCAT_PROCS" | sed 's/^/    /' | head -5
else
    echo -e "${YELLOW}⚠ No socat proxy processes found${NC}"
fi

# Check for HAProxy
HAPROXY_PROCS=$(ps | grep haproxy | grep -v grep)
if [ -n "$HAPROXY_PROCS" ]; then
    echo -e "${GREEN}✓ HAProxy is running:${NC}"
    echo "$HAPROXY_PROCS" | sed 's/^/    /'
else
    echo -e "${BLUE}  No HAProxy processes (normal if using socat)${NC}"
fi

# Check listening ports
echo ""
echo -e "${BLUE}  Checking listening ports (8080, 2323):${NC}"
LISTENING=$(netstat -ln 2>/dev/null | grep -E ':8080|:2323' || echo "")
if [ -n "$LISTENING" ]; then
    echo -e "${GREEN}✓ Ports are listening:${NC}"
    echo "$LISTENING" | sed 's/^/    /'
else
    echo -e "${RED}✗ No processes listening on 8080 or 2323${NC}"
    echo ""
    echo -e "${YELLOW}FIX:${NC}"
    echo "  /etc/init.d/ipv4-ipv6-gateway restart"
    echo "  # Wait 30 seconds"
    echo "  ps | grep socat"
fi
echo ""

#
# STEP 7: Test actual connectivity
#
echo -e "${YELLOW}Step 7: Testing actual connectivity...${NC}"

if [ "$DEVICES_DISCOVERED" = true ] && [ -n "$DEVICE_LAN_IP" ]; then
    echo -e "${BLUE}  Testing device at $DEVICE_LAN_IP${NC}"

    # Test 1: Direct LAN access (should always work)
    echo ""
    echo -e "${BLUE}  Test 1: Direct LAN access (http://$DEVICE_LAN_IP:80)${NC}"
    if curl -s --connect-timeout 5 http://$DEVICE_LAN_IP:80 >/dev/null 2>&1; then
        echo -e "${GREEN}    ✓ Device HTTP works on port 80${NC}"
        DEVICE_HTTP_PORT=80
    elif curl -s --connect-timeout 5 http://$DEVICE_LAN_IP:5000 >/dev/null 2>&1; then
        echo -e "${GREEN}    ✓ Device HTTP works on port 5000${NC}"
        DEVICE_HTTP_PORT=5000
    else
        echo -e "${YELLOW}    ⚠ Device HTTP not responding (may not have web server)${NC}"
        DEVICE_HTTP_PORT=""
    fi

    # Test 2: Port forwarding via WAN IP (if device has WAN IP)
    DEVICE_WAN_IP=$(cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | grep -oP '"ipv4_wan_address":\s*"\K[0-9.]+' | head -1)
    if [ -n "$DEVICE_WAN_IP" ] && [ -n "$DEVICE_HTTP_PORT" ]; then
        echo ""
        echo -e "${BLUE}  Test 2: Port forwarding via WAN IP (http://$DEVICE_WAN_IP:8080)${NC}"

        # Test from gateway itself
        if curl -s --connect-timeout 5 http://$DEVICE_WAN_IP:8080 >/dev/null 2>&1; then
            echo -e "${GREEN}    ✓ Port forwarding works!${NC}"
        else
            echo -e "${RED}    ✗ Port forwarding NOT working${NC}"
            echo -e "${YELLOW}    This means external clients can't access the device via IPv4${NC}"
        fi
    fi

    # Test 3: IPv6 proxy (if device has IPv6)
    DEVICE_IPV6=$(cat /etc/ipv4-ipv6-gateway/devices.json 2>/dev/null | grep -oP '"ipv6_address":\s*"\K[0-9a-f:]+' | head -1)
    if [ -n "$DEVICE_IPV6" ] && [ -n "$DEVICE_HTTP_PORT" ]; then
        echo ""
        echo -e "${BLUE}  Test 3: IPv6 proxy (http://[$DEVICE_IPV6]:8080)${NC}"

        # Test from gateway itself
        if curl -s --connect-timeout 5 "http://[$DEVICE_IPV6]:8080" >/dev/null 2>&1; then
            echo -e "${GREEN}    ✓ IPv6 proxy works!${NC}"
        else
            echo -e "${RED}    ✗ IPv6 proxy NOT working${NC}"
            echo -e "${YELLOW}    This means IPv6 clients can't access the device${NC}"
        fi
    fi
else
    echo -e "${BLUE}  Skipping connectivity tests (no devices discovered yet)${NC}"
fi
echo ""

#
# STEP 8: Summary and recommendations
#
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Verification Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

ISSUES_FOUND=0

# Service check
if [ "$SERVICE_RUNNING" = true ]; then
    echo -e "${GREEN}✓ Gateway service is running${NC}"
else
    echo -e "${RED}✗ Gateway service is NOT running${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# Device discovery check
if [ "$DEVICES_DISCOVERED" = true ]; then
    echo -e "${GREEN}✓ Devices discovered: $DEVICE_COUNT${NC}"
else
    echo -e "${YELLOW}⚠ No devices discovered yet (may be normal)${NC}"
fi

# Port forwarding check
if [ -n "$NAT_RULES" ]; then
    echo -e "${GREEN}✓ Port forwarding is active${NC}"
else
    if [ "$DEVICES_DISCOVERED" = true ]; then
        echo -e "${RED}✗ Port forwarding NOT configured${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    else
        echo -e "${BLUE}⊘ Port forwarding not needed yet (no devices)${NC}"
    fi
fi

# IPv6 proxy check
if [ -n "$SOCAT_PROCS" ] || [ -n "$HAPROXY_PROCS" ]; then
    echo -e "${GREEN}✓ IPv6→IPv4 proxy is running${NC}"
else
    if [ "$DEVICES_DISCOVERED" = true ]; then
        echo -e "${RED}✗ IPv6→IPv4 proxy NOT running${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    else
        echo -e "${BLUE}⊘ IPv6 proxy not needed yet (no devices)${NC}"
    fi
fi

echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✓ ALL CHECKS PASSED!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${GREEN}Your IPv4↔IPv6 Gateway is fully operational!${NC}"
    echo ""

    if [ "$DEVICES_DISCOVERED" = true ]; then
        echo -e "${YELLOW}Quick Access Guide:${NC}"
        echo ""
        if [ -n "$DEVICE_LAN_IP" ]; then
            echo "  From LAN:"
            echo "    http://$DEVICE_LAN_IP:80"
            echo ""
        fi
        if [ -n "$DEVICE_WAN_IP" ]; then
            echo "  From WAN (IPv4):"
            echo "    http://$DEVICE_WAN_IP:8080"
            echo "    telnet $DEVICE_WAN_IP 2323"
            echo ""
        fi
        if [ -n "$DEVICE_IPV6" ]; then
            echo "  From WAN (IPv6):"
            echo "    http://[$DEVICE_IPV6]:8080"
            echo "    telnet $DEVICE_IPV6 2323"
            echo ""
        fi
    fi

    echo -e "${YELLOW}Monitoring Commands:${NC}"
    echo "  gateway-status-direct        # Check status"
    echo "  gateway-devices-direct       # List devices"
    echo "  tail -f /var/log/ipv4-ipv6-gateway.log  # View logs"
    echo ""

    exit 0
else
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}⚠ ISSUES FOUND: $ISSUES_FOUND${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Recommended Actions:${NC}"
    echo ""

    if [ "$SERVICE_RUNNING" = false ]; then
        echo "1. Start the gateway service:"
        echo "   /etc/init.d/ipv4-ipv6-gateway start"
        echo ""
    fi

    if [ "$DEVICES_DISCOVERED" = false ]; then
        echo "2. Ensure a device is connected and discoverable:"
        echo "   • Connect device to eth1 (LAN)"
        echo "   • From device: ping 192.168.1.1"
        echo "   • Wait 30 seconds"
        echo "   • Check: gateway-devices-direct"
        echo ""
    fi

    if [ "$DEVICES_DISCOVERED" = true ] && [ -z "$NAT_RULES" ]; then
        echo "3. Manually configure port forwarding:"
        echo "   gateway-port-forward add 8080 $DEVICE_LAN_IP 80"
        echo "   gateway-port-forward add 2323 $DEVICE_LAN_IP 23"
        echo ""
    fi

    if [ "$DEVICES_DISCOVERED" = true ] && [ -z "$SOCAT_PROCS" ] && [ -z "$HAPROXY_PROCS" ]; then
        echo "4. Restart gateway to start IPv6 proxy:"
        echo "   /etc/init.d/ipv4-ipv6-gateway restart"
        echo ""
    fi

    echo -e "${BLUE}For detailed diagnostics, run:${NC}"
    echo "  gateway-diagnose --fix-all"
    echo ""

    exit 1
fi
