#!/bin/bash
#
# IPv6→IPv4 Proxy Troubleshooting Script
# Diagnoses and fixes proxy backend issues
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/ipv4-ipv6-gateway"
LOG_FILE="/var/log/ipv4-ipv6-gateway.log"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IPv6→IPv4 Proxy Troubleshooting${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running on gateway
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${RED}Error: Gateway not installed at $INSTALL_DIR${NC}"
    exit 1
fi

# Step 1: Check configured backend
echo -e "${YELLOW}Step 1: Checking configured proxy backend...${NC}"
BACKEND=$(grep "IPV6_PROXY_BACKEND" "$INSTALL_DIR/gateway_config.py" | grep -o '"[^"]*"' | tr -d '"')
echo -e "${BLUE}Configured backend: $BACKEND${NC}"
echo ""

# Step 2: Check if proxy is enabled
echo -e "${YELLOW}Step 2: Checking if proxy is enabled...${NC}"
PROXY_ENABLED=$(grep "^ENABLE_IPV6_TO_IPV4_PROXY" "$INSTALL_DIR/gateway_config.py" | grep -o 'True\|False' | head -1)
if [ "$PROXY_ENABLED" = "True" ]; then
    echo -e "${GREEN}✓ IPv6→IPv4 proxy is enabled${NC}"
else
    echo -e "${RED}✗ IPv6→IPv4 proxy is DISABLED${NC}"
    echo -e "${YELLOW}Fix: Edit $INSTALL_DIR/gateway_config.py${NC}"
    echo -e "${YELLOW}     Set: ENABLE_IPV6_TO_IPV4_PROXY = True${NC}"
    exit 1
fi
echo ""

# Step 3: Check if backend software is installed
echo -e "${YELLOW}Step 3: Checking if $BACKEND is installed...${NC}"
if [ "$BACKEND" = "haproxy" ]; then
    if command -v haproxy >/dev/null 2>&1; then
        VERSION=$(haproxy -v 2>&1 | head -1)
        echo -e "${GREEN}✓ HAProxy installed: $VERSION${NC}"
    else
        echo -e "${RED}✗ HAProxy NOT installed${NC}"
        echo -e "${YELLOW}Fix: opkg install haproxy${NC}"
        echo -e "${YELLOW}Or switch to socat:${NC}"
        echo "  sed -i 's/IPV6_PROXY_BACKEND = \"haproxy\"/IPV6_PROXY_BACKEND = \"socat\"/' $INSTALL_DIR/gateway_config.py"
        echo "  /etc/init.d/ipv4-ipv6-gateway restart"
        exit 1
    fi
elif [ "$BACKEND" = "socat" ]; then
    if command -v socat >/dev/null 2>&1; then
        VERSION=$(socat -V 2>&1 | head -1)
        echo -e "${GREEN}✓ socat installed: $VERSION${NC}"
    else
        echo -e "${RED}✗ socat NOT installed${NC}"
        echo -e "${YELLOW}Fix: opkg install socat${NC}"
        exit 1
    fi
fi
echo ""

# Step 4: Check if proxy process is running
echo -e "${YELLOW}Step 4: Checking if $BACKEND is running...${NC}"
if [ "$BACKEND" = "haproxy" ]; then
    PROCESSES=$(ps | grep haproxy | grep -v grep || true)
    if [ -n "$PROCESSES" ]; then
        echo -e "${GREEN}✓ HAProxy is running:${NC}"
        echo "$PROCESSES"
    else
        echo -e "${RED}✗ HAProxy is NOT running${NC}"
        echo -e "${YELLOW}This is the problem! HAProxy should be running but isn't.${NC}"
        echo ""
        echo -e "${YELLOW}Checking why HAProxy isn't running...${NC}"

        # Check if config exists
        if [ -f "/etc/haproxy/haproxy.cfg" ]; then
            echo -e "${BLUE}HAProxy config exists, testing it...${NC}"
            if haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1; then
                echo -e "${GREEN}✓ Config is valid${NC}"
            else
                echo -e "${RED}✗ Config has errors${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ HAProxy config doesn't exist yet${NC}"
            echo -e "${YELLOW}  This is normal if no devices have been discovered${NC}"
        fi

        echo ""
        echo -e "${YELLOW}Quick Fix Options:${NC}"
        echo ""
        echo "Option 1: Restart gateway service (will auto-start HAProxy)"
        echo "  /etc/init.d/ipv4-ipv6-gateway restart"
        echo "  sleep 10"
        echo "  ps | grep haproxy"
        echo ""
        echo "Option 2: Switch to socat (more reliable for simple cases)"
        echo "  sed -i 's/IPV6_PROXY_BACKEND = \"haproxy\"/IPV6_PROXY_BACKEND = \"socat\"/' $INSTALL_DIR/gateway_config.py"
        echo "  /etc/init.d/ipv4-ipv6-gateway restart"
        echo ""

        read -p "Apply Option 1 (restart service)? (y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Restarting gateway service...${NC}"
            /etc/init.d/ipv4-ipv6-gateway restart
            echo -e "${BLUE}Waiting 10 seconds for startup...${NC}"
            sleep 10

            PROCESSES=$(ps | grep haproxy | grep -v grep || true)
            if [ -n "$PROCESSES" ]; then
                echo -e "${GREEN}✓ HAProxy is now running!${NC}"
                echo "$PROCESSES"
                echo ""
                echo -e "${GREEN}Try your telnet/curl command again${NC}"
                exit 0
            else
                echo -e "${RED}✗ HAProxy still not running${NC}"
                echo -e "${YELLOW}Check logs: tail -50 $LOG_FILE | grep -i haproxy${NC}"
                exit 1
            fi
        fi

        exit 1
    fi
elif [ "$BACKEND" = "socat" ]; then
    PROCESSES=$(ps | grep socat | grep -v grep || true)
    if [ -n "$PROCESSES" ]; then
        echo -e "${GREEN}✓ socat is running:${NC}"
        echo "$PROCESSES"
    else
        echo -e "${RED}✗ socat is NOT running${NC}"
        echo -e "${YELLOW}Restarting gateway service...${NC}"
        /etc/init.d/ipv4-ipv6-gateway restart
        sleep 5

        PROCESSES=$(ps | grep socat | grep -v grep || true)
        if [ -n "$PROCESSES" ]; then
            echo -e "${GREEN}✓ socat is now running${NC}"
        else
            echo -e "${RED}✗ socat still not running${NC}"
            echo -e "${YELLOW}Check logs: tail -50 $LOG_FILE${NC}"
            exit 1
        fi
    fi
fi
echo ""

# Step 5: Check gateway logs for proxy errors
echo -e "${YELLOW}Step 5: Checking recent proxy logs...${NC}"
if [ -f "$LOG_FILE" ]; then
    PROXY_LOGS=$(tail -100 "$LOG_FILE" | grep -iE "proxy|haproxy|socat" || true)
    if [ -n "$PROXY_LOGS" ]; then
        echo -e "${BLUE}Recent proxy-related logs:${NC}"
        echo "$PROXY_LOGS" | tail -20
    else
        echo -e "${YELLOW}⚠ No recent proxy logs found${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Log file not found${NC}"
fi
echo ""

# Step 6: Get device info (single-device mode)
echo -e "${YELLOW}Step 6: Getting device information...${NC}"
DEVICE_FILE="/etc/ipv4-ipv6-gateway/device.json"

if [ -f "$DEVICE_FILE" ]; then
    DEVICE=$(cat "$DEVICE_FILE" 2>/dev/null || echo "{}")
    echo -e "${BLUE}Configured device:${NC}"
    echo "$DEVICE" | python3 -m json.tool 2>/dev/null || echo "$DEVICE"
else
    echo -e "${YELLOW}⚠ No device file found${NC}"
    echo -e "${YELLOW}  This is normal if no device has been discovered yet${NC}"
fi
echo ""

# Step 7: Test direct connection to device (bypass proxy)
echo -e "${YELLOW}Step 7: Testing direct connection to device...${NC}"
if [ -f "$DEVICE_FILE" ]; then
    # Extract device IP (single-device mode)
    DEVICE_IP=$(cat "$DEVICE_FILE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('lan_ipv4', ''))" 2>/dev/null || echo "")

    if [ -n "$DEVICE_IP" ]; then
        echo -e "${BLUE}Testing telnet to $DEVICE_IP:23 (direct, bypass proxy)...${NC}"
        timeout 3 telnet "$DEVICE_IP" 23 >/dev/null 2>&1 && \
            echo -e "${GREEN}✓ Direct connection works${NC}" || \
            echo -e "${RED}✗ Direct connection failed${NC}"

        echo -e "${BLUE}Testing HTTP to $DEVICE_IP:80 (direct, bypass proxy)...${NC}"
        timeout 3 curl -s "http://$DEVICE_IP:80" >/dev/null 2>&1 && \
            echo -e "${GREEN}✓ Direct HTTP works${NC}" || \
            echo -e "${RED}✗ Direct HTTP failed${NC}"
    else
        echo -e "${YELLOW}⚠ No device IP found in $DEVICE_FILE${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No device configured yet${NC}"
fi
echo ""

# Summary and recommendations
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Backend: $BACKEND"
echo "  Proxy enabled: $PROXY_ENABLED"
echo ""

if [ "$BACKEND" = "haproxy" ]; then
    PROCESSES=$(ps | grep haproxy | grep -v grep || true)
    if [ -n "$PROCESSES" ]; then
        echo -e "${GREEN}✓ HAProxy is running - proxy should work${NC}"
        echo ""
        echo -e "${YELLOW}If you still see connection resets:${NC}"
        echo "1. Check HAProxy stats: curl http://192.168.1.1:8404/stats"
        echo "2. Watch logs: tail -f $LOG_FILE | grep -i haproxy"
        echo "3. Verify device IP is correct in devices.json"
        echo "4. Try switching to socat if issues persist"
    else
        echo -e "${RED}✗ HAProxy is NOT running - this is the problem${NC}"
        echo ""
        echo -e "${YELLOW}Recommended fix:${NC}"
        echo "/etc/init.d/ipv4-ipv6-gateway restart"
    fi
elif [ "$BACKEND" = "socat" ]; then
    PROCESSES=$(ps | grep socat | grep -v grep || true)
    if [ -n "$PROCESSES" ]; then
        echo -e "${GREEN}✓ socat is running - proxy should work${NC}"
        echo ""
        echo -e "${YELLOW}If you still see connection resets with socat:${NC}"
        echo "1. Switch to HAProxy (better protocol handling)"
        echo "   sed -i 's/IPV6_PROXY_BACKEND = \"socat\"/IPV6_PROXY_BACKEND = \"haproxy\"/' $INSTALL_DIR/gateway_config.py"
        echo "   opkg install haproxy"
        echo "   /etc/init.d/ipv4-ipv6-gateway restart"
    else
        echo -e "${RED}✗ socat is NOT running - this is the problem${NC}"
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
