#!/bin/sh
#
# verify.sh — Health check for IPv4↔IPv6 Gateway deployment
#
# Checks:
#   - Service status (systemd / init.d)
#   - Process presence
#   - API /health and /status
#   - Basic network (lan/wan or ip addr)
#

SERVICE_NAME="ipv4-ipv6-gateway"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
INIT_SCRIPT="/etc/init.d/${SERVICE_NAME}"
API_BASE="http://127.0.0.1:5050"

# Color codes (use printf instead of echo -e for portability)
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

set -e

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv4↔IPv6 Gateway Verification Script${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Detect init system
if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
else
    INIT_SYSTEM="initd"
fi
echo -e "${BLUE}Detected init system: ${INIT_SYSTEM}${NC}\n"

http_get() {
    URL="$1"

    if command -v curl >/dev/null 2>&1; then
        if curl -sS "$URL" >/dev/null 2>&1; then
            curl -s "$URL"
            return 0
        fi
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -qO- "$URL"
        return 0
    fi

    echo "ERROR: neither working curl nor wget is available" >&2
    return 1
}

# 1. Service status
echo -e "${YELLOW}1) Service status${NC}"

if [ "$INIT_SYSTEM" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl list-units --type=service 2>/dev/null | grep -q "$SERVICE_NAME.service"; then
        echo -e "${BLUE}- systemd status:${NC}"
        systemctl is-active "$SERVICE_NAME" && \
            echo -e "${GREEN}  -> Service is active (systemd)${NC}" || \
            echo -e "${RED}  -> Service is NOT active (systemd)${NC}"
        echo ""
    else
        echo -e "${YELLOW}  -> systemd unit not found for ${SERVICE_NAME}${NC}"
    fi
fi

if [ -x "$INIT_SCRIPT" ]; then
    echo -e "${BLUE}- init.d status:${NC}"
    "$INIT_SCRIPT" status || true
else
    echo -e "${YELLOW}  -> /etc/init.d/${SERVICE_NAME} not found${NC}"
fi
echo ""

# 2. Process check
echo -e "${YELLOW}2) Process check${NC}"
if pgrep -f "ipv4_ipv6_gateway.py" >/dev/null 2>&1; then
    PIDS="$(pgrep -f "ipv4_ipv6_gateway.py" | tr '\n' ' ')"
    echo -e "${GREEN}  -> ipv4_ipv6_gateway.py running (PID(s): ${PIDS})${NC}"
else
    echo -e "${RED}  -> ipv4_ipv6_gateway.py process NOT found${NC}"
fi
echo ""

# 3. Device state (direct check - works without API)
echo -e "${YELLOW}3) Device state check (single-device mode)${NC}"
DEVICE_STATE="/etc/ipv4-ipv6-gateway/device.json"

if [ -f "$DEVICE_STATE" ]; then
    echo -e "${BLUE}- Device configuration:${NC}"
    cat "$DEVICE_STATE" | python3 -m json.tool 2>/dev/null || cat "$DEVICE_STATE"
    echo -e "${GREEN}  -> Device state found${NC}"
else
    echo -e "${YELLOW}  -> No device configured yet ($DEVICE_STATE not found)${NC}"
fi
echo ""

# Optional API health check (if API is running)
echo -e "${YELLOW}3b) API health check (optional in single-device mode)${NC}"

echo -e "${BLUE}- /health:${NC}"
if OUTPUT=$(http_get "${API_BASE}/health" 2>/dev/null); then
    echo "$OUTPUT" | python3 -m json.tool 2>/dev/null || echo "$OUTPUT"
    echo -e "${GREEN}  -> /health responded (API is running)${NC}"
else
    echo -e "${YELLOW}  -> API not responding (this is OK in single-device mode)${NC}"
    echo -e "${BLUE}  ℹ Use gateway-status-direct instead${NC}"
fi
echo ""

# 4. Logs
echo -e "${YELLOW}4) Log tail (${LOG_FILE})${NC}"
if [ -f "$LOG_FILE" ]; then
    echo -e "${BLUE}- Last 20 lines:${NC}"
    tail -n 20 "$LOG_FILE" || true
else
    echo -e "${YELLOW}  -> Log file not found at ${LOG_FILE}${NC}"
fi
echo ""

# 5. Network sanity
echo -e "${YELLOW}5) Network sanity check${NC}"

if command -v ifstatus >/dev/null 2>&1; then
    echo -e "${BLUE}- ifstatus lan:${NC}"
    ifstatus lan 2>/dev/null || echo "  (lan interface not defined)"
    echo ""
    echo -e "${BLUE}- ifstatus wan:${NC}"
    ifstatus wan 2>/dev/null || echo "  (wan interface not defined)"
else
    echo -e "${BLUE}- ip -4 addr show:${NC}"
    ip -4 addr show || true
fi
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Verification complete.${NC}"
echo -e "${GREEN}========================================${NC}\n"
