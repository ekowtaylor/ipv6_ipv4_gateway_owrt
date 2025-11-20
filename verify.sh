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

printf "${GREEN}========================================${NC}\n"
printf "${GREEN}IPv4↔IPv6 Gateway Verification Script${NC}\n"
printf "${GREEN}========================================${NC}\n\n"

# Detect init system
if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
else
    INIT_SYSTEM="initd"
fi
printf "${BLUE}Detected init system: ${INIT_SYSTEM}${NC}\n\n"

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
printf "${YELLOW}1) Service status${NC}\n"

if [ "$INIT_SYSTEM" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl list-units --type=service 2>/dev/null | grep -q "$SERVICE_NAME.service"; then
        printf "${BLUE}- systemd status:${NC}\n"
        systemctl is-active "$SERVICE_NAME" && \
            printf "${GREEN}  -> Service is active (systemd)${NC}\n" || \
            printf "${RED}  -> Service is NOT active (systemd)${NC}\n"
        echo ""
    else
        printf "${YELLOW}  -> systemd unit not found for ${SERVICE_NAME}${NC}\n"
    fi
fi

if [ -x "$INIT_SCRIPT" ]; then
    printf "${BLUE}- init.d status:${NC}\n"
    "$INIT_SCRIPT" status || true
else
    printf "${YELLOW}  -> /etc/init.d/${SERVICE_NAME} not found${NC}\n"
fi
echo ""

# 2. Process check
printf "${YELLOW}2) Process check${NC}\n"
if pgrep -f "ipv4_ipv6_gateway.py" >/dev/null 2>&1; then
    PIDS="$(pgrep -f "ipv4_ipv6_gateway.py" | tr '\n' ' ')"
    printf "${GREEN}  -> ipv4_ipv6_gateway.py running (PID(s): ${PIDS})${NC}\n"
else
    printf "${RED}  -> ipv4_ipv6_gateway.py process NOT found${NC}\n"
fi
echo ""

# 3. Device state (direct check - works without API)
printf "${YELLOW}3) Device state check (single-device mode)${NC}\n"
DEVICE_STATE="/etc/ipv4-ipv6-gateway/device.json"

if [ -f "$DEVICE_STATE" ]; then
    printf "${BLUE}- Device configuration:${NC}\n"
    cat "$DEVICE_STATE" | python3 -m json.tool 2>/dev/null || cat "$DEVICE_STATE"
    printf "${GREEN}  -> Device state found${NC}\n"
else
    printf "${YELLOW}  -> No device configured yet ($DEVICE_STATE not found)${NC}\n"
fi
echo ""

# Optional API health check (if API is running)
printf "${YELLOW}3b) API health check (optional in single-device mode)${NC}\n"

printf "${BLUE}- /health:${NC}\n"
if OUTPUT=$(http_get "${API_BASE}/health" 2>/dev/null); then
    echo "$OUTPUT" | python3 -m json.tool 2>/dev/null || echo "$OUTPUT"
    printf "${GREEN}  -> /health responded (API is running)${NC}\n"
else
    printf "${YELLOW}  -> API not responding (this is OK in single-device mode)${NC}\n"
    printf "${BLUE}  ℹ Use gateway-status-direct instead${NC}\n"
fi
echo ""

# 4. Logs
printf "${YELLOW}4) Log tail (${LOG_FILE})${NC}\n"
if [ -f "$LOG_FILE" ]; then
    printf "${BLUE}- Last 20 lines:${NC}\n"
    tail -n 20 "$LOG_FILE" || true
else
    printf "${YELLOW}  -> Log file not found at ${LOG_FILE}${NC}\n"
fi
echo ""

# 5. Network sanity
printf "${YELLOW}5) Network sanity check${NC}\n"

if command -v ifstatus >/dev/null 2>&1; then
    printf "${BLUE}- ifstatus lan:${NC}\n"
    ifstatus lan 2>/dev/null || echo "  (lan interface not defined)"
    echo ""
    printf "${BLUE}- ifstatus wan:${NC}\n"
    ifstatus wan 2>/dev/null || echo "  (wan interface not defined)"
else
    printf "${BLUE}- ip -4 addr show:${NC}\n"
    ip -4 addr show || true
fi
echo ""

printf "${GREEN}========================================${NC}\n"
printf "${GREEN}Verification complete.${NC}\n"
printf "${GREEN}========================================${NC}\n\n"
