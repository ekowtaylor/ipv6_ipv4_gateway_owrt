#!/bin/bash
# Quick Device Store Inspector
# Shows exactly what's in devices.json to diagnose WAN address issues

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEVICES_FILE="/etc/ipv4-ipv6-gateway/devices.json"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DEVICE STORE INSPECTOR${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ ! -f "$DEVICES_FILE" ]; then
    echo -e "${RED}✗ Device store not found: $DEVICES_FILE${NC}"
    echo ""
    echo -e "${YELLOW}This means either:${NC}"
    echo "  1. Gateway service hasn't started yet"
    echo "  2. No devices have been discovered"
    echo "  3. Service crashed before creating the file"
    echo ""
    echo -e "${BLUE}Check service status:${NC}"
    echo "  ps | grep ipv4_ipv6_gateway"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ Device store found${NC}"
echo -e "${BLUE}Location: $DEVICES_FILE${NC}"
echo ""

# Show raw JSON
echo -e "${YELLOW}=== RAW DEVICE DATA ===${NC}"
cat "$DEVICES_FILE"
echo ""
echo ""

# Parse and analyze
echo -e "${YELLOW}=== ANALYZED DEVICE DATA ===${NC}"

if command -v python3 >/dev/null 2>&1; then
    python3 << 'PYEOF'
import json
import sys

try:
    with open("/etc/ipv4-ipv6-gateway/devices.json", "r") as f:
        devices = json.load(f)
    
    if not devices:
        print("\033[1;33m⚠ No devices in store\033[0m")
        sys.exit(0)
    
    for mac, device in devices.items():
        print(f"\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        print(f"\033[1;36mDevice: {mac}\033[0m")
        print(f"\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        
        # LAN IPv4
        lan_ipv4 = device.get("ipv4_address", None)
        if lan_ipv4:
            print(f"  \033[0;32m✓ LAN IPv4:\033[0m {lan_ipv4}")
        else:
            print(f"  \033[0;31m✗ LAN IPv4:\033[0m Not assigned")
        
        # WAN IPv4
        wan_ipv4 = device.get("ipv4_wan_address", None)
        if wan_ipv4:
            print(f"  \033[0;32m✓ WAN IPv4:\033[0m {wan_ipv4}")
        else:
            print(f"  \033[0;31m✗ WAN IPv4:\033[0m Not assigned \033[1;31m← PROBLEM!\033[0m")
        
        # WAN IPv6
        wan_ipv6 = device.get("ipv6_address", None)
        if wan_ipv6:
            # Check if it's a string or list
            if isinstance(wan_ipv6, list):
                print(f"  \033[0;32m✓ WAN IPv6:\033[0m {len(wan_ipv6)} address(es)")
                for i, addr in enumerate(wan_ipv6, 1):
                    print(f"    {i}. {addr}")
            else:
                print(f"  \033[0;32m✓ WAN IPv6:\033[0m {wan_ipv6}")
        else:
            print(f"  \033[0;31m✗ WAN IPv6:\033[0m Not assigned \033[1;31m← PROBLEM!\033[0m")
        
        # Status
        status = device.get("status", "unknown")
        if status == "active":
            print(f"  \033[0;32m✓ Status:\033[0m {status}")
        elif status == "pending":
            print(f"  \033[1;33m⚠ Status:\033[0m {status} (discovery in progress?)")
        elif status == "failed":
            print(f"  \033[0;31m✗ Status:\033[0m {status}")
        else:
            print(f"  \033[1;33m? Status:\033[0m {status}")
        
        # Timestamps
        discovered = device.get("discovered_at", "unknown")
        last_seen = device.get("last_seen", "unknown")
        print(f"  \033[0;34mℹ Discovered:\033[0m {discovered}")
        print(f"  \033[0;34mℹ Last Seen:\033[0m {last_seen}")
        print("")
    
    # Summary
    total = len(devices)
    with_wan_ipv4 = sum(1 for d in devices.values() if d.get("ipv4_wan_address"))
    with_wan_ipv6 = sum(1 for d in devices.values() if d.get("ipv6_address"))
    
    print(f"\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"\033[1;33mSUMMARY\033[0m")
    print(f"\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"  Total Devices: {total}")
    print(f"  With WAN IPv4: {with_wan_ipv4}/{total}")
    print(f"  With WAN IPv6: {with_wan_ipv6}/{total}")
    print("")
    
    if with_wan_ipv4 == 0 and with_wan_ipv6 == 0:
        print(f"\033[1;31m✗ CRITICAL: No devices have WAN addresses!\033[0m")
        print(f"\033[1;33mThis means IPv4/IPv6 discovery is FAILING.\033[0m")
        print("")
        print(f"\033[0;34mNext steps:\033[0m")
        print("  1. Check logs: tail -100 /var/log/ipv4-ipv6-gateway.log")
        print("  2. Look for 'Failed to obtain IPv4/IPv6' messages")
        print("  3. Check if eth0 has global IPv6: ip -6 addr show eth0")
        print("  4. Check if MAC spoofing works: ip link show eth0")
    elif with_wan_ipv4 < total or with_wan_ipv6 < total:
        print(f"\033[1;33m⚠ WARNING: Some devices missing WAN addresses\033[0m")
    else:
        print(f"\033[0;32m✓ All devices have WAN addresses\033[0m")
    
except FileNotFoundError:
    print("\033[0;31m✗ Device store file not found\033[0m")
except json.JSONDecodeError:
    print("\033[0;31m✗ Device store contains invalid JSON\033[0m")
    print("\nRaw content:")
    with open("/etc/ipv4-ipv6-gateway/devices.json", "r") as f:
        print(f.read())
except Exception as e:
    print(f"\033[0;31m✗ Error reading device store: {e}\033[0m")
PYEOF
else
    echo -e "${YELLOW}python3 not available, showing raw JSON only${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}For more details, check the log:${NC}"
echo -e "${BLUE}  tail -100 /var/log/ipv4-ipv6-gateway.log${NC}"
echo -e "${BLUE}========================================${NC}"
