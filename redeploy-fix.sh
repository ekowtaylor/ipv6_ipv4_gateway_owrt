#!/bin/bash
# Quick redeploy script - fixes the production path issue
# Run this from your Mac

ROUTER_IP="$1"

if [ -z "$ROUTER_IP" ]; then
    echo "Usage: ./redeploy-fix.sh <router-ip>"
    echo "Example: ./redeploy-fix.sh 192.168.1.1"
    exit 1
fi

echo "======================================================================"
echo "Redeploying Fixed Gateway to Router"
echo "======================================================================"
echo ""

echo "1. Uploading fixed files to router..."
scp gateway_config.py ipv4_ipv6_gateway.py root@${ROUTER_IP}:/opt/ipv4-ipv6-gateway/ && echo "   ✓ Python files uploaded" || { echo "   ✗ Failed"; exit 1; }

echo ""
echo "2. Uploading troubleshooting script..."
scp troubleshoot-deployment.sh root@${ROUTER_IP}:/root/ && echo "   ✓ Script uploaded" || { echo "   ✗ Failed"; exit 1; }
ssh root@${ROUTER_IP} "chmod +x /root/troubleshoot-deployment.sh" && echo "   ✓ Made executable" || { echo "   ✗ Failed"; exit 1; }

echo ""
echo "3. Restarting service..."
ssh root@${ROUTER_IP} "/etc/init.d/ipv4-ipv6-gateway restart" && echo "   ✓ Service restarted" || { echo "   ✗ Failed"; exit 1; }

echo ""
echo "4. Waiting 5 seconds for startup..."
sleep 5

echo ""
echo "5. Checking service status..."
ssh root@${ROUTER_IP} "/etc/init.d/ipv4-ipv6-gateway status" && echo "   ✓ Service running" || echo "   ⚠ Service may not be running"

echo ""
echo "======================================================================"
echo "Deployment complete!"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "  1. SSH to router: ssh root@${ROUTER_IP}"
echo "  2. Run troubleshooting: ./troubleshoot-deployment.sh"
echo "  3. Check logs: tail -f /var/log/ipv4-ipv6-gateway.log"
echo ""
