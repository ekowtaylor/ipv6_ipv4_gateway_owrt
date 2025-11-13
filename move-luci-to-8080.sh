#!/bin/sh
#
# Move OpenWrt LuCI to port 8080 (frees port 80 for IPv6 proxy)
# Run this on the OpenWrt gateway
#

echo "=========================================="
echo "Move LuCI to Port 8080"
echo "=========================================="
echo ""

echo "Current uhttpd configuration:"
uci show uhttpd | grep -E 'listen_http|listen_https'
echo ""

echo "Changing LuCI HTTP port from 80 to 8080..."
uci delete uhttpd.main.listen_http
uci add_list uhttpd.main.listen_http='0.0.0.0:8080'
uci add_list uhttpd.main.listen_http='[::]:8080'

echo "Committing changes..."
uci commit uhttpd

echo "Restarting uhttpd..."
/etc/init.d/uhttpd restart

echo ""
echo "✓ LuCI moved to port 8080"
echo ""
echo "Access LuCI at:"
echo "  http://gateway-ip:8080"
echo ""
echo "Port 80 is now free for IPv6→IPv4 proxy!"
echo ""
echo "To verify:"
echo "  netstat -ln | grep ':80 '"
echo "  (should show nothing or only IPv6 proxy)"
echo ""
