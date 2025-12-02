#!/bin/sh
# Move LuCI to alternate port (8080 or other) to free up port 80 for device

set -e

LUCI_PORT=8888  # Change LuCI to port 8888 (can be any high port)

echo "Moving LuCI to port $LUCI_PORT..."

# Backup current config
uci show uhttpd > /tmp/uhttpd_backup.txt

# Change HTTP port
uci set uhttpd.main.listen_http="0.0.0.0:$LUCI_PORT"
uci set uhttpd.main.listen_http="[::]:$LUCI_PORT"

# Change HTTPS port (optional)
# uci set uhttpd.main.listen_https="0.0.0.0:8443"
# uci set uhttpd.main.listen_https="[::]:8443"

# Commit changes
uci commit uhttpd

# Restart uhttpd (LuCI web server)
/etc/init.d/uhttpd restart

echo "✓ LuCI moved to port $LUCI_PORT"
echo "Access LuCI at: http://192.168.1.1:$LUCI_PORT"
echo ""
echo "Backup saved to: /tmp/uhttpd_backup.txt"
echo "To restore: cat /tmp/uhttpd_backup.txt | uci import uhttpd && uci commit uhttpd && /etc/init.d/uhttpd restart"
