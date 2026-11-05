#!/bin/bash
# Remove update-airlock. Keeps config, history and backups unless --purge is given.
#   sudo /opt/update-airlock/app/scripts/uninstall.sh [--purge]
# Containers that were updated stay as they are (compose files keep their pinned image line).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

systemctl disable --now update-airlock-check.timer update-airlock-apply.timer 2>/dev/null || true
systemctl stop update-airlock-check.service update-airlock-apply.service 2>/dev/null || true
[ -x /usr/local/bin/update-airlock ] && /usr/local/bin/update-airlock cleanup || true
docker image rm update-airlock/egress-proxy:1 2>/dev/null || true
rm -f /etc/systemd/system/update-airlock-check.service /etc/systemd/system/update-airlock-check.timer \
      /etc/systemd/system/update-airlock-apply.service /etc/systemd/system/update-airlock-apply.timer \
      /etc/systemd/system/update-airlock-failure@.service
systemctl daemon-reload
rm -f /usr/local/bin/update-airlock /etc/logrotate.d/update-airlock \
      /var/lib/prometheus/node-exporter/update_airlock.prom
rm -rf /opt/update-airlock /var/www/update-airlock
if [ -e /etc/nginx/sites-enabled/update-airlock ] || [ -e /etc/nginx/sites-available/update-airlock ]; then
  rm -f /etc/nginx/sites-enabled/update-airlock /etc/nginx/sites-available/update-airlock
  nginx -t && systemctl reload nginx || true
fi
if [ "$PURGE" = 1 ]; then
  rm -rf /etc/update-airlock /var/lib/update-airlock /var/log/update-airlock /var/backups/update-airlock
  for img in $(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^update-airlock-keep/' || true); do
    docker rmi "$img" || true
  done
  echo "removed completely (incl. backups and kept rollback images)"
else
  echo "removed. Kept: /etc/update-airlock, /var/lib/update-airlock, /var/backups/update-airlock, /var/log/update-airlock"
fi
echo "Remember: remove the HA automation update_airlock_dead_mans_switch and the sensor cards in Home Assistant."
