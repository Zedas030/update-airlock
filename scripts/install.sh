#!/bin/bash
# Install or update update-airlock on this host. Run from the repository: sudo ./scripts/install.sh [--enable]
#   --enable   also enable and start the timers (first installation: enter HA_TOKEN in .env first)
# Existing /etc/update-airlock/config.yaml and .env are never overwritten.
set -euo pipefail

#   --nginx    also install the nginx site for the status page (port 8100, web/nginx-update-airlock.conf)
ENABLE=0
NGINX=0
for a in "$@"; do
  case "$a" in
    --enable) ENABLE=1 ;;
    --nginx) NGINX=1 ;;
    *) echo "unknown option $a"; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/update-airlock/app
ETC=/etc/update-airlock

echo "== checking requirements"
for b in docker tar zstd iptables python3 systemctl; do
  command -v "$b" >/dev/null || { echo "missing: $b"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "missing: docker compose plugin"; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 11)' || { echo "python >= 3.11 needed"; exit 1; }
if ! python3 -c 'import yaml, requests' 2>/dev/null; then
  echo "installing python3-yaml python3-requests (Debian packages)"
  apt-get install -y python3-yaml python3-requests
fi

echo "== copying the application to $APP"
mkdir -p "$APP"
rm -rf "$APP/update_airlock"
tar -C "$SRC" --exclude=./local --exclude=./.git --exclude=__pycache__ --exclude=.pytest_cache --exclude=.venv \
    --exclude=./sync.sh -cf - . | tar -C "$APP" --no-same-owner -xf -
# Code that runs as root must not be writable by anybody else
chown -R root:root /opt/update-airlock
find "$APP" -type d -exec chmod 755 {} +
find "$APP" -type f -exec chmod 644 {} +
chmod 755 "$APP"/scripts/*.sh
install -m 755 "$SRC/scripts/update-airlock.wrapper" /usr/local/bin/update-airlock

echo "== configuration in $ETC"
install -d -m 750 "$ETC"
[ -f "$ETC/config.yaml" ] || install -m 640 "$SRC/config/config.example.yaml" "$ETC/config.yaml"
[ -f "$ETC/.env" ] || install -m 600 "$SRC/config/env.example" "$ETC/.env"
chmod 600 "$ETC/.env"

echo "== directories"
install -d -m 700 /var/lib/update-airlock /var/backups/update-airlock
install -d -m 750 /var/log/update-airlock
install -d -m 755 /var/www/update-airlock
install -m 644 "$SRC/scripts/logrotate" /etc/logrotate.d/update-airlock

if [ "$NGINX" = 1 ]; then
  echo "== nginx site (status page on port 8100)"
  command -v nginx >/dev/null || { echo "nginx not installed"; exit 1; }
  install -m 644 "$SRC/web/nginx-update-airlock.conf" /etc/nginx/sites-available/update-airlock
  ln -sf ../sites-available/update-airlock /etc/nginx/sites-enabled/update-airlock
  nginx -t
  systemctl reload nginx
fi

echo "== systemd units"
for u in update-airlock-check.service update-airlock-check.timer update-airlock-apply.service \
         update-airlock-apply.timer update-airlock-failure@.service; do
  install -m 644 "$SRC/systemd/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload

update-airlock validate
if [ "$ENABLE" = 1 ]; then
  systemctl enable --now update-airlock-check.timer update-airlock-apply.timer
  echo "timers enabled"
else
  if systemctl is-enabled update-airlock-check.timer >/dev/null 2>&1; then
    systemctl restart update-airlock-check.timer update-airlock-apply.timer
  else
    echo "timers NOT enabled yet - after entering HA_TOKEN: sudo $0 --enable"
  fi
fi
echo "done. Status: sudo update-airlock status"
