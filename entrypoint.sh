#!/bin/sh
set -eu
mkdir -p /data /var/www/certbot /etc/nginx/conf.d /etc/nginx/stream-conf.d
touch /data/local-dns-hosts
dnsmasq --keep-in-foreground --conf-file= --port=53 \
  --listen-address="$GATEHOUSE_LAN_IP" --bind-interfaces --no-hosts \
  --addn-hosts=/data/local-dns-hosts --cache-size=1000 \
  --pid-file=/run/gatehouse-dnsmasq.pid --log-facility=- &
dns_pid=$!
python3 /app/app.py &
app_pid=$!
(
  while :; do
    sleep 43200
    certbot renew --quiet --deploy-hook "nginx -s reload" || true
  done
) &
renew_pid=$!
trap 'kill "$app_pid" "$renew_pid" "$dns_pid" 2>/dev/null || true; nginx -s quit 2>/dev/null || true' TERM INT
while [ ! -f /etc/nginx/conf.d/proxy-hosts.conf ] || [ ! -f /etc/nginx/stream-conf.d/game-services.conf ]; do sleep 0.1; done
nginx -g 'daemon off;' &
nginx_pid=$!
while kill -0 "$app_pid" 2>/dev/null && kill -0 "$nginx_pid" 2>/dev/null && kill -0 "$dns_pid" 2>/dev/null; do
  sleep 2
done
kill "$app_pid" "$nginx_pid" "$renew_pid" "$dns_pid" 2>/dev/null || true
wait "$app_pid" 2>/dev/null || true
wait "$nginx_pid" 2>/dev/null || true
wait "$dns_pid" 2>/dev/null || true
