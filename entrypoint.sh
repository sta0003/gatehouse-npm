#!/bin/sh
set -eu
mkdir -p /data /var/www/certbot /etc/nginx/conf.d
python3 /app/app.py &
app_pid=$!
(
  while :; do
    sleep 43200
    certbot renew --quiet --deploy-hook "nginx -s reload" || true
  done
) &
renew_pid=$!
trap 'kill "$app_pid" "$renew_pid" 2>/dev/null || true; nginx -s quit 2>/dev/null || true' TERM INT
while [ ! -f /etc/nginx/conf.d/proxy-hosts.conf ]; do sleep 0.1; done
nginx -g 'daemon off;' &
nginx_pid=$!
while kill -0 "$app_pid" 2>/dev/null && kill -0 "$nginx_pid" 2>/dev/null; do
  sleep 2
done
kill "$app_pid" "$nginx_pid" "$renew_pid" 2>/dev/null || true
wait "$app_pid" 2>/dev/null || true
wait "$nginx_pid" 2>/dev/null || true
