FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx certbot && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py entrypoint.sh ./
COPY web ./web
COPY nginx.conf /etc/nginx/nginx.conf
RUN chmod +x /app/entrypoint.sh && rm -f /etc/nginx/sites-enabled/default
EXPOSE 80 443 8080
VOLUME ["/data", "/etc/letsencrypt"]
HEALTHCHECK --interval=30s --timeout=3s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/status')"
ENTRYPOINT ["/app/entrypoint.sh"]
