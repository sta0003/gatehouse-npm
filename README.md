# Gatehouse — NGINX Manager

A small self-hosted control panel for routing domains and subdomains to services on your local network. Gatehouse generates NGINX configuration, validates it before reload, and requests Let's Encrypt certificates using the HTTP-01 challenge.

## How traffic flows

`Internet → router ports 80/443 → Gatehouse → local service`

TLS ends at Gatehouse. Your upstream service can use plain HTTP on the trusted LAN, or HTTPS if it already supports it.

## Start it

### Quick install with curl

On a machine with Docker and the Docker Compose plugin installed, run:

```sh
mkdir gatehouse && cd gatehouse
curl -fsSL https://github.com/sta0003/gatehouse-npm/archive/refs/heads/main.tar.gz | tar -xz --strip-components=1
chmod +x gatehouse.sh
./gatehouse.sh install
```

The installer will ask you to create the administrator password, build the container, wait for it to become healthy, and print the dashboard address.

### Manual setup

1. Install Docker with the Compose plugin.
2. Run `./gatehouse.sh install` and enter a long, unique administrator password when prompted.
3. Open `http://<gatehouse-lan-ip>:8080` and sign in as `admin`.
4. Forward TCP ports 80 and 443 from your router to the Gatehouse machine.
5. Create public DNS `A`/`AAAA` records for each domain pointing to your public IP.
6. Add a proxy host, verify HTTP works, then click **Enable HTTPS**.

The helper also supports `start`, `stop`, `restart`, `rebuild`, `update`, `status`, and `logs`. Run `./gatehouse.sh help` for the complete list. It never deletes the persistent `data` or `letsencrypt` directories.

Do not expose port 8080 to the public internet. Restrict it with your host firewall, a VPN, or a trusted management VLAN.

## HTTPS requirements

The initial release uses Let's Encrypt HTTP-01. Certificate issuance requires:

- a real domain you control;
- public DNS pointing to this gateway;
- inbound TCP port 80 reaching this container;
- no CGNAT or ISP filtering that prevents inbound access.

For LAN-only hostnames, split DNS, wildcard certificates, or networks behind CGNAT, add a DNS-01 provider integration or use a private CA such as Caddy's local CA / step-ca. Browsers must trust that CA for warnings to disappear.

## Operations

- Proxy records are stored in `./data/proxy.db`.
- Certificates are stored in `./letsencrypt` and persist across rebuilds.
- The container checks for certificate renewals every 12 hours and reloads NGINX after a successful renewal.
- Every route change writes a generated config, runs `nginx -t`, and only then reloads NGINX. If validation fails, the previous config is restored.

## Backup and migration

Administrators can open **Backup & restore** in the dashboard to download a passphrase-encrypted `.ghbackup` file. It contains proxy hosts, IP access rules, dashboard users, password hashes, and the complete Let's Encrypt state. Traffic logs, `.env`, generated NGINX files, and machine-specific Compose settings are intentionally excluded.

To migrate, start Gatehouse on the new machine, sign in with its temporary administrator account, open **Backup & restore**, and restore the file using its original passphrase. Gatehouse validates and stages the archive before replacing live data, keeps a rollback copy during the operation, reloads NGINX, and signs out every dashboard session after a successful restore. Keep both the backup and its passphrase secure; neither can recover the other.

## Local development without Docker

The application uses only Python's standard library:

```sh
DATA_DIR=/tmp/gatehouse-data \
NGINX_OUTPUT=/tmp/gatehouse.conf \
ADMIN_PASSWORD=development-only \
python3 app.py
```

Then open `http://localhost:8080`. NGINX reload is skipped when the binary is not installed.
