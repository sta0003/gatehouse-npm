#!/usr/bin/env python3
"""Small, dependency-free web manager for an NGINX reverse proxy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse


DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "proxy.db"
NGINX_OUTPUT = Path(os.environ.get("NGINX_OUTPUT", "/etc/nginx/conf.d/proxy-hosts.conf"))
WEB_ROOT = Path(__file__).with_name("web")
CERT_ROOT = Path(os.environ.get("CERT_ROOT", "/etc/letsencrypt/live"))
CERT_STORAGE_ROOT = Path(os.environ.get("CERT_STORAGE_ROOT", str(CERT_ROOT.parent)))
ACME_ROOT = os.environ.get("ACME_ROOT", "/var/www/certbot")
ACCESS_LOG = Path(os.environ.get("ACCESS_LOG", "/data/access.log"))
ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me-now")
SESSION_TTL = 12 * 60 * 60
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
BACKUP_MAGIC = b"GATEHOUSE-BACKUP-1\n"
BACKUP_ITERATIONS = 200_000
MAX_BACKUP_BYTES = 64 * 1024 * 1024


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if len(password) > 1024:
        raise ValueError("Password is too long")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(expected)))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def initialize() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Path(ACME_ROOT).mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS proxy_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domains TEXT NOT NULL UNIQUE,
                upstream_scheme TEXT NOT NULL,
                upstream_host TEXT NOT NULL,
                upstream_port INTEGER NOT NULL,
                websocket INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                allowlist TEXT NOT NULL DEFAULT '',
                blocklist TEXT NOT NULL DEFAULT '',
                certificate INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )"""
        )
        proxy_columns = {row["name"] for row in connection.execute("PRAGMA table_info(proxy_hosts)")}
        if "allowlist" not in proxy_columns:
            connection.execute("ALTER TABLE proxy_hosts ADD COLUMN allowlist TEXT NOT NULL DEFAULT ''")
        if "blocklist" not in proxy_columns:
            connection.execute("ALTER TABLE proxy_hosts ADD COLUMN blocklist TEXT NOT NULL DEFAULT ''")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
                enabled INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )"""
        )
        if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            connection.execute(
                "INSERT INTO users (username, password_hash, role, enabled, created_at) VALUES (?, ?, 'admin', 1, ?)",
                (ADMIN_USER, hash_password(ADMIN_PASSWORD), int(time.time())),
            )
    secret_file = DATA_DIR / "session_secret"
    if not secret_file.exists():
        secret_file.write_text(secrets.token_hex(32))
        secret_file.chmod(0o600)
    render_and_reload(reload_nginx=False)


def normalize_domains(value: str) -> list[str]:
    domains = sorted(set(part.strip().lower().rstrip(".") for part in value.replace(",", " ").split()))
    if not domains or any(not HOST_RE.fullmatch(item) for item in domains):
        raise ValueError("Enter one or more complete domain names, such as app.example.com")
    return domains


def normalize_networks(value: object, label: str) -> list[str]:
    if isinstance(value, list):
        parts = [str(item).strip() for item in value]
    else:
        parts = [item.strip() for item in re.split(r"[\s,]+", str(value or ""))]
    parts = [item for item in parts if item]
    if len(parts) > 200:
        raise ValueError(f"{label} supports up to 200 IP addresses or networks")
    networks = []
    for item in parts:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(f"Invalid {label.lower()} entry: {item}") from None
    unique = set(networks)
    return [network.with_prefixlen for network in sorted(unique, key=lambda network: (network.version, int(network.network_address), network.prefixlen))]


def validate_payload(payload: dict) -> dict:
    domains = normalize_domains(str(payload.get("domains", "")))
    scheme = str(payload.get("upstream_scheme", "http")).lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Upstream scheme must be http or https")
    host = str(payload.get("upstream_host", "")).strip()
    if not host or any(char in host for char in " /;{}$\n\r\t"):
        raise ValueError("Enter a valid upstream hostname or IP address")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", host):
            raise ValueError("Enter a valid upstream hostname or IP address") from None
    try:
        port = int(payload.get("upstream_port"))
    except (TypeError, ValueError):
        raise ValueError("Upstream port must be a number") from None
    if not 1 <= port <= 65535:
        raise ValueError("Upstream port must be between 1 and 65535")
    allowlist = normalize_networks(payload.get("allowlist", ""), "Allowlist")
    blocklist = normalize_networks(payload.get("blocklist", ""), "Blocklist")
    return {
        "domains": " ".join(domains),
        "upstream_scheme": scheme,
        "upstream_host": host,
        "upstream_port": port,
        "websocket": int(bool(payload.get("websocket", True))),
        "enabled": int(bool(payload.get("enabled", True))),
        "allowlist": "\n".join(allowlist),
        "blocklist": "\n".join(blocklist),
    }


def validate_user_payload(payload: dict, require_password: bool = True) -> dict:
    username = str(payload.get("username", "")).strip()
    role = str(payload.get("role", "operator")).lower()
    password = str(payload.get("password", ""))
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3–32 letters, numbers, dots, dashes, or underscores")
    if role not in {"admin", "operator"}:
        raise ValueError("Role must be administrator or operator")
    values = {"username": username, "role": role, "enabled": int(bool(payload.get("enabled", True)))}
    if password:
        values["password_hash"] = hash_password(password)
    elif require_password:
        raise ValueError("Password is required")
    return values


def public_user(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "username": row["username"], "role": row["role"], "enabled": bool(row["enabled"]), "created_at": row["created_at"]}


def certificate_exists(primary_domain: str) -> bool:
    directory = CERT_ROOT / primary_domain
    return (directory / "fullchain.pem").exists() and (directory / "privkey.pem").exists()


def certificate_details(primary_domain: str, configured: bool = True) -> dict:
    base = {
        "installed": False, "status": "missing" if configured else "not_enabled",
        "issuer": None, "valid_from": None, "expires_at": None,
        "days_remaining": None, "serial": None, "sans": [],
    }
    if not configured:
        return base
    directory = CERT_ROOT / primary_domain
    cert_path = directory / "cert.pem"
    if not cert_path.exists() or not certificate_exists(primary_domain):
        return base
    base["installed"] = True
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert_path))
        valid_from = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), timezone.utc)
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = (expires_at - now).days
        issuer_fields = {key: value for group in decoded.get("issuer", ()) for key, value in group}
        issuer_parts = [issuer_fields.get("organizationName"), issuer_fields.get("commonName")]
        base.update({
            "status": "expired" if expires_at <= now else "expiring" if remaining <= 30 else "valid",
            "issuer": " · ".join(dict.fromkeys(part for part in issuer_parts if part)) or "Unknown issuer",
            "valid_from": valid_from.isoformat(),
            "expires_at": expires_at.isoformat(),
            "days_remaining": remaining,
            "serial": decoded.get("serialNumber"),
            "sans": [value for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"],
        })
    except (KeyError, OSError, ValueError, ssl.SSLError):
        base["status"] = "invalid"
    return base


def host_config(row: sqlite3.Row) -> str:
    domains = row["domains"].split()
    primary = domains[0]
    upstream_host = row["upstream_host"]
    if ":" in upstream_host and not upstream_host.startswith("["):
        upstream_host = f"[{upstream_host}]"
    upstream = f'{row["upstream_scheme"]}://{upstream_host}:{row["upstream_port"]}'
    allowed = row["allowlist"].split()
    blocked = row["blocklist"].split()
    access_lines = [f"            deny {network};" for network in blocked]
    access_lines.extend(f"            allow {network};" for network in allowed)
    if allowed:
        access_lines.append("            deny all;")
    access_rules = "\n".join(access_lines)
    if access_rules:
        access_rules += "\n"
    upgrade_headers = """
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;""" if row["websocket"] else ""
    common = f"""
        location ^~ /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}
        location / {{
{access_rules}
            proxy_pass {upstream};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_ssl_server_name on;
            {upgrade_headers}
        }}"""
    domain_text = " ".join(domains)
    if row["certificate"] and certificate_exists(primary):
        http_body = f"""
        location ^~ /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}
        location / {{
{access_rules}            return 301 https://$host$request_uri;
        }}"""
        https = f"""
server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {domain_text};
    ssl_certificate {CERT_ROOT / primary / 'fullchain.pem'};
    ssl_certificate_key {CERT_ROOT / primary / 'privkey.pem'};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security \"max-age=31536000\" always;
    add_header Content-Security-Policy \"upgrade-insecure-requests\" always;
    {common}
}}
"""
    else:
        http_body = common
        https = ""
    return f"""# Proxy host {row['id']}: {domain_text}
server {{
    listen 80;
    listen [::]:80;
    server_name {domain_text};
    {http_body}
}}
{https}"""


def render_config(connection: sqlite3.Connection | None = None) -> str:
    header = """# Generated by NGINX Manager. Do not edit by hand.
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 444; }
}
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
}
"""
    owns_connection = connection is None
    connection = connection or db()
    rows = connection.execute("SELECT * FROM proxy_hosts WHERE enabled = 1 ORDER BY id").fetchall()
    if owns_connection:
        connection.close()
    return header + "\n".join(host_config(row) for row in rows)


def run_nginx(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["nginx", *args], text=True, capture_output=True, timeout=20)


def render_and_reload(reload_nginx: bool = True, connection: sqlite3.Connection | None = None) -> None:
    NGINX_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    previous = NGINX_OUTPUT.read_text() if NGINX_OUTPUT.exists() else None
    content = render_config(connection)
    with tempfile.NamedTemporaryFile("w", dir=NGINX_OUTPUT.parent, delete=False) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    temporary_path.replace(NGINX_OUTPUT)
    if not reload_nginx or not shutil_which("nginx"):
        return
    check = run_nginx("-t")
    if check.returncode:
        if previous is None:
            NGINX_OUTPUT.unlink(missing_ok=True)
        else:
            NGINX_OUTPUT.write_text(previous)
        raise RuntimeError(check.stderr.strip() or "NGINX configuration validation failed")
    reload_result = run_nginx("-s", "reload")
    if reload_result.returncode:
        if previous is None:
            NGINX_OUTPUT.unlink(missing_ok=True)
        else:
            NGINX_OUTPUT.write_text(previous)
        raise RuntimeError(reload_result.stderr.strip() or "NGINX reload failed")


def ensure_domains_available(connection: sqlite3.Connection, domains: str, exclude_id: int | None = None) -> None:
    requested = set(domains.split())
    rows = connection.execute("SELECT id, domains FROM proxy_hosts").fetchall()
    for row in rows:
        if row["id"] != exclude_id and requested.intersection(row["domains"].split()):
            overlap = sorted(requested.intersection(row["domains"].split()))[0]
            raise ValueError(f"{overlap} is already assigned to another proxy host")


def stats_snapshot() -> dict:
    """Summarize the last 24 hours of NGINX's JSON access log."""
    now = datetime.now(timezone.utc)
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    minute_start = now.replace(second=0, microsecond=0) - timedelta(minutes=59)
    five_minute_start = now - timedelta(minutes=5)
    buckets = [{"time": (start + timedelta(hours=index)).isoformat(), "requests": 0, "errors": 0} for index in range(24)]
    minute_buckets = [{"time": (minute_start + timedelta(minutes=index)).isoformat(), "requests": 0, "bytes": 0} for index in range(60)]
    status = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    total_bytes = 0
    latency_total = 0.0
    records = 0
    recent = []
    destinations: dict[str, dict] = {}
    sources: dict[str, dict] = {}
    live_requests = 0
    live_bytes = 0
    live_sources: set[str] = set()
    with db() as connection:
        route_rows = connection.execute("SELECT domains, upstream_scheme, upstream_host, upstream_port FROM proxy_hosts").fetchall()
    route_map = {
        domain: f'{row["upstream_scheme"]}://{row["upstream_host"]}:{row["upstream_port"]}'
        for row in route_rows for domain in row["domains"].split()
    }
    if ACCESS_LOG.exists():
        try:
            with ACCESS_LOG.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 2_000_000))
                if size > 2_000_000:
                    stream.readline()
                lines = stream.readlines()[-20_000:]
            for raw_line in lines:
                try:
                    entry = json.loads(raw_line)
                    occurred = datetime.fromisoformat(str(entry["time"]).replace("Z", "+00:00")).astimezone(timezone.utc)
                    if occurred < start:
                        continue
                    code = int(entry.get("status", 0))
                    bytes_sent = int(entry.get("bytes", 0) or 0)
                    request_time = float(entry.get("request_time", 0) or 0)
                    host = str(entry.get("host", "-") or "-")
                    remote = str(entry.get("remote", "-") or "-")
                    uri = str(entry.get("uri", "/") or "/").split("?", 1)[0][:500]
                    bucket_index = int((occurred - start).total_seconds() // 3600)
                    if 0 <= bucket_index < len(buckets):
                        buckets[bucket_index]["requests"] += 1
                        if code >= 400:
                            buckets[bucket_index]["errors"] += 1
                    minute_index = int((occurred - minute_start).total_seconds() // 60)
                    if 0 <= minute_index < len(minute_buckets):
                        minute_buckets[minute_index]["requests"] += 1
                        minute_buckets[minute_index]["bytes"] += bytes_sent
                    family = f"{code // 100}xx"
                    if family in status:
                        status[family] += 1
                    total_bytes += bytes_sent
                    latency_total += request_time
                    records += 1
                    destination = destinations.setdefault(host, {"host": host, "upstream": route_map.get(host, "Unmatched / gateway"), "requests": 0, "bytes": 0, "errors": 0})
                    destination["requests"] += 1
                    destination["bytes"] += bytes_sent
                    destination["errors"] += int(code >= 400)
                    source = sources.setdefault(remote, {"ip": remote, "requests": 0, "bytes": 0, "last_seen": entry["time"]})
                    source["requests"] += 1
                    source["bytes"] += bytes_sent
                    source["last_seen"] = entry["time"]
                    if occurred >= five_minute_start:
                        live_requests += 1
                        live_bytes += bytes_sent
                        live_sources.add(remote)
                    recent.append({
                        "time": entry["time"], "source": remote, "scheme": entry.get("scheme", "-"),
                        "method": entry.get("method", "GET"), "host": host, "uri": uri,
                        "upstream": route_map.get(host, "Unmatched / gateway"), "status": code,
                        "bytes": bytes_sent, "latency_ms": round(request_time * 1000),
                    })
                except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                    continue
        except OSError:
            pass
    return {
        "window_hours": 24,
        "requests": records,
        "error_rate": round(((status["4xx"] + status["5xx"]) / records * 100) if records else 0, 1),
        "avg_latency_ms": round((latency_total / records * 1000) if records else 0),
        "bytes": total_bytes,
        "status": status,
        "timeline": buckets,
        "minute_timeline": minute_buckets,
        "live": {"requests": live_requests, "bytes": live_bytes, "sources": len(live_sources)},
        "destinations": sorted(destinations.values(), key=lambda item: item["requests"], reverse=True)[:12],
        "sources": sorted(sources.values(), key=lambda item: item["requests"], reverse=True)[:20],
        "recent": list(reversed(recent[-100:])),
    }


def shutil_which(command: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(folder) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def validate_backup_passphrase(passphrase: object) -> str:
    value = str(passphrase or "")
    if len(value) < 12:
        raise ValueError("Backup passphrase must be at least 12 characters")
    if len(value) > 1024 or "\n" in value or "\r" in value:
        raise ValueError("Backup passphrase is invalid")
    return value


def openssl_crypt(source: Path, destination: Path, passphrase: str, decrypt: bool = False) -> None:
    if not shutil_which("openssl"):
        raise RuntimeError("OpenSSL is required for encrypted backups")
    command = ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", str(BACKUP_ITERATIONS), "-md", "sha256"]
    if decrypt:
        command.append("-d")
    command.extend(["-in", str(source), "-out", str(destination), "-pass", "stdin"])
    result = subprocess.run(command, input=passphrase + "\n", text=True, capture_output=True, timeout=180)
    if result.returncode:
        destination.unlink(missing_ok=True)
        raise ValueError("Incorrect passphrase or damaged backup file")


def database_snapshot(destination: Path) -> None:
    source = sqlite3.connect(DB_PATH)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def create_backup(passphrase: object) -> tuple[Path, dict]:
    passphrase = validate_backup_passphrase(passphrase)
    descriptor, output_name = tempfile.mkstemp(prefix="gatehouse-", suffix=".ghbackup")
    os.close(descriptor)
    output = Path(output_name)
    try:
        with tempfile.TemporaryDirectory(prefix="gatehouse-backup-") as temporary:
            stage = Path(temporary)
            database_snapshot(stage / "proxy.db")
            with sqlite3.connect(stage / "proxy.db") as connection:
                route_count = connection.execute("SELECT COUNT(*) FROM proxy_hosts").fetchone()[0]
                user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            certificate_count = sum(1 for path in CERT_ROOT.glob("*") if path.is_dir() and (path / "fullchain.pem").exists()) if CERT_ROOT.exists() else 0
            manifest = {
                "format": "gatehouse-backup", "version": 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "routes": route_count, "users": user_count, "certificates": certificate_count,
            }
            (stage / "manifest.json").write_text(json.dumps(manifest, indent=2))
            certificate_stage = stage / "letsencrypt"
            certificate_stage.mkdir()
            if CERT_STORAGE_ROOT.exists():
                shutil.copytree(CERT_STORAGE_ROOT, certificate_stage, symlinks=True, dirs_exist_ok=True)
            archive = stage / "payload.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(stage / "manifest.json", arcname="manifest.json")
                bundle.add(stage / "proxy.db", arcname="proxy.db")
                bundle.add(certificate_stage, arcname="letsencrypt", recursive=True)
            encrypted = stage / "encrypted.bin"
            openssl_crypt(archive, encrypted, passphrase)
            ciphertext = encrypted.read_bytes()
            if len(ciphertext) + len(BACKUP_MAGIC) + 48 > MAX_BACKUP_BYTES:
                raise ValueError("Backup is larger than the 64 MiB migration limit")
            mac_salt = secrets.token_bytes(16)
            mac_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), mac_salt, BACKUP_ITERATIONS, dklen=32)
            signature = hmac.new(mac_key, BACKUP_MAGIC + mac_salt + ciphertext, hashlib.sha256).digest()
            output.write_bytes(BACKUP_MAGIC + mac_salt + signature + ciphertext)
            output.chmod(0o600)
            return output, manifest
    except Exception:
        output.unlink(missing_ok=True)
        raise


def decrypt_backup(data: bytes, passphrase: object, destination: Path) -> None:
    passphrase = validate_backup_passphrase(passphrase)
    header_size = len(BACKUP_MAGIC) + 16 + 32
    if len(data) < header_size or not data.startswith(BACKUP_MAGIC):
        raise ValueError("This is not a Gatehouse backup file")
    mac_salt = data[len(BACKUP_MAGIC):len(BACKUP_MAGIC) + 16]
    signature = data[len(BACKUP_MAGIC) + 16:header_size]
    ciphertext = data[header_size:]
    mac_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), mac_salt, BACKUP_ITERATIONS, dklen=32)
    expected = hmac.new(mac_key, BACKUP_MAGIC + mac_salt + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Incorrect passphrase or damaged backup file")
    encrypted = destination.with_suffix(".encrypted")
    encrypted.write_bytes(ciphertext)
    try:
        openssl_crypt(encrypted, destination, passphrase, decrypt=True)
    finally:
        encrypted.unlink(missing_ok=True)


def validate_restore_stage(stage: Path) -> dict:
    manifest_path, database_path = stage / "manifest.json", stage / "proxy.db"
    certificate_path = stage / "letsencrypt"
    if (manifest_path.is_symlink() or database_path.is_symlink() or certificate_path.is_symlink()
            or not manifest_path.is_file() or not database_path.is_file() or not certificate_path.is_dir()):
        raise ValueError("Backup is missing required migration data")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Backup manifest is invalid") from error
    if manifest.get("format") != "gatehouse-backup" or manifest.get("version") != 1:
        raise ValueError("This backup version is not supported")
    try:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Backup database failed its integrity check")
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"proxy_hosts", "users"}.issubset(tables):
            raise ValueError("Backup database is missing required tables")
        if connection.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0] < 1:
            raise ValueError("Backup must contain an enabled administrator")
    except sqlite3.DatabaseError as error:
        raise ValueError("Backup database is invalid") from error
    finally:
        if "connection" in locals():
            connection.close()
    return manifest


def clear_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    resolved = directory.resolve()
    if resolved == Path("/") or len(resolved.parts) < 3:
        raise RuntimeError("Refusing to replace an unsafe certificate directory")
    for child in directory.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)


def restore_backup(data: bytes, passphrase: object) -> dict:
    if not data or len(data) > MAX_BACKUP_BYTES:
        raise ValueError("Backup file must be smaller than 64 MiB")
    with tempfile.TemporaryDirectory(prefix="gatehouse-restore-") as temporary:
        work = Path(temporary)
        archive = work / "payload.tar.gz"
        decrypt_backup(data, passphrase, archive)
        stage = work / "stage"
        stage.mkdir()
        try:
            with tarfile.open(archive, "r:gz") as bundle:
                members = bundle.getmembers()
                if len(members) > 10_000 or sum(member.size for member in members) > 256 * 1024 * 1024:
                    raise ValueError("Backup archive exceeds the safe extraction limit")
                for member in members:
                    first = Path(member.name).parts[0] if Path(member.name).parts else ""
                    if first not in {"manifest.json", "proxy.db", "letsencrypt"} or member.isdev() or member.isfifo():
                        raise ValueError("Backup contains an unsafe archive entry")
                bundle.extractall(stage, filter="data")
        except (tarfile.TarError, OSError) as error:
            raise ValueError("Backup archive is invalid") from error
        manifest = validate_restore_stage(stage)

        rollback_db = work / "rollback.db"
        database_snapshot(rollback_db)
        rollback_certs = work / "rollback-letsencrypt"
        rollback_certs.mkdir()
        if CERT_STORAGE_ROOT.exists():
            shutil.copytree(CERT_STORAGE_ROOT, rollback_certs, symlinks=True, dirs_exist_ok=True)
        secret_path = DATA_DIR / "session_secret"
        previous_secret = secret_path.read_bytes() if secret_path.exists() else None
        try:
            incoming_db = DATA_DIR / ".proxy.db.restore"
            shutil.copy2(stage / "proxy.db", incoming_db)
            incoming_db.replace(DB_PATH)
            clear_directory(CERT_STORAGE_ROOT)
            shutil.copytree(stage / "letsencrypt", CERT_STORAGE_ROOT, symlinks=True, dirs_exist_ok=True)
            secret_path.unlink(missing_ok=True)
            initialize()
            render_and_reload()
        except Exception as error:
            shutil.copy2(rollback_db, DB_PATH)
            clear_directory(CERT_STORAGE_ROOT)
            shutil.copytree(rollback_certs, CERT_STORAGE_ROOT, symlinks=True, dirs_exist_ok=True)
            if previous_secret is None:
                secret_path.unlink(missing_ok=True)
            else:
                secret_path.write_bytes(previous_secret)
                secret_path.chmod(0o600)
            try:
                render_and_reload()
            except Exception:
                pass
            raise RuntimeError(f"Restore failed and the previous configuration was recovered: {error}") from error
        return manifest


def secret() -> bytes:
    return (DATA_DIR / "session_secret").read_bytes()


def make_session(user: sqlite3.Row) -> str:
    expires = str(int(time.time()) + SESSION_TTL)
    body = f'{user["username"]}:{expires}:{user["session_version"]}'
    signature = hmac.new(secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}:{signature}"


def valid_session(value: str) -> sqlite3.Row | None:
    try:
        username, expires, version, signature = value.split(":", 3)
        body = f"{username}:{expires}:{version}"
        expected = hmac.new(secret(), body.encode(), hashlib.sha256).hexdigest()
        if int(expires) <= time.time() or not hmac.compare_digest(signature, expected):
            return None
        with db() as connection:
            user = connection.execute("SELECT * FROM users WHERE username = ? AND enabled = 1", (username,)).fetchone()
        return user if user and user["session_version"] == int(version) else None
    except (ValueError, TypeError):
        return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NginxManager/0.1"

    def json_response(self, status: int, body: dict | list, cookie: str | None = None) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def payload(self, max_size: int = 64_000) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > max_size:
            raise ValueError("Request is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def file_response(self, path: Path, filename: str) -> None:
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with path.open("rb") as stream:
            shutil.copyfileobj(stream, self.wfile)

    def current_user(self) -> sqlite3.Row | None:
        cookies = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        item = cookies.get("nginx_manager_session")
        return valid_session(item.value) if item else None

    def authenticated(self) -> bool:
        return self.current_user() is not None

    def require_auth(self) -> bool:
        if self.authenticated():
            return True
        self.json_response(401, {"error": "Authentication required"})
        return False

    def require_admin(self) -> bool:
        user = self.current_user()
        if user and user["role"] == "admin":
            return True
        self.json_response(403, {"error": "Administrator access required"})
        return False

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/status":
            self.json_response(200, {"authenticated": self.authenticated(), "default_password": ADMIN_PASSWORD == "change-me-now"})
            return
        if path == "/api/me":
            user = self.current_user()
            if not user:
                self.json_response(401, {"error": "Authentication required"}); return
            self.json_response(200, public_user(user)); return
        if path == "/api/users":
            if not self.require_admin(): return
            with db() as connection:
                users = [public_user(row) for row in connection.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE")]
            self.json_response(200, users); return
        if path == "/api/backups/info":
            if not self.require_admin(): return
            with db() as connection:
                route_count = connection.execute("SELECT COUNT(*) FROM proxy_hosts").fetchone()[0]
                user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            certificate_count = sum(1 for item in CERT_ROOT.glob("*") if item.is_dir() and (item / "fullchain.pem").exists()) if CERT_ROOT.exists() else 0
            self.json_response(200, {
                "routes": route_count, "users": user_count, "certificates": certificate_count,
                "encrypted": True, "max_restore_bytes": MAX_BACKUP_BYTES,
            }); return
        if path == "/api/hosts":
            if not self.require_auth(): return
            with db() as connection:
                rows = [dict(row) for row in connection.execute("SELECT * FROM proxy_hosts ORDER BY id DESC")]
            for row in rows:
                row["websocket"] = bool(row["websocket"])
                row["enabled"] = bool(row["enabled"])
                primary_domain = row["domains"].split()[0]
                row["certificate_info"] = certificate_details(primary_domain, bool(row["certificate"]))
                row["certificate"] = bool(row["certificate_info"]["installed"])
            self.json_response(200, rows)
            return
        if path == "/api/stats":
            if not self.require_auth(): return
            self.json_response(200, stats_snapshot())
            return
        if path.startswith("/api/"):
            self.json_response(404, {"error": "Not found"})
            return
        file_path = WEB_ROOT / ("index.html" if path == "/" else path.lstrip("/"))
        try:
            file_path = file_path.resolve()
            if WEB_ROOT.resolve() not in file_path.parents and file_path != WEB_ROOT.resolve():
                raise FileNotFoundError
            data = file_path.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            self.send_error(404)
            return
        mime = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".png": "image/png"}.get(file_path.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self.payload(90 * 1024 * 1024 if path == "/api/backups/restore" else 64_000)
            if path == "/api/login":
                with db() as connection:
                    user = connection.execute("SELECT * FROM users WHERE username = ? AND enabled = 1", (str(payload.get("username", "")).strip(),)).fetchone()
                if not user or not verify_password(str(payload.get("password", "")), user["password_hash"]):
                    self.json_response(401, {"error": "Incorrect username or password"})
                    return
                cookie = f"nginx_manager_session={make_session(user)}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
                self.json_response(200, {"ok": True, "user": public_user(user)}, cookie)
                return
            if not self.require_auth(): return
            if path == "/api/logout":
                self.json_response(200, {"ok": True}, "nginx_manager_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                return
            if path == "/api/backups/create":
                if not self.require_admin(): return
                backup_path, manifest = create_backup(payload.get("passphrase"))
                try:
                    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    self.file_response(backup_path, f"gatehouse_{stamp}.ghbackup")
                finally:
                    backup_path.unlink(missing_ok=True)
                return
            if path == "/api/backups/restore":
                if not self.require_admin(): return
                encoded = payload.get("backup")
                if not isinstance(encoded, str):
                    raise ValueError("Choose a Gatehouse backup file")
                try:
                    backup_data = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    raise ValueError("Backup upload is invalid") from None
                manifest = restore_backup(backup_data, payload.get("passphrase"))
                self.json_response(200, {"ok": True, "restored": manifest, "signed_out": True})
                return
            if path == "/api/hosts":
                values = validate_payload(payload)
                connection = db()
                try:
                    ensure_domains_available(connection, values["domains"])
                    cursor = connection.execute(
                        "INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, websocket, enabled, allowlist, blocklist, created_at) VALUES (:domains,:upstream_scheme,:upstream_host,:upstream_port,:websocket,:enabled,:allowlist,:blocklist,:created_at)",
                        values | {"created_at": int(time.time())},
                    )
                    render_and_reload(connection=connection)
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
                self.json_response(201, {"id": cursor.lastrowid})
                return
            if path == "/api/users":
                if not self.require_admin(): return
                values = validate_user_payload(payload) | {"created_at": int(time.time())}
                with db() as connection:
                    cursor = connection.execute(
                        "INSERT INTO users (username, password_hash, role, enabled, created_at) VALUES (:username, :password_hash, :role, :enabled, :created_at)", values
                    )
                self.json_response(201, {"id": cursor.lastrowid}); return
            match = re.fullmatch(r"/api/hosts/(\d+)/certificate", path)
            if match:
                self.issue_certificate(int(match.group(1)), payload)
                return
            self.json_response(404, {"error": "Not found"})
        except sqlite3.IntegrityError:
            self.json_response(409, {"error": "That username is already in use" if path == "/api/users" else "That exact domain set already exists"})
        except (ValueError, json.JSONDecodeError) as error:
            self.json_response(400, {"error": str(error)})
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            self.json_response(500, {"error": str(error)})

    def do_PUT(self) -> None:
        if not self.require_auth(): return
        path = urlparse(self.path).path
        user_match = re.fullmatch(r"/api/users/(\d+)", path)
        if user_match:
            if not self.require_admin(): return
            try:
                values = validate_user_payload(self.payload(), require_password=False)
                user_id = int(user_match.group(1))
                actor = self.current_user()
                with db() as connection:
                    target = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not target: raise ValueError("User not found")
                    if target["id"] == actor["id"] and (values["username"] != target["username"] or values["role"] != target["role"] or values["enabled"] != target["enabled"]):
                        raise ValueError("You cannot change your own username, role, or status")
                    removing_admin = target["role"] == "admin" and target["enabled"] and (values["role"] != "admin" or not values["enabled"])
                    if removing_admin and connection.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1").fetchone()[0] <= 1:
                        raise ValueError("At least one enabled administrator is required")
                    connection.execute("UPDATE users SET username=:username, role=:role, enabled=:enabled WHERE id=:id", values | {"id": user_id})
                    if "password_hash" in values:
                        connection.execute("UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?", (values["password_hash"], user_id))
                self.json_response(200, {"ok": True}); return
            except sqlite3.IntegrityError:
                self.json_response(409, {"error": "That username is already in use"}); return
            except (ValueError, json.JSONDecodeError) as error:
                self.json_response(400, {"error": str(error)}); return
        match = re.fullmatch(r"/api/hosts/(\d+)", path)
        if not match:
            self.json_response(404, {"error": "Not found"}); return
        try:
            values = validate_payload(self.payload()) | {"id": int(match.group(1))}
            connection = db()
            try:
                ensure_domains_available(connection, values["domains"], values["id"])
                cursor = connection.execute("UPDATE proxy_hosts SET domains=:domains, upstream_scheme=:upstream_scheme, upstream_host=:upstream_host, upstream_port=:upstream_port, websocket=:websocket, enabled=:enabled, allowlist=:allowlist, blocklist=:blocklist WHERE id=:id", values)
                if not cursor.rowcount: raise ValueError("Proxy host not found")
                render_and_reload(connection=connection)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            self.json_response(200, {"ok": True})
        except (ValueError, json.JSONDecodeError, sqlite3.IntegrityError) as error:
            self.json_response(400, {"error": str(error)})
        except RuntimeError as error:
            self.json_response(500, {"error": str(error)})

    def do_DELETE(self) -> None:
        if not self.require_auth(): return
        path = urlparse(self.path).path
        user_match = re.fullmatch(r"/api/users/(\d+)", path)
        if user_match:
            if not self.require_admin(): return
            try:
                user_id = int(user_match.group(1))
                actor = self.current_user()
                if user_id == actor["id"]: raise ValueError("You cannot delete your own account")
                with db() as connection:
                    target = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not target: raise ValueError("User not found")
                    if target["role"] == "admin" and target["enabled"] and connection.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1").fetchone()[0] <= 1:
                        raise ValueError("At least one enabled administrator is required")
                    connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
                self.json_response(200, {"ok": True}); return
            except ValueError as error:
                self.json_response(400, {"error": str(error)}); return
        match = re.fullmatch(r"/api/hosts/(\d+)", path)
        if not match:
            self.json_response(404, {"error": "Not found"}); return
        connection = db()
        try:
            connection.execute("DELETE FROM proxy_hosts WHERE id = ?", (int(match.group(1)),))
            render_and_reload(connection=connection)
            connection.commit()
            self.json_response(200, {"ok": True})
        except Exception as error:
            connection.rollback()
            self.json_response(500, {"error": str(error)})
        finally:
            connection.close()

    def issue_certificate(self, host_id: int, payload: dict) -> None:
        with db() as connection:
            row = connection.execute("SELECT * FROM proxy_hosts WHERE id = ?", (host_id,)).fetchone()
        if not row: raise ValueError("Proxy host not found")
        domains = row["domains"].split()
        force = bool(payload.get("force", False))
        if force:
            if not certificate_exists(domains[0]):
                raise ValueError("No installed certificate is available to renew")
            command = ["certbot", "renew", "--cert-name", domains[0], "--force-renewal", "--non-interactive"]
        else:
            email = str(payload.get("email", "")).strip()
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise ValueError("Enter a valid email address")
            command = ["certbot", "certonly", "--webroot", "-w", ACME_ROOT, "--non-interactive", "--agree-tos", "--keep-until-expiring", "--email", email]
            for domain in domains:
                command.extend(["-d", domain])
        result = subprocess.run(command, text=True, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip()[-2000:])
        connection = db()
        try:
            connection.execute("UPDATE proxy_hosts SET certificate = 1 WHERE id = ?", (host_id,))
            render_and_reload(connection=connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        self.json_response(200, {"ok": True, "certificate": certificate_details(domains[0])})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    initialize()
    address = os.environ.get("LISTEN_ADDRESS", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.ThreadingHTTPServer((address, port), Handler)
    print(f"NGINX Manager listening on http://{address}:{port}", flush=True)
    server.serve_forever()
