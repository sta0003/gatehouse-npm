import os
import tempfile
import unittest
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

temp = tempfile.TemporaryDirectory()
os.environ["DATA_DIR"] = temp.name
os.environ["NGINX_OUTPUT"] = str(Path(temp.name) / "proxy.conf")
os.environ["STREAM_OUTPUT"] = str(Path(temp.name) / "streams.conf")
os.environ["DNS_HOSTS"] = str(Path(temp.name) / "local-dns-hosts")
os.environ["DNSMASQ_PID"] = str(Path(temp.name) / "dnsmasq.pid")
os.environ["GATEHOUSE_LAN_IP"] = "192.168.1.50"
os.environ["CERT_STORAGE_ROOT"] = str(Path(temp.name) / "letsencrypt")
os.environ["CERT_ROOT"] = str(Path(temp.name) / "letsencrypt" / "live")
os.environ["ACME_ROOT"] = str(Path(temp.name) / "acme")

import app


class ValidationTests(unittest.TestCase):
    def test_password_hashing(self):
        encoded = app.hash_password("a-long-test-password")
        self.assertTrue(app.verify_password("a-long-test-password", encoded))
        self.assertFalse(app.verify_password("wrong-password", encoded))

    def test_rejects_short_password(self):
        with self.assertRaises(ValueError):
            app.hash_password("short")

    def test_normalizes_domains(self):
        self.assertEqual(app.normalize_domains("B.example.com, a.example.com b.example.com"), ["a.example.com", "b.example.com"])

    def test_rejects_nginx_injection(self):
        with self.assertRaises(ValueError):
            app.validate_payload({"domains": "ok.example.com", "upstream_host": "localhost; return 200", "upstream_port": 80})

    def test_validates_port(self):
        with self.assertRaises(ValueError):
            app.validate_payload({"domains": "ok.example.com", "upstream_host": "10.0.0.2", "upstream_port": 70000})

    def test_normalizes_ip_access_lists(self):
        values = app.validate_payload({
            "domains": "ok.example.com", "upstream_host": "10.0.0.2", "upstream_port": 80,
            "allowlist": "192.168.1.42, 2001:db8::1", "blocklist": "203.0.113.9/24",
        })
        self.assertEqual(values["allowlist"], "192.168.1.42/32\n2001:db8::1/128")
        self.assertEqual(values["blocklist"], "203.0.113.0/24")

    def test_rejects_invalid_ip_access_entry(self):
        with self.assertRaises(ValueError):
            app.validate_payload({"domains": "ok.example.com", "upstream_host": "10.0.0.2", "upstream_port": 80, "blocklist": "not-an-ip"})

    def test_rejects_domain_used_by_another_route(self):
        app.initialize()
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
            connection.execute("INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, created_at) VALUES (?, ?, ?, ?, ?)", ("used.example.com", "http", "10.0.0.2", 80, 1))
            with self.assertRaises(ValueError):
                app.ensure_domains_available(connection, "other.example.com used.example.com")

    def test_renders_route(self):
        app.initialize()
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
            connection.execute("INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, allowlist, blocklist, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", ("app.example.com", "http", "10.0.0.5", 3000, "192.168.1.0/24", "192.168.1.66/32", 1))
        rendered = app.render_config()
        self.assertIn("ssl_reject_handshake on", rendered)
        self.assertIn("server_name app.example.com", rendered)
        self.assertIn("proxy_pass http://10.0.0.5:3000", rendered)
        self.assertLess(rendered.index("deny 192.168.1.66/32"), rendered.index("allow 192.168.1.0/24"))
        self.assertIn("deny all", rendered)

    def test_disabled_route_is_not_rendered(self):
        app.initialize()
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
            connection.execute("INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)", ("paused.example.com", "http", "10.0.0.6", 8080, 0, 1))
        self.assertNotIn("paused.example.com", app.render_config())

    def test_validates_and_renders_game_port_remap(self):
        app.initialize()
        values = app.validate_stream_payload({
            "name": "Game server", "domain": "game.example.com", "listen_port": 25565,
            "protocol": "tcp", "upstream_host": "192.168.1.60", "upstream_port": 25566,
        })
        with app.db() as connection:
            connection.execute("DELETE FROM stream_routes")
            connection.execute(
                "INSERT INTO stream_routes (name, domain, kind, listen_port, protocol, upstream_host, upstream_port, enabled, created_at) VALUES (:name,:domain,:kind,:listen_port,:protocol,:upstream_host,:upstream_port,:enabled,1)", values
            )
        rendered = app.render_stream_config()
        self.assertIn("listen 25565", rendered)
        self.assertIn("proxy_pass 192.168.1.60:25566", rendered)

    def test_renders_raw_tcp_service_in_nginx(self):
        app.initialize()
        values = app.validate_stream_payload({
            "name": "Other game", "domain": "game.example.com", "listen_port": 27015,
            "protocol": "tcp", "upstream_host": "192.168.1.61", "upstream_port": 27016,
        })
        with app.db() as connection:
            connection.execute("DELETE FROM stream_routes")
            connection.execute(
                "INSERT INTO stream_routes (name, domain, kind, listen_port, protocol, upstream_host, upstream_port, enabled, created_at) VALUES (:name,:domain,:kind,:listen_port,:protocol,:upstream_host,:upstream_port,:enabled,1)", values
            )
        rendered = app.render_stream_config()
        self.assertIn("listen 27015", rendered)
        self.assertIn("proxy_pass 192.168.1.61:27016", rendered)

    def test_rejects_reserved_and_duplicate_stream_ports(self):
        app.initialize()
        with self.assertRaisesRegex(ValueError, "reserved"):
            app.validate_stream_payload({"name": "Bad", "domain": "bad.example.com", "listen_port": 443, "protocol": "tcp", "upstream_host": "10.0.0.2", "upstream_port": 443})
        with app.db() as connection:
            connection.execute("DELETE FROM stream_routes")
            connection.execute("INSERT INTO stream_routes (name, domain, kind, listen_port, protocol, upstream_host, upstream_port, created_at) VALUES ('Existing','one.example.com','port',25565,'both','10.0.0.2',25565,1)")
            with self.assertRaisesRegex(ValueError, "already assigned"):
                app.ensure_stream_route_available(connection, {"domain": "two.example.com", "listen_port": 25565, "protocol": "tcp"})

    def test_local_dns_includes_web_and_game_domains(self):
        app.initialize()
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
            connection.execute("DELETE FROM stream_routes")
            connection.execute("INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, created_at) VALUES ('app.example.com alias.example.com','http','10.0.0.3',80,1)")
            connection.execute("INSERT INTO stream_routes (name, domain, listen_port, protocol, upstream_host, upstream_port, created_at) VALUES ('Game server','game.example.com',25565,'tcp','10.0.0.4',25565,1)")
        rendered = app.render_dns_hosts()
        self.assertIn("192.168.1.50 app.example.com", rendered)
        self.assertIn("192.168.1.50 alias.example.com", rendered)
        self.assertIn("192.168.1.50 game.example.com", rendered)

    def test_reads_certificate_metadata(self):
        domain = "secure.example.com"
        directory = app.CERT_ROOT / domain
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("cert.pem", "fullchain.pem", "privkey.pem"):
            (directory / name).write_text("test")
        now = datetime.now(timezone.utc)
        decoded = {
            "notBefore": (now - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": (now + timedelta(days=20)).strftime("%b %d %H:%M:%S %Y GMT"),
            "issuer": ((('organizationName', "Let's Encrypt"),), (('commonName', 'Test CA'),)),
            "serialNumber": "ABC123",
            "subjectAltName": (("DNS", domain),),
        }
        with mock.patch.object(app.ssl._ssl, "_test_decode_cert", return_value=decoded):
            details = app.certificate_details(domain)
        self.assertTrue(details["installed"])
        self.assertEqual(details["status"], "expiring")
        self.assertEqual(details["issuer"], "Let's Encrypt · Test CA")
        self.assertEqual(details["sans"], [domain])

    def test_summarizes_json_access_log(self):
        log_path = Path(temp.name) / "access.log"
        app.ACCESS_LOG = log_path
        now = datetime.now(timezone.utc).isoformat()
        log_path.write_text("\n".join([
            json.dumps({"time": now, "host": "app.example.com", "status": 200, "bytes": 512, "request_time": 0.04}),
            json.dumps({"time": now, "host": "app.example.com", "status": 502, "bytes": 128, "request_time": 0.16}),
        ]))
        snapshot = app.stats_snapshot()
        self.assertEqual(snapshot["requests"], 2)
        self.assertEqual(snapshot["status"]["5xx"], 1)
        self.assertEqual(snapshot["avg_latency_ms"], 100)

    def test_encrypted_backup_round_trip(self):
        app.initialize()
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
            connection.execute(
                "INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, created_at) VALUES (?, ?, ?, ?, ?)",
                ("backup.example.com", "http", "10.0.0.20", 8123, 1),
            )
        certificate_file = app.CERT_STORAGE_ROOT / "archive" / "backup.example.com" / "cert1.pem"
        certificate_file.parent.mkdir(parents=True, exist_ok=True)
        certificate_file.write_text("certificate-data")
        backup, manifest = app.create_backup("a-strong-backup-passphrase")
        self.addCleanup(backup.unlink, missing_ok=True)
        self.assertEqual(manifest["routes"], 1)
        with app.db() as connection:
            connection.execute("DELETE FROM proxy_hosts")
        certificate_file.unlink()
        with mock.patch.object(app, "render_and_reload"):
            restored = app.restore_backup(backup.read_bytes(), "a-strong-backup-passphrase")
        with app.db() as connection:
            domains = connection.execute("SELECT domains FROM proxy_hosts").fetchone()[0]
        self.assertEqual(domains, "backup.example.com")
        self.assertEqual(certificate_file.read_text(), "certificate-data")
        self.assertEqual(restored["version"], 1)

    def test_backup_rejects_wrong_passphrase_and_tampering(self):
        app.initialize()
        backup, _ = app.create_backup("the-correct-backup-passphrase")
        self.addCleanup(backup.unlink, missing_ok=True)
        with self.assertRaisesRegex(ValueError, "Incorrect passphrase"):
            app.restore_backup(backup.read_bytes(), "the-wrong-backup-passphrase")
        damaged = bytearray(backup.read_bytes())
        damaged[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "damaged backup"):
            app.restore_backup(bytes(damaged), "the-correct-backup-passphrase")


if __name__ == "__main__":
    unittest.main()
