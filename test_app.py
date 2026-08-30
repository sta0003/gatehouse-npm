import os
import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path

temp = tempfile.TemporaryDirectory()
os.environ["DATA_DIR"] = temp.name
os.environ["NGINX_OUTPUT"] = str(Path(temp.name) / "proxy.conf")
os.environ["CERT_ROOT"] = str(Path(temp.name) / "certs")
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
            connection.execute("INSERT INTO proxy_hosts (domains, upstream_scheme, upstream_host, upstream_port, created_at) VALUES (?, ?, ?, ?, ?)", ("app.example.com", "http", "10.0.0.5", 3000, 1))
        rendered = app.render_config()
        self.assertIn("ssl_reject_handshake on", rendered)
        self.assertIn("server_name app.example.com", rendered)
        self.assertIn("proxy_pass http://10.0.0.5:3000", rendered)

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


if __name__ == "__main__":
    unittest.main()
