"""Tests for the local-only demonstration webapp and replay integration."""

from __future__ import annotations

import json
import os
import threading
import unittest
from unittest.mock import patch
from urllib import error, parse, request

from scripts.attack_replay import replay_attack
from simulations.webapp.app import create_server


class WebappTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = patch.dict(os.environ, {
            "DEMO_USERNAME": "demo",
            "DEMO_PASSWORD": "demo-only-not-a-real-secret",
        })
        self.env.start()
        self.server = create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.env.stop()

    def test_root_and_health(self) -> None:
        for path in ("/", "/health"):
            with self.subTest(path=path), request.urlopen(self.base_url + path) as response:
                self.assertEqual(response.status, 200)
                self.assertTrue(json.loads(response.read().decode()))

    def test_probe_paths_not_exposed(self) -> None:
        for path in ("/.env", "/admin", "/wp-login.php"):
            with self.subTest(path=path), self.assertRaises(error.HTTPError) as raised:
                request.urlopen(self.base_url + path)
            self.assertEqual(raised.exception.code, 404)

    def post_login(self, username: str, password: str) -> int:
        payload = parse.urlencode({"username": username, "password": password}).encode()
        req = request.Request(
            self.base_url + "/login", data=payload, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with request.urlopen(req) as response:
                return response.status
        except error.HTTPError as exc:
            return exc.code

    def test_wrong_credentials_return_401(self) -> None:
        self.assertEqual(self.post_login("admin", "wrong"), 401)

    def test_demo_credentials_return_200(self) -> None:
        self.assertEqual(self.post_login("demo", "demo-only-not-a-real-secret"), 200)

    def test_mixed_replay_produces_401_and_404(self) -> None:
        result = replay_attack(
            base_url=self.base_url,
            scenario="mixed", source_ip="198.51.100.77",
            attempts=5, concurrency=3, timeout=2.0, delay_ms=0,
        )
        self.assertEqual(result["total_requests"], 13)
        self.assertEqual(result["statuses"].get("401"), 5)
        self.assertEqual(result["statuses"].get("404"), 8)

    def test_replay_rejects_nonlocal_target(self) -> None:
        with self.assertRaises(ValueError):
            replay_attack(
                base_url="http://example.com", scenario="mixed",
                source_ip="198.51.100.77", attempts=5,
                concurrency=3, timeout=2.0, delay_ms=0,
            )


if __name__ == "__main__":
    unittest.main()
