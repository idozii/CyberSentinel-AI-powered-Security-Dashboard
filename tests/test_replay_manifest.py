"""Test proxy correlation IDs with a local stub (real NGINX still needs smoke test)."""
import json
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scripts.attack_replay import replay_attack


class LocalProxyStub(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200 if self.path in ("/", "/health") else 404
        self.send_response(status)
        self.send_header("X-CyberSentinel-Request-ID", uuid.uuid4().hex)
        self.end_headers()

    def do_POST(self):
        self.send_response(401)
        self.send_header("X-CyberSentinel-Request-ID", uuid.uuid4().hex)
        self.end_headers()

    def log_message(self, *_):
        return


class ReplayManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manifest = Path(self.tmp.name) / "manifest.jsonl"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalProxyStub)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_mixed_manifest_has_distinct_ids_and_labels(self):
        result = replay_attack(base_url=self.base_url, scenario="mixed", source_ip="198.51.100.77",
                               attempts=5, concurrency=3, timeout=2.0, delay_ms=0, manifest_path=self.manifest)
        records = [json.loads(x) for x in self.manifest.read_text().splitlines()]
        self.assertEqual(result["labeled_requests"], 13)
        self.assertEqual(len(records), 13)
        self.assertEqual(len({r["request_id"] for r in records}), 13)
        self.assertEqual(sum(r["scenario_label"] == "simulated_brute_force" for r in records), 5)
        self.assertEqual(sum(r["scenario_label"] == "simulated_path_scan" for r in records), 8)
        self.assertEqual(result["statuses"].get("401"), 5)
        self.assertEqual(result["statuses"].get("404"), 8)

    def test_benign_is_explicitly_labeled(self):
        result = replay_attack(base_url=self.base_url, scenario="benign", source_ip="198.51.100.77",
                               attempts=6, concurrency=2, timeout=2.0, delay_ms=0, manifest_path=self.manifest)
        records = [json.loads(x) for x in self.manifest.read_text().splitlines()]
        self.assertEqual(result["statuses"], {"200": 6})
        self.assertEqual({r["scenario_label"] for r in records}, {"simulated_benign"})


if __name__ == "__main__":
    unittest.main()
