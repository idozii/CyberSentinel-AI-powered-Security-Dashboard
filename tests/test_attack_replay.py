import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scripts.attack_replay import replay_attack


class RecordingHandler(BaseHTTPRequestHandler):
    requests = []

    def _record(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b""
        self.__class__.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body.decode("utf-8", errors="ignore"),
            }
        )

    def do_GET(self) -> None:
        self._record()
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")

    def do_POST(self) -> None:
        self._record()
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b"unauthorized")

    def log_message(self, format: str, *args) -> None:
        return


class AttackReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        RecordingHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_mixed_attack_replay_generates_suspicious_paths_and_methods(self) -> None:
        summary = replay_attack(
            base_url=self.base_url,
            scenario="mixed",
            source_ip="198.51.100.77",
            attempts=5,
            concurrency=3,
            timeout=2.0,
            delay_ms=0,
        )

        captured = RecordingHandler.requests
        self.assertEqual(summary["total_requests"], 13)
        self.assertEqual(len(captured), 13)
        self.assertIn("401", summary["statuses"])
        self.assertIn("404", summary["statuses"])
        self.assertTrue(any(item["path"] == "/login" for item in captured))
        self.assertTrue(any(item["path"] == "/.env" for item in captured))
        self.assertTrue(any(item["method"] == "POST" for item in captured))
        self.assertTrue(any(item["headers"].get("X-Attack-Scenario") == "scan" for item in captured))
        self.assertTrue(any(item["headers"].get("X-Attack-Scenario") == "brute-force" for item in captured))


if __name__ == "__main__":
    unittest.main()
