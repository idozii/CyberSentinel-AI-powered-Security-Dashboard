"""Local-only demonstration webapp for CyberSentinel traffic collection.

Not an authentication service for production use. It intentionally keeps no
session state, accepts only a demo credential, and never logs passwords.
"""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

MAX_FORM_BYTES = 4096


class LabHandler(BaseHTTPRequestHandler):
    server_version = "CyberSentinelLab/0.1"

    def send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler interface
        path = urlsplit(self.path).path
        if path == "/":
            self.send_json(200, {"service": "cybersentinel-demo", "message": "Local security lab"})
        elif path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler interface
        if urlsplit(self.path).path != "/login":
            self.send_json(404, {"error": "not_found"})
            return

        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/x-www-form-urlencoded":
            self.send_json(415, {"error": "unsupported_media_type"})
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"error": "invalid_content_length"})
            return

        if length < 0:
            self.send_json(400, {"error": "invalid_content_length"})
            return
        if length > MAX_FORM_BYTES:
            self.send_json(413, {"error": "request_too_large"})
            return

        try:
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="strict"), keep_blank_values=True)
        except UnicodeDecodeError:
            self.send_json(400, {"error": "invalid_form"})
            return

        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        expected_username = os.getenv("DEMO_USERNAME", "")
        expected_password = os.getenv("DEMO_PASSWORD", "")
        if not expected_username or not expected_password:
            self.send_json(503, {"error": "demo_credentials_not_configured"})
            return

        valid = hmac.compare_digest(username, expected_username) and hmac.compare_digest(password, expected_password)
        if valid:
            self.send_json(200, {"result": "demo_login_success"})
        else:
            self.send_json(401, {"error": "invalid_credentials"})


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), LabHandler)


def main() -> None:
    host = os.getenv("LAB_HOST", "0.0.0.0")
    port = int(os.getenv("LAB_PORT", "8000"))
    with create_server(host, port) as server:
        print(f"CyberSentinel lab serving on {host}:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
