"""Minimal-data NGINX JSONL adapter and opt-in HTTPS staging delivery.

Raw IPs, URLs, queries, request bodies, User-Agent, cookies and passwords
never leave this process. An HMAC pseudonym represents the client per UTC day.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, parse, request

MAX_LINE_BYTES = 8192
MAX_BATCH = 25
REQUEST_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")


class AgentError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_local_server(url: str) -> str:
    try:
        parsed = parse.urlsplit(url)
        addr = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise AgentError("Server must be an explicit localhost HTTP origin") from exc
    if parsed.scheme != "http" or not addr.is_loopback or addr.version != 4 or port != 8002:
        raise AgentError("Step 11 agent accepts only http://127.0.0.1:8002")
    if parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise AgentError("Server URL must be exactly http://127.0.0.1:8002")
    return "http://127.0.0.1:8002"



def validate_ingest_origin(url: str, allowed_remote_host: str | None = None) -> str:
    """Keep loopback mode by default; permit ONLY an explicitly pinned HTTPS hostname.

    The remote host is an operator-controlled CLI option, not a value accepted from
    arbitrary network requests. urllib provides certificate and hostname validation.
    No redirects or proxy environment variables are permitted by send_events.
    """
    if url == "http://127.0.0.1:8002" or url == "http://127.0.0.1:8002/":
        return validate_local_server(url)
    if allowed_remote_host is None:
        raise AgentError("Remote HTTPS requires --allow-remote-host")
    if not isinstance(allowed_remote_host, str) or not allowed_remote_host:
        raise AgentError("Invalid approved HTTPS hostname")
    if not isinstance(url, str) or len(url) > 300:
        raise AgentError("Invalid ingest URL")
    try:
        parsed = parse.urlsplit(url)
        port = parsed.port
        host = parsed.hostname
    except (ValueError, TypeError) as exc:
        raise AgentError("Invalid ingest URL") from exc
    hostname_pattern = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$")
    if (parsed.scheme != "https" or not host or host != allowed_remote_host
            or not hostname_pattern.fullmatch(host)
            or "." not in host or ".." in host or host.endswith(".localhost")
            or host.endswith((".local", ".internal", ".test", ".invalid", ".example", ".onion"))
            or host.startswith("xn--") or ".xn--" in host
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or port not in (None, 443)):
        raise AgentError("Remote ingest must be an approved HTTPS DNS origin on port 443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise AgentError("Remote ingest host cannot be an IP literal")
    return f"https://{host}"

def _as_int(value, field: str, max_value: int) -> int:
    try:
        if isinstance(value, bool) or value is None or str(value).strip() == "":
            raise ValueError("not an integer")
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise AgentError(f"Invalid {field}") from exc
    if not 0 <= v <= max_value:
        raise AgentError(f"Invalid {field}")
    return v


def to_minimal_event(row: dict, key: str) -> dict:
    if not isinstance(row, dict):
        raise AgentError("NGINX row must be an object")
    try:
        when = datetime.fromisoformat(str(row["time_iso8601"]).replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError("timezone required")
        stamp = int(when.timestamp())
    except (KeyError, ValueError, TypeError, OverflowError) as exc:
        raise AgentError("Invalid NGINX timestamp") from exc
    if abs(time.time() - stamp) > 300:
        raise AgentError("Outdated NGINX event; only last 5 minutes are accepted")
    method = str(row.get("request_method", "")).upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise AgentError("Invalid method")
    status = _as_int(row.get("status"), "status", 599)
    if status < 100:
        raise AgentError("Invalid status")
    try:
        duration = float(row.get("request_time", 0)) * 1000
    except (TypeError, ValueError) as exc:
        raise AgentError("Invalid request duration") from exc
    if not math.isfinite(duration) or not 0 <= duration <= 120000:
        raise AgentError("Invalid request duration")
    try:
        src = ipaddress.ip_address(str(row["remote_addr"]))
    except (KeyError, ValueError) as exc:
        raise AgentError("Invalid source address") from exc
    rid = str(row.get("request_id", ""))
    if not REQUEST_ID_RE.fullmatch(rid):
        raise AgentError("Invalid NGINX request identifier")
    # Only inspect the first path segment; never send raw URL or query.
    uri = str(row.get("uri", ""))
    path = parse.urlsplit(uri).path.lower().rstrip("/")
    if path == "/login":
        group = "login"
    elif path == "/health":
        group = "health"
    elif path.startswith("/admin"):
        group = "admin"
    elif path.startswith("/api/") or path == "/api":
        group = "api"
    else:
        group = "other"
    day = when.astimezone(timezone.utc).strftime("%Y%m%d")
    secret = key.encode("utf-8")
    source_ref = hmac.new(secret, f"client:{day}:{src.compressed}".encode(), hashlib.sha256).hexdigest()[:32]
    event_id = hmac.new(secret, f"event:{rid}:{stamp}".encode(), hashlib.sha256).hexdigest()[:32]
    return {
        "event_id": event_id, "occurred_at": stamp,
        "source_ref": source_ref, "method": method, "path_group": group,
        "status_code": status, "duration_ms": round(duration, 3),
        "request_bytes": _as_int(row.get("request_length", 0), "request length", 100000000),
        "response_bytes": _as_int(row.get("bytes_sent", 0), "response bytes", 100000000),
    }


def send_events(server: str, domain_id: str, events: list[dict], key: str,
                *, allowed_remote_host: str | None = None) -> dict:
    base = validate_ingest_origin(server, allowed_remote_host)
    if not key.startswith("csa_") or len(key) < 36:
        raise AgentError("Missing or invalid agent key")
    if not 1 <= len(events) <= MAX_BATCH:
        raise AgentError("Batch must contain 1..25 events")
    if not re.fullmatch(r"[0-9a-f]{32}", domain_id):
        raise AgentError("Invalid domain ID")
    blob = json.dumps({"domain_id": domain_id, "events": events}, separators=(",", ":")).encode("utf-8")
    if len(blob) > 32768:
        raise AgentError("Batch too large")
    req = request.Request(base + "/agent/v1/ingest", method="POST", data=blob,
                          headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=5) as response:
            if response.status != 200:
                raise AgentError("Unexpected ingest status")
            result = json.loads(response.read(2048))
            return {"accepted": result["accepted"], "duplicates": result["duplicates"],
                    "alerts_updated": result.get("alerts_updated", 0)}
    except error.HTTPError as exc:
        raise AgentError(f"Ingest rejected request (HTTP {exc.code})") from None
    except (error.URLError, OSError, ValueError, KeyError) as exc:
        raise AgentError("Cannot deliver batch to configured ingest API") from exc


def load_events(file: Path, key: str, max_events: int = 25) -> list[dict]:
    if not 1 <= max_events <= 25:
        raise AgentError("max_events must be 1..25")
    found: list[dict] = []
    with Path(file).open("rb") as handle:
        for raw in handle:
            if len(raw) > MAX_LINE_BYTES:
                raise AgentError("NGINX log line exceeds 8 KB")
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except (UnicodeDecodeError, ValueError) as exc:
                raise AgentError("Invalid JSONL input") from exc
            found.append(to_minimal_event(row, key))
            if len(found) >= max_events:
                break
    return found
