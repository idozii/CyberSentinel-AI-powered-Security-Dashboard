"""Small, bounded security-telemetry simulation against a local lab only."""

from __future__ import annotations

import argparse
import ipaddress
import json
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Tuple
from urllib import error, parse, request


@dataclass(frozen=True)
class AttackRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes = b""
    label: str = "unlabeled"


def build_login_bruteforce(base_ip: str, attempts: int) -> List[AttackRequest]:
    attempts_list: List[AttackRequest] = []
    for index in range(attempts):
        payload = parse.urlencode({
            "username": "admin", "password": f"BadGuess{index:03d}!"
        }).encode("utf-8")
        attempts_list.append(AttackRequest(
            method="POST", path="/login",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "CyberSentinel-AttackReplay/1.0 brute-force",
                "X-Forwarded-For": base_ip,
                "X-Attack-Scenario": "brute-force",
            }, body=payload, label="simulated_brute_force",
        ))
    return attempts_list


def build_path_scan(base_ip: str) -> List[AttackRequest]:
    suspicious_paths = [
        "/admin", "/.env", "/wp-login.php", "/phpmyadmin",
        "/api/debug", "/actuator/health", "/../../etc/passwd",
        "/index.php?file=../../../../windows/win.ini",
    ]
    return [AttackRequest(
        method="GET", path=path,
        headers={
            "User-Agent": "CyberSentinel-AttackReplay/1.0 scanner",
            "X-Forwarded-For": base_ip,
            "X-Attack-Scenario": "scan",
        },
        label="simulated_path_scan",
    ) for path in suspicious_paths]


def build_benign(base_ip: str, attempts: int) -> List[AttackRequest]:
    """Generate bounded benign traffic for a controlled baseline."""
    return [AttackRequest(
        method="GET",
        path="/health" if i % 2 else "/",
        headers={
            "User-Agent": "CyberSentinel-Lab/1.0",
            "X-Forwarded-For": base_ip,
        },
        label="simulated_benign",
    ) for i in range(attempts)]


def build_mixed_sequence(base_ip: str, attempts: int) -> List[AttackRequest]:
    return build_path_scan(base_ip) + build_login_bruteforce(base_ip, attempts)


SCENARIOS: Dict[str, Callable[[str, int], List[AttackRequest]]] = {
    "brute-force": build_login_bruteforce,
    "scan": lambda ip, attempts: build_path_scan(ip),
    "mixed": build_mixed_sequence,
    "benign": build_benign,
}


def validate_local_target(base_url: str) -> str:
    parsed = parse.urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("The simulation target must be a local HTTP URL")
    try:
        local = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = parsed.hostname.lower() == "localhost"
    if not local or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("Only http://localhost or a loopback IP (with optional port) is allowed")
    return base_url


class NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_request_with_id(
    base_url: str, attack_request: AttackRequest, timeout: float
) -> Tuple[int, str, str]:
    """Return HTTP status, requested path, and NGINX-issued request ID."""
    target = parse.urljoin(base_url.rstrip("/") + "/", attack_request.path.lstrip("/"))
    req = request.Request(
        target,
        data=attack_request.body if attack_request.method != "GET" else None,
        method=attack_request.method,
        headers=attack_request.headers,
    )
    opener = request.build_opener(request.ProxyHandler({}), NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as response:
            return (
                response.status,
                attack_request.path,
                response.headers.get("X-CyberSentinel-Request-ID", ""),
            )
    except error.HTTPError as exc:
        return (
            exc.code,
            attack_request.path,
            exc.headers.get("X-CyberSentinel-Request-ID", ""),
        )
    except error.URLError:
        return 0, attack_request.path, ""


def send_request(base_url: str, attack_request: AttackRequest, timeout: float) -> Tuple[int, str]:
    """Compatibility wrapper for callers expecting (status, path)."""
    status, path, _ = send_request_with_id(base_url, attack_request, timeout)
    return status, path


def replay_attack(
    *, base_url: str, scenario: str, source_ip: str, attempts: int,
    concurrency: int, timeout: float, delay_ms: int,
    manifest_path: Path | None = None,
) -> Dict[str, object]:
    """Run local-only traffic, optionally recording supervised lab labels separately."""
    validate_local_target(base_url)
    if scenario not in SCENARIOS:
        raise ValueError("Unknown scenario")
    if not 1 <= attempts <= 50:
        raise ValueError("Attempts must be between 1 and 50")
    if not 1 <= concurrency <= 8:
        raise ValueError("Concurrency must be between 1 and 8")
    if not 0 < timeout <= 10:
        raise ValueError("Timeout must be between 0 and 10 seconds")
    if not 0 <= delay_ms <= 5000:
        raise ValueError("Delay must be between 0 and 5000 ms")

    attack_requests = SCENARIOS[scenario](source_ip, attempts)
    statuses: Dict[str, int] = {}
    paths: List[str] = []
    manifest_records: List[dict[str, object]] = []
    run_id = uuid.uuid4().hex

    def execute(attack_request: AttackRequest) -> Tuple[int, str, str]:
        if delay_ms:
            time.sleep(delay_ms / 1000)
        return send_request_with_id(base_url, attack_request, timeout)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(execute, item): item for item in attack_requests
        }
        for future in as_completed(futures):
            status_code, path, request_id = future.result()
            item = futures[future]
            statuses[str(status_code)] = statuses.get(str(status_code), 0) + 1
            paths.append(path)
            if manifest_path is not None:
                if not request_id:
                    raise ValueError(
                        "Missing X-CyberSentinel-Request-ID response header. "
                        "Run via updated NGINX; direct webapp requests cannot be labeled."
                    )
                manifest_records.append({
                    "request_id": request_id,
                    "run_id": run_id,
                    "scenario_label": item.label,
                    "observed_status": status_code,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                })

    if manifest_path is not None:
        ids = [str(row["request_id"]) for row in manifest_records]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate proxy request IDs; refusing ambiguous manifest")
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("a", encoding="utf-8") as handle:
            for row in manifest_records:
                handle.write(json.dumps(row, separators=(",", ":")) + "\n")

    result: Dict[str, object] = {
        "scenario": scenario,
        "source_ip": source_ip,
        "total_requests": len(attack_requests),
        "statuses": statuses,
        "sample_paths": paths[:10],
    }
    if manifest_path is not None:
        result["labeled_requests"] = len(manifest_records)
        result["manifest_path"] = str(manifest_path)
        result["run_id"] = run_id
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate bounded traffic only against a localhost demo proxy")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="mixed")
    parser.add_argument("--source-ip", default="198.51.100.77")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--manifest-path", type=Path, default=None,
                        help="Write labels separately, joined by NGINX request ID")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = replay_attack(
            base_url=args.base_url,
            scenario=args.scenario,
            source_ip=args.source_ip,
            attempts=args.attempts,
            concurrency=args.concurrency,
            timeout=args.timeout,
            delay_ms=args.delay_ms,
            manifest_path=args.manifest_path,
        )
    except ValueError as exc:
        print(f"Invalid simulation parameters: {exc}")
        return 2
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
