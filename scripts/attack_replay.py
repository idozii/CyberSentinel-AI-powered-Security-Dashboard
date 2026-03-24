from __future__ import annotations

import argparse
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Tuple
from urllib import error, parse, request


@dataclass(frozen=True)
class AttackRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes = b""


def build_login_bruteforce(base_ip: str, attempts: int) -> List[AttackRequest]:
    requests: List[AttackRequest] = []
    for index in range(attempts):
        payload = parse.urlencode(
            {
                "username": "admin",
                "password": f"BadGuess{index:03d}!",
            }
        ).encode("utf-8")
        requests.append(
            AttackRequest(
                method="POST",
                path="/login",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "CyberSentinel-AttackReplay/1.0 brute-force",
                    "X-Forwarded-For": base_ip,
                    "X-Attack-Scenario": "brute-force",
                },
                body=payload,
            )
        )
    return requests


def build_path_scan(base_ip: str) -> List[AttackRequest]:
    suspicious_paths = [
        "/admin",
        "/.env",
        "/wp-login.php",
        "/phpmyadmin",
        "/api/debug",
        "/actuator/health",
        "/../../etc/passwd",
        "/index.php?file=../../../../windows/win.ini",
    ]
    return [
        AttackRequest(
            method="GET",
            path=path,
            headers={
                "User-Agent": "CyberSentinel-AttackReplay/1.0 scanner",
                "X-Forwarded-For": base_ip,
                "X-Attack-Scenario": "scan",
            },
        )
        for path in suspicious_paths
    ]


def build_mixed_sequence(base_ip: str, attempts: int) -> List[AttackRequest]:
    return build_path_scan(base_ip) + build_login_bruteforce(base_ip, attempts)


SCENARIOS: Dict[str, Callable[[str, int], List[AttackRequest]]] = {
    "brute-force": lambda ip, attempts: build_login_bruteforce(ip, attempts),
    "scan": lambda ip, attempts: build_path_scan(ip),
    "mixed": build_mixed_sequence,
}


def send_request(base_url: str, attack_request: AttackRequest, timeout: float) -> Tuple[int, str]:
    target = parse.urljoin(base_url.rstrip("/") + "/", attack_request.path.lstrip("/"))
    req = request.Request(
        target,
        data=attack_request.body if attack_request.method != "GET" else None,
        method=attack_request.method,
        headers=attack_request.headers,
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return response.status, attack_request.path
    except error.HTTPError as exc:
        return exc.code, attack_request.path
    except error.URLError:
        return 0, attack_request.path


def replay_attack(
    *,
    base_url: str,
    scenario: str,
    source_ip: str,
    attempts: int,
    concurrency: int,
    timeout: float,
    delay_ms: int,
) -> Dict[str, object]:
    attack_requests = SCENARIOS[scenario](source_ip, attempts)
    statuses: Dict[str, int] = {}
    paths: List[str] = []
    lock = threading.Lock()

    def execute(attack_request: AttackRequest) -> Tuple[int, str]:
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
        return send_request(base_url, attack_request, timeout)

    with ThreadPoolExecutor(max_workers=max(concurrency, 1)) as executor:
        futures = [executor.submit(execute, attack_request) for attack_request in attack_requests]
        for future in as_completed(futures):
            status_code, path = future.result()
            with lock:
                statuses[str(status_code)] = statuses.get(str(status_code), 0) + 1
                paths.append(path)

    return {
        "scenario": scenario,
        "source_ip": source_ip,
        "total_requests": len(attack_requests),
        "statuses": statuses,
        "sample_paths": paths[:10],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay safe attack-like traffic against a local webapp proxy.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="Proxy base URL to target.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="mixed", help="Traffic pattern to replay.")
    parser.add_argument("--source-ip", default="198.51.100.77", help="Value placed in X-Forwarded-For.")
    parser.add_argument("--attempts", type=int, default=12, help="Number of login attempts for brute-force traffic.")
    parser.add_argument("--concurrency", type=int, default=4, help="Number of concurrent requests.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-request timeout in seconds.")
    parser.add_argument("--delay-ms", type=int, default=0, help="Optional delay before each request.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    summary = replay_attack(
        base_url=args.base_url,
        scenario=args.scenario,
        source_ip=args.source_ip,
        attempts=args.attempts,
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay_ms=args.delay_ms,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
