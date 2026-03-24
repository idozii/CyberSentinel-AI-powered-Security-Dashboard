from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Dict, Iterable, Iterator, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, "", "-"):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, "", "-"):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_ip(raw_ip: str) -> str:
    if not raw_ip:
        return ""
    if "," in raw_ip:
        return raw_ip.split(",", 1)[0].strip()
    return raw_ip.strip()


@dataclass
class TrafficEvent:
    schema_version: str
    captured_at: str
    service: str
    container_id: str
    source_ip: str
    http_method: str
    host: str
    path: str
    query_present: bool
    status_code: int
    request_bytes: int
    response_bytes: int
    duration_ms: float
    user_agent: str
    referer: str
    forwarded_for: str
    request_id: str
    raw: Dict[str, Any]


@dataclass
class CollectorConfig:
    input_path: Optional[Path]
    output_dir: Path
    target_service: str
    schema_version: str
    rotate_bytes: int
    follow: bool
    poll_interval: float


class JsonlRotator:
    def __init__(self, output_dir: Path, service: str, rotate_bytes: int) -> None:
        self.output_dir = output_dir
        self.service = service
        self.rotate_bytes = rotate_bytes
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._handle: Optional[IO[str]] = None
        self._current_path: Optional[Path] = None

    def _new_path(self) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        filename = f"{self.service}-{timestamp}-{suffix}.jsonl"
        return self.output_dir / filename

    def _ensure_handle(self) -> IO[str]:
        if self._handle is None:
            self._current_path = self._new_path()
            self._handle = self._current_path.open("a", encoding="utf-8")
        return self._handle

    def _should_rotate(self) -> bool:
        if self._handle is None or self._current_path is None:
            return False
        self._handle.flush()
        return self._current_path.stat().st_size >= self.rotate_bytes

    def write(self, event: TrafficEvent) -> Path:
        handle = self._ensure_handle()
        handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
        handle.flush()
        current_path = self._current_path
        if current_path is None:
            raise RuntimeError("rotation path missing after write")
        if self._should_rotate():
            self.rotate()
        return current_path

    def rotate(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        self._current_path = None

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        self._current_path = None


def parse_log_line(line: str, *, target_service: str, schema_version: str) -> Optional[TrafficEvent]:
    stripped = line.strip()
    if not stripped:
        return None

    payload = json.loads(stripped)
    service = str(payload.get("service") or "")
    if target_service and service and service != target_service:
        return None
    if target_service and not service:
        service = target_service

    path = str(payload.get("uri") or payload.get("path") or "")
    query_string = str(payload.get("args") or payload.get("query_string") or "")
    request_id = str(payload.get("request_id") or payload.get("trace_id") or uuid.uuid4().hex)
    forwarded_for = str(payload.get("xff") or payload.get("forwarded_for") or "")
    remote_addr = str(payload.get("remote_addr") or payload.get("source_ip") or "")
    source_ip = normalize_ip(forwarded_for or remote_addr)

    event = TrafficEvent(
        schema_version=schema_version,
        captured_at=str(payload.get("time_iso8601") or payload.get("timestamp") or utc_now()),
        service=service or target_service,
        container_id=str(payload.get("container_id") or ""),
        source_ip=source_ip,
        http_method=str(payload.get("request_method") or payload.get("method") or ""),
        host=str(payload.get("host") or ""),
        path=path,
        query_present=bool(query_string),
        status_code=safe_int(payload.get("status")),
        request_bytes=safe_int(payload.get("request_length")),
        response_bytes=safe_int(payload.get("bytes_sent") or payload.get("body_bytes_sent")),
        duration_ms=round(safe_float(payload.get("request_time")) * 1000, 3),
        user_agent=str(payload.get("http_user_agent") or payload.get("user_agent") or ""),
        referer=str(payload.get("http_referer") or payload.get("referer") or ""),
        forwarded_for=forwarded_for,
        request_id=request_id,
        raw=payload,
    )
    return event


def iter_lines(handle: IO[str], *, follow: bool, poll_interval: float) -> Iterator[str]:
    while True:
        position = handle.tell()
        line = handle.readline()
        if line:
            yield line
            continue
        if not follow:
            break
        handle.seek(position)
        time.sleep(poll_interval)


def process_stream(lines: Iterable[str], config: CollectorConfig, writer: JsonlRotator) -> int:
    written = 0
    for line in lines:
        try:
            event = parse_log_line(
                line,
                target_service=config.target_service,
                schema_version=config.schema_version,
            )
        except json.JSONDecodeError:
            continue
        if event is None:
            continue
        writer.write(event)
        written += 1
    return written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect proxy access logs into rotated JSONL files.")
    parser.add_argument("--input", dest="input_path", help="Path to the structured proxy access log file.")
    parser.add_argument("--output-dir", required=True, help="Directory where JSONL output files are written.")
    parser.add_argument("--target-service", required=True, help="Service name to stamp/filter in collected events.")
    parser.add_argument("--schema-version", default="traffic_event.v1", help="Schema version to include in events.")
    parser.add_argument("--rotate-bytes", type=int, default=5_000_000, help="Rotate the output file after this many bytes.")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval used when following a file.")
    parser.add_argument("--follow", action="store_true", help="Continue tailing the input file for new log lines.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = CollectorConfig(
        input_path=Path(args.input_path) if args.input_path else None,
        output_dir=Path(args.output_dir),
        target_service=args.target_service,
        schema_version=args.schema_version,
        rotate_bytes=args.rotate_bytes,
        follow=bool(args.follow),
        poll_interval=float(args.poll_interval),
    )

    writer = JsonlRotator(config.output_dir, config.target_service, config.rotate_bytes)
    try:
        if config.input_path is None:
            written = process_stream(sys.stdin, config, writer)
        else:
            with config.input_path.open("r", encoding="utf-8") as handle:
                if config.follow:
                    handle.seek(0, os.SEEK_END)
                written = process_stream(
                    iter_lines(handle, follow=config.follow, poll_interval=config.poll_interval),
                    config,
                    writer,
                )
    finally:
        writer.close()

    print(f"written_events={written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
