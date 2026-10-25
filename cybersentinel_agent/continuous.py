"""Bounded, restartable localhost NGINX log follower with a durable outbox.

All queued data has already been sanitized by to_minimal_event. The outbox and
cursor are committed in the same SQLite transaction. A successful HTTP receipt
must be observed before queued items are removed. This is at-least-once delivery,
not an exactly-once transport and not a production remote collector.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path
from contextlib import contextmanager
from typing import Callable

from cybersentinel_agent.client import AgentError, MAX_LINE_BYTES, send_events, to_minimal_event, validate_ingest_origin

MAX_QUEUE = 1000

# Each identity class is restricted to its corresponding ingest origin.
# A demo key must never be sent to PostgreSQL staging and vice versa.
DEMO_TOKEN = re.compile(r'^csd_[A-Za-z0-9_-]{40,64}$')
STAGING_TOKEN = re.compile(r'^csp_[a-f0-9]{32}_[A-Za-z0-9_-]{40,64}$')


def validate_watcher_identity(server: str, key: str) -> None:
    """Fail closed on any key / origin mismatch, before opening the outbox."""
    if not isinstance(key, str):
        raise AgentError('Invalid agent key for target origin')
    if server == 'http://127.0.0.1:8002':
        allowed = key.startswith('csa_') and len(key) >= 36
    elif server == 'http://127.0.0.1:8019':
        allowed = bool(DEMO_TOKEN.fullmatch(key))
    elif server == 'http://127.0.0.1:8008':
        allowed = bool(STAGING_TOKEN.fullmatch(key))
    elif server.startswith('https://'):
        # Step 14 already supports legacy csa_ HTTPS bridge credentials.
        # Preserve that tested behavior; csp_ belongs to the Step 18 endpoint.
        allowed = bool(STAGING_TOKEN.fullmatch(key)) or (key.startswith('csa_') and len(key) >= 36)
    else:
        allowed = False
    if not allowed:
        raise AgentError('Agent key type does not match the ingest origin')
MAX_READ_PER_POLL = 100
MAX_ROTATION_CANDIDATES = 32
STALE_SECONDS = 300


class Outbox:
    """Owner-only, SQLite-backed cursor and FIFO of sanitized event JSON."""

    def __init__(self, path: Path):
        path = Path(path).absolute()
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise AgentError("State database must be a regular file, not a symlink")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = path
        self.path.parent.chmod(0o700)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cursors (
                  log_path TEXT PRIMARY KEY,
                  device INTEGER NOT NULL,
                  inode INTEGER NOT NULL,
                  offset INTEGER NOT NULL CHECK(offset >= 0)
                );
                CREATE TABLE IF NOT EXISTS agent_settings (
                  name TEXT PRIMARY KEY, fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_id TEXT NOT NULL UNIQUE,
                  payload TEXT NOT NULL,
                  occurred_at INTEGER NOT NULL
                );
            """)
        self.path.chmod(0o600)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            with conn:
                yield conn
        finally:
            conn.close()

    def bind(self, domain_id: str, key: str, log_path: str) -> None:
        # Protect against sending persisted events under a different owner/key.
        fingerprint = hashlib.sha256((domain_id + "\0" + key + "\0" + log_path).encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint FROM agent_settings WHERE name='binding'").fetchone()
            if row and row[0] != fingerprint:
                raise AgentError("State belongs to a different domain, key or log. Use a new state file")
            if not row:
                db.execute("INSERT INTO agent_settings(name,fingerprint) VALUES('binding',?)", (fingerprint,))

    def cursor(self, log_path: str):
        with self._connect() as db:
            row = db.execute("SELECT device,inode,offset FROM cursors WHERE log_path=?", (log_path,)).fetchone()
        return tuple(int(x) for x in row) if row else None

    def size(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM queue").fetchone()[0])

    def save_line(self, log_path: str, device: int, inode: int, offset: int, event: dict | None):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if event is not None:
                if db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] >= MAX_QUEUE:
                    raise AgentError("Outbox full; no additional log data will be consumed")
                # Only minimized fields are ever serialized. Never save raw NGINX text.
                db.execute("INSERT OR IGNORE INTO queue(event_id,payload,occurred_at) VALUES (?,?,?)",
                           (event["event_id"], json.dumps(event, separators=(",", ":")), event["occurred_at"]))
            db.execute("INSERT INTO cursors(log_path,device,inode,offset) VALUES(?,?,?,?) "
                       "ON CONFLICT(log_path) DO UPDATE SET device=excluded.device,"
                       "inode=excluded.inode,offset=excluded.offset",
                       (log_path, int(device), int(inode), int(offset)))

    def pending(self, limit: int = 25):
        with self._connect() as db:
            rows = db.execute("SELECT seq,payload FROM queue ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [(int(s), json.loads(blob)) for s, blob in rows]

    def confirm(self, seqs: list[int]) -> None:
        if not seqs:
            return
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("DELETE FROM queue WHERE seq=?", ((s,) for s in seqs))

    def expired_count(self, clock: Callable[[], float] = time.time) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM queue WHERE occurred_at < ?",
                                  (int(clock()) - STALE_SECONDS,)).fetchone()[0])

    def purge_expired(self, *, confirm_loss: bool = False, clock: Callable[[], float] = time.time) -> int:
        if not confirm_loss:
            raise AgentError("Explicit --confirm-loss is required to discard stale events")
        with self._connect() as db:
            cur = db.execute("DELETE FROM queue WHERE occurred_at < ?", (int(clock()) - STALE_SECONDS,))
            return cur.rowcount


class ContinuousAgent:
    """Single-process follower. Use a process-level lock in the CLI."""

    def __init__(self, log_path: Path, state_path: Path, domain_id: str, key: str,
                 *, server: str = "http://127.0.0.1:8002", from_start: bool = False,
                 sender: Callable = send_events, clock: Callable[[], float] = time.time,
                 allowed_remote_host: str | None = None):
        self.log_path = Path(log_path).absolute()
        if self.log_path.is_symlink():
            raise AgentError("Refusing a symlinked NGINX log")
        self.log_id = str(self.log_path)
        origin = validate_ingest_origin(server, allowed_remote_host)
        if not re.fullmatch(r"[0-9a-f]{32}", domain_id):
            raise AgentError("Invalid domain ID")
        validate_watcher_identity(origin, key)
        self.store = Outbox(state_path)
        if self.store.path == self.log_path:
            raise AgentError("State database and watched log cannot be the same file")
        self.store.bind(domain_id, key, self.log_id)
        self.domain_id = domain_id
        self.key = key
        self.server = server
        self.allowed_remote_host = allowed_remote_host
        self.from_start = from_start
        self.sender = sender
        self.clock = clock
        self.handle = None
        self.device_inode = None
        self.rotation_pending = False
        self.warn_unrecoverable_rotation = False
        self.retry_after = 0.0
        self.failures = 0
        self.observed = 0
        self.accepted = 0
        self.duplicates = 0

    @staticmethod
    def _safe_stat(path: Path):
        if path.is_symlink():
            raise AgentError("Refusing symlinked log or rotated log")
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(st.st_mode):
            raise AgentError("Log input must be a regular file")
        return st

    def _open(self, path: Path, offset: int):
        self._safe_stat(path)
        handle = path.open("rb")
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            handle.close()
            raise AgentError("Log descriptor is not a regular file")
        handle.seek(offset)
        self.handle = handle
        self.device_inode = (st.st_dev, st.st_ino)

    def _find_rotated(self, target: tuple[int, int]):
        # A recovery attempt only. Not guaranteed on exotic log rotation schemes.
        current_prefix = self.log_path.name + "."
        try:
            candidates = sorted(self.log_path.parent.iterdir(), key=lambda p: p.name)
        except FileNotFoundError:
            return None
        checked = 0
        for p in candidates:
            if not p.name.startswith(current_prefix):
                continue
            checked += 1
            if checked > MAX_ROTATION_CANDIDATES:
                break
            st = self._safe_stat(p)
            if st and (st.st_dev, st.st_ino) == target:
                return p
        return None

    def _attach(self):
        if self.handle is not None:
            return
        current = self._safe_stat(self.log_path)
        cursor = self.store.cursor(self.log_id)
        if cursor:
            target = (cursor[0], cursor[1])
            if current and (current.st_dev, current.st_ino) == target:
                self._open(self.log_path, min(cursor[2], current.st_size))
                # copytruncate: reset when stored offset is beyond current size.
                if cursor[2] > current.st_size:
                    self.handle.seek(0)
                return
            rotated = self._find_rotated(target)
            if rotated is not None:
                self._open(rotated, min(cursor[2], rotated.stat().st_size))
                self.rotation_pending = True
                return
            self.warn_unrecoverable_rotation = True
            if current:
                self._open(self.log_path, 0)
            return
        if current:
            self._open(self.log_path, 0 if self.from_start else current.st_size)
            if not self.from_start:
                self.store.save_line(self.log_id, current.st_dev, current.st_ino, current.st_size, None)

    def _switch_if_needed(self):
        if self.handle is None:
            return
        latest = self._safe_stat(self.log_path)
        if latest and (latest.st_dev, latest.st_ino) != self.device_inode:
            self.rotation_pending = True
        elif latest is None:
            self.rotation_pending = True
        elif latest.st_size < self.handle.tell():
            # Copytruncate: same inode, shorter file.
            self.handle.seek(0)
            self.store.save_line(self.log_id, latest.st_dev, latest.st_ino, 0, None)

    def _advance(self) -> bool:
        """Read one complete line if possible. Do not advance on partial input."""
        assert self.handle is not None
        if self.store.size() >= MAX_QUEUE:
            return False
        start = self.handle.tell()
        raw = self.handle.readline(MAX_LINE_BYTES + 1)
        if not raw:
            return False
        if len(raw) > MAX_LINE_BYTES:
            self.handle.seek(start)
            raise AgentError("NGINX log line exceeds 8 KB; cursor retained")
        if not raw.endswith(b"\n"):
            self.handle.seek(start)
            return False
        if raw.strip():
            try:
                row = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                self.handle.seek(start)
                raise AgentError("Invalid JSON log line; cursor retained") from exc
            try:
                minimized = to_minimal_event(row, self.key)
            except AgentError:
                self.handle.seek(start)
                raise
        else:
            minimized = None
        device, inode = self.device_inode
        self.store.save_line(self.log_id, device, inode, self.handle.tell(), minimized)
        if minimized is not None:
            self.observed += 1
        return True

    def poll(self, max_lines: int = MAX_READ_PER_POLL) -> int:
        if not 1 <= max_lines <= MAX_READ_PER_POLL:
            raise AgentError("Invalid max_lines")
        self._attach()
        self._switch_if_needed()
        n = 0
        while n < max_lines and self.handle is not None:
            if self._advance():
                n += 1
                continue
            if self.rotation_pending and self.store.size() < MAX_QUEUE:
                # Old descriptor is at EOF; drain complete, then open the new inode.
                self.handle.close()
                self.handle = None
                self.rotation_pending = False
                current = self._safe_stat(self.log_path)
                if current:
                    self._open(self.log_path, 0)
                else:
                    break
                continue
            break
        return n

    def flush(self) -> dict:
        if self.clock() < self.retry_after:
            return {"state": "backoff", "queued": self.store.size()}
        batch = self.store.pending(25)
        if not batch:
            return {"state": "empty", "queued": 0}
        # An event older than 5 minutes will be rejected by the server.
        # Never silently discard it. Require operator acknowledgement.
        if any(abs(self.clock() - event["occurred_at"]) >= STALE_SECONDS - 5 for _, event in batch):
            raise AgentError("Queued events are near or past API freshness limit; resolve or explicitly purge expired")
        try:
            if self.allowed_remote_host:
                result = self.sender(self.server, self.domain_id, [item for _, item in batch],
                                     self.key, allowed_remote_host=self.allowed_remote_host)
            else:
                result = self.sender(self.server, self.domain_id, [item for _, item in batch], self.key)
        except AgentError as exc:
            status = re.search(r"HTTP (\d{3})", str(exc))
            code = int(status.group(1)) if status else None
            if code is not None and code != 429 and code < 500:
                raise AgentError(f"Permanent ingest error HTTP {code}; outbox retained") from exc
            self.failures += 1
            backoff = min(60.0, float(2 ** min(self.failures, 6)))
            self.retry_after = self.clock() + backoff
            return {"state": "retry", "queued": self.store.size(), "retry_in_seconds": backoff}
        if (type(result.get("accepted")) is not int or type(result.get("duplicates")) is not int
                or result["accepted"] < 0 or result["duplicates"] < 0
                or result["accepted"] + result["duplicates"] != len(batch)):
            raise AgentError("Unexpected server receipt; outbox retained")
        self.store.confirm([seq for seq, _ in batch])
        self.accepted += result["accepted"]
        self.duplicates += result["duplicates"]
        self.failures = 0
        self.retry_after = 0.0
        return {"state": "sent", "accepted": result["accepted"],
                "duplicates": result["duplicates"], "queued": self.store.size()}

    def step(self) -> dict:
        # Deliver queued data first, reducing chance of stale events on next poll.
        delivery = self.flush()
        consumed = self.poll()
        # If the first flush was throttled, don't force a second attempt.
        if delivery["state"] in ("empty", "sent") and self.store.size():
            delivery = self.flush()
        return {"read_lines": consumed, "delivery": delivery,
                "queued": self.store.size(), "observed_total": self.observed,
                "accepted_total": self.accepted, "duplicates_total": self.duplicates,
                "rotation_recovery_warning": self.warn_unrecoverable_rotation}

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None
