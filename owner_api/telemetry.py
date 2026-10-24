"""Local owner-scoped telemetry API-key management and bounded event persistence.

This is a development-only ingestion store, not a production multi-tenant pipeline.
No raw IP, URL, query, request body, cookies or credentials are accepted.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from owner_api.store import OwnerError, OwnerStore
from owner_api.detection import DetectionStore

KEY_PREFIX = "csa_"
MAX_ACTIVE_KEYS = 3
MAX_EVENTS_PER_BATCH = 25
MAX_EVENTS_PER_MINUTE = 300
RETENTION_SECONDS = 7 * 86400
SOURCE_PATTERN = re.compile(r"^[a-f0-9]{32}$")
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
PATH_GROUPS = frozenset({"login", "health", "admin", "api", "other"})


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class TelemetryStore:
    def __init__(self, owner_store: OwnerStore):
        self.owners = owner_store
        with self.owners._db(write=True) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agent_keys (
                    id TEXT PRIMARY KEY, domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
                    created_at REAL NOT NULL, revoked_at REAL,
                    last_used_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_keys_domain ON agent_keys(domain_id);
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id TEXT PRIMARY KEY, domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    agent_event_id TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL, received_at REAL NOT NULL,
                    source_ref TEXT NOT NULL, method TEXT NOT NULL, path_group TEXT NOT NULL,
                    status_code INTEGER NOT NULL, duration_ms REAL NOT NULL,
                    request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL,
                    UNIQUE(domain_id, agent_event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_domain_time ON telemetry_events(domain_id, received_at);
            """)
        self.detector = DetectionStore(self.owners)

    @staticmethod
    def _verified_domain(conn: sqlite3.Connection, owner_id: str, domain_id: str):
        row = conn.execute("SELECT id, domain, verified_at FROM domains WHERE id=? AND user_id=?",
                           (domain_id, owner_id)).fetchone()
        if not row:
            raise OwnerError("Domain not found", 404)
        if row["verified_at"] is None:
            raise OwnerError("Verify DNS ownership before connecting an agent", 409)
        return row

    def issue_key(self, owner_id: str, domain_id: str, label: str) -> dict:
        label = label.strip()
        if not (1 <= len(label) <= 64 and all(32 <= ord(c) <= 126 for c in label)):
            raise OwnerError("Invalid agent key label", 422)
        token = KEY_PREFIX + secrets.token_urlsafe(32)
        kid = uuid.uuid4().hex
        now = time.time()
        with self.owners._db(write=True) as conn:
            self._verified_domain(conn, owner_id, domain_id)
            active = conn.execute("SELECT count(*) FROM agent_keys WHERE domain_id=? AND revoked_at IS NULL", (domain_id,)).fetchone()[0]
            if active >= MAX_ACTIVE_KEYS:
                raise OwnerError("Maximum active agent keys reached", 429)
            conn.execute("INSERT INTO agent_keys(id,domain_id,token_hash,label,created_at) VALUES(?,?,?,?,?)",
                         (kid, domain_id, key_digest(token), label, now))
        return {"id": kid, "label": label, "domain_id": domain_id, "agent_key": token,
                "created_at": now, "notice": "Copy this key now. It will not be shown again."}

    def list_keys(self, owner_id: str, domain_id: str) -> list[dict]:
        with self.owners._db() as conn:
            self._verified_domain(conn, owner_id, domain_id)
            rows = conn.execute("SELECT id,label,created_at,last_used_at FROM agent_keys "
                                "WHERE domain_id=? AND revoked_at IS NULL ORDER BY created_at DESC", (domain_id,)).fetchall()
        return [dict(r) for r in rows]

    def revoke_key(self, owner_id: str, domain_id: str, key_id: str) -> None:
        with self.owners._db(write=True) as conn:
            self._verified_domain(conn, owner_id, domain_id)
            changed = conn.execute("UPDATE agent_keys SET revoked_at=? WHERE id=? AND domain_id=? AND revoked_at IS NULL",
                                   (time.time(), key_id, domain_id))
            if changed.rowcount == 0:
                raise OwnerError("Active key not found", 404)

    def _validate_events(self, events: list[dict[str, Any]], now: float) -> None:
        if not (1 <= len(events) <= MAX_EVENTS_PER_BATCH):
            raise OwnerError("Event batch size not permitted", 422)
        for ev in events:
            if not SOURCE_PATTERN.fullmatch(ev["source_ref"]):
                raise OwnerError("Invalid pseudonymous source reference", 422)
            if ev["method"] not in METHODS or ev["path_group"] not in PATH_GROUPS:
                raise OwnerError("Invalid event category", 422)
            if abs(int(ev["occurred_at"]) - now) > 300:
                raise OwnerError("Event outside allowed 5-minute time window", 422)

    def ingest(self, token: str, domain_id: str, events: list[dict[str, Any]]) -> dict:
        now = time.time()
        self._validate_events(events, now)
        if not token.startswith(KEY_PREFIX) or not 36 <= len(token) <= 100:
            raise OwnerError("Invalid agent credentials", 401)
        accepted = duplicates = 0
        accepted_events: list[dict[str, Any]] = []
        with self.owners._db(write=True) as conn:
            key = conn.execute(
                "SELECT agent_keys.id, agent_keys.domain_id FROM agent_keys "
                "JOIN domains ON domains.id=agent_keys.domain_id "
                "WHERE agent_keys.token_hash=? AND agent_keys.domain_id=? "
                "AND agent_keys.revoked_at IS NULL AND domains.verified_at IS NOT NULL",
                (key_digest(token), domain_id),
            ).fetchone()
            if not key:
                raise OwnerError("Invalid agent credentials or domain", 401)
            conn.execute("DELETE FROM telemetry_events WHERE received_at < ?", (now-RETENTION_SECONDS,))
            sent = conn.execute("SELECT count(*) FROM telemetry_events WHERE domain_id=? AND received_at >= ?",
                                (domain_id, now-60)).fetchone()[0]
            if sent + len(events) > MAX_EVENTS_PER_MINUTE:
                raise OwnerError("Telemetry rate limit reached", 429)
            for ev in events:
                inserted = conn.execute(
                    "INSERT OR IGNORE INTO telemetry_events "
                    "(id,domain_id,agent_event_id,occurred_at,received_at,source_ref,method,path_group,status_code,duration_ms,request_bytes,response_bytes) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (uuid.uuid4().hex, domain_id, ev["event_id"], ev["occurred_at"], now,
                     ev["source_ref"], ev["method"], ev["path_group"], ev["status_code"],
                     ev["duration_ms"], ev["request_bytes"], ev["response_bytes"]),
                )
                if inserted.rowcount:
                    accepted += 1
                    accepted_events.append(ev)
                else:
                    duplicates += 1
            new_alerts = self.detector.process_new_events(conn, domain_id, accepted_events, now)
            conn.execute("UPDATE agent_keys SET last_used_at=? WHERE id=?", (now, key["id"]))
        return {"accepted": accepted, "duplicates": duplicates, "domain_id": domain_id,
                "alerts_updated": new_alerts}

    def recent(self, owner_id: str, domain_id: str, limit: int = 50) -> dict:
        if not 1 <= limit <= 100:
            raise OwnerError("Invalid event limit", 422)
        with self.owners._db() as conn:
            self._verified_domain(conn, owner_id, domain_id)
            rows = conn.execute(
                "SELECT agent_event_id,occurred_at,received_at,source_ref,method,path_group,"
                "status_code,duration_ms,request_bytes,response_bytes "
                "FROM telemetry_events WHERE domain_id=? ORDER BY received_at DESC,id DESC LIMIT ?",
                (domain_id, limit),
            ).fetchall()
            total = conn.execute("SELECT count(*) FROM telemetry_events WHERE domain_id=?", (domain_id,)).fetchone()[0]
        return {"domain_id": domain_id, "total_events": total, "returned": len(rows), "events": [dict(r) for r in rows]}
