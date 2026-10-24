"""Owner-scoped, explainable event-window rules for the local monitoring lab.

Alerts are advisories about telemetry patterns, not evidence of hostile intent.
No experiment run IDs, raw IPs, request URLs or serialized ML models are used.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from typing import Any

from owner_api.store import OwnerError, OwnerStore

WINDOW_SECONDS = 60
ALERT_RETENTION_SECONDS = 7 * 86400
# (rule_id, threshold, category, severity, explanation)
RULES = (
    ("repeated_login_failures", 5, "failed_logins", "high",
     "Five or more HTTP 401 responses on the login path group in one 60-second window."),
    ("http_404_burst", 8, "http_404", "medium",
     "Eight or more HTTP 404 responses in one 60-second window. Could be normal missing URLs."),
    ("server_error_burst", 5, "http_5xx", "medium",
     "Five or more HTTP 5xx responses in one 60-second window."),
    ("request_volume_spike", 40, "requests", "low",
     "Forty or more requests from the same pseudonymous source in 60 seconds."),
)


class DetectionStore:
    def __init__(self, owners: OwnerStore):
        self.owners = owners
        with self.owners._db(write=True) as conn:
            conn.executescript("""
                CREATE INDEX IF NOT EXISTS idx_events_detection
                    ON telemetry_events(domain_id, source_ref, occurred_at);
                CREATE TABLE IF NOT EXISTS detection_alerts (
                    id TEXT PRIMARY KEY,
                    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    source_ref TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    observed_count INTEGER NOT NULL,
                    threshold_count INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open','acknowledged')),
                    first_detected_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    acknowledged_at REAL,
                    UNIQUE(domain_id, source_ref, window_start, rule_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_domain_updated
                    ON detection_alerts(domain_id, updated_at DESC);
            """)

    @staticmethod
    def _totals(conn: sqlite3.Connection, domain_id: str, source_ref: str, start: int) -> dict[str, int]:
        row = conn.execute("""
            SELECT COUNT(*) AS requests,
                   COALESCE(SUM(CASE WHEN path_group='login' AND status_code=401 THEN 1 ELSE 0 END),0) AS failed_logins,
                   COALESCE(SUM(CASE WHEN status_code=404 THEN 1 ELSE 0 END),0) AS http_404,
                   COALESCE(SUM(CASE WHEN status_code BETWEEN 500 AND 599 THEN 1 ELSE 0 END),0) AS http_5xx
            FROM telemetry_events
            WHERE domain_id=? AND source_ref=? AND occurred_at >= ? AND occurred_at < ?
        """, (domain_id, source_ref, start, start + WINDOW_SECONDS)).fetchone()
        return {name: int(row[name]) for name in ("requests", "failed_logins", "http_404", "http_5xx")}

    def process_new_events(self, conn: sqlite3.Connection, domain_id: str,
                           accepted_events: list[dict[str, Any]], now: float) -> int:
        """Called inside the same ingestion transaction. No additional commit."""
        if not accepted_events:
            return 0
        windows = {(str(e["source_ref"]), (int(e["occurred_at"]) // WINDOW_SECONDS) * WINDOW_SECONDS)
                   for e in accepted_events}
        inserted = 0
        for source, start in sorted(windows):
            totals = self._totals(conn, domain_id, source, start)
            for rule_id, threshold, counter, severity, explanation in RULES:
                count = totals[counter]
                if count < threshold:
                    continue
                title = {
                    "repeated_login_failures": "Repeated login failures",
                    "http_404_burst": "HTTP 404 response burst",
                    "server_error_burst": "HTTP 5xx error burst",
                    "request_volume_spike": "High request volume",
                }[rule_id]
                changed = conn.execute("""
                    INSERT INTO detection_alerts
                        (id,domain_id,source_ref,window_start,rule_id,severity,title,explanation,
                         observed_count,threshold_count,status,first_detected_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,'open',?,?)
                    ON CONFLICT(domain_id,source_ref,window_start,rule_id)
                    DO UPDATE SET observed_count=excluded.observed_count,updated_at=excluded.updated_at
                    WHERE excluded.observed_count > detection_alerts.observed_count
                """, (uuid.uuid4().hex, domain_id, source, start, rule_id, severity,
                      title, explanation, count, threshold, now, now))
                inserted += int(changed.rowcount > 0)
        # Cleanup by window time, retaining valid recent acknowledgements.
        conn.execute("DELETE FROM detection_alerts WHERE window_start < ?", (int(now) - ALERT_RETENTION_SECONDS,))
        return inserted

    def list_alerts(self, owner_id: str, domain_id: str, *, limit: int = 50,
                    status: str | None = None) -> dict[str, Any]:
        if not 1 <= limit <= 100:
            raise OwnerError("Alert limit must be 1..100", 422)
        if status not in (None, "open", "acknowledged"):
            raise OwnerError("Unsupported alert status", 422)
        with self.owners._db() as conn:
            # Defense against cross-tenant access, even if an alert ID is guessed.
            self._verified_domain(conn, owner_id, domain_id)
            filters = "AND status=?" if status else ""
            params: tuple = (domain_id, status) if status else (domain_id,)
            row_count = conn.execute("SELECT COUNT(*) FROM detection_alerts WHERE domain_id=? " + filters,
                                     params).fetchone()[0]
            rows = conn.execute("SELECT id,rule_id,severity,title,explanation,source_ref,window_start,"
                                "observed_count,threshold_count,status,first_detected_at,updated_at,acknowledged_at "
                                "FROM detection_alerts WHERE domain_id=? " + filters +
                                " ORDER BY window_start DESC, first_detected_at DESC,id DESC LIMIT ?",
                                (*params, limit)).fetchall()
        return {"domain_id": domain_id, "total_alerts": int(row_count),
                "returned": len(rows), "alerts": [dict(r) for r in rows]}

    def acknowledge(self, owner_id: str, domain_id: str, alert_id: str) -> dict[str, Any]:
        if len(alert_id) != 32 or any(ch not in "0123456789abcdef" for ch in alert_id):
            raise OwnerError("Alert not found", 404)
        with self.owners._db(write=True) as conn:
            self._verified_domain(conn, owner_id, domain_id)
            existing = conn.execute("SELECT status FROM detection_alerts WHERE id=? AND domain_id=?",
                                    (alert_id, domain_id)).fetchone()
            if existing is None:
                raise OwnerError("Alert not found", 404)
            if existing["status"] == "open":
                conn.execute("UPDATE detection_alerts SET status='acknowledged',acknowledged_at=? "
                             "WHERE id=? AND domain_id=?", (time.time(), alert_id, domain_id))
            row = conn.execute("SELECT id,domain_id,status,acknowledged_at FROM detection_alerts "
                               "WHERE id=? AND domain_id=?", (alert_id, domain_id)).fetchone()
        return dict(row)

    @staticmethod
    def _verified_domain(conn: sqlite3.Connection, owner_id: str, domain_id: str):
        row = conn.execute("SELECT id FROM domains WHERE id=? AND user_id=? AND verified_at IS NOT NULL",
                           (domain_id, owner_id)).fetchone()
        if not row:
            raise OwnerError("Verified domain not found", 404)
        return row
