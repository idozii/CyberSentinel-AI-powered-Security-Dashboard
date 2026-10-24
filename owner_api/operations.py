"""Private SQLite staging operations - inspect, online backup, restore drill, retention.

This is not PostgreSQL, a production migration system or a disaster recovery SLA.
No account email, token, domain value or request telemetry is written to stdout.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

EVENT_RETENTION = 7 * 86400
ALERT_RETENTION = 7 * 86400
REQUIRED_TABLES = frozenset({"users", "sessions", "domains", "agent_keys", "telemetry_events", "detection_alerts"})


class OperationsError(ValueError):
    pass


def _regular_db(path: Path) -> Path:
    path = Path(path).absolute()
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise OperationsError("Database does not exist") from exc
    if not stat.S_ISREG(info.st_mode):
        raise OperationsError("Database must be a regular file, not a symlink")
    if os.name == "posix" and (info.st_mode & 0o077):
        raise OperationsError("Database must not be readable by group or others (chmod 600)")
    return path


def _open_readonly(path: Path) -> sqlite3.Connection:
    # SQLite URI mode=ro prevents creating a new database on wrong paths.
    return sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=ro", uri=True, timeout=5)


def _integrity(conn: sqlite3.Connection) -> dict:
    if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise OperationsError("SQLite quick_check failed")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise OperationsError("SQLite foreign_key_check failed")
    actual = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = sorted(REQUIRED_TABLES - actual)
    if missing:
        raise OperationsError("Required owner schema missing: " + ", ".join(missing))
    counts = {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in sorted(REQUIRED_TABLES)}
    return {"status": "ok", "schema_checked": sorted(REQUIRED_TABLES), "counts": counts}


def inspect(path: Path) -> dict:
    source = _regular_db(path)
    with _open_readonly(source) as conn:
        return _integrity(conn)


def _safe_backup_dir(path: Path) -> Path:
    root = Path(path).absolute()
    if root.is_symlink():
        raise OperationsError("Backup directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise OperationsError("Backup destination must be a directory")
    if os.name == "posix":
        mode = root.stat().st_mode & 0o777
        if mode & 0o077:
            raise OperationsError("Backup directory must have private permissions (chmod 700)")
    return root


def backup(path: Path, dest_root: Path) -> dict:
    source = _regular_db(path)
    directory = _safe_backup_dir(dest_root)
    if source.parent == directory:
        raise OperationsError("Keep backups in a separate directory from the live database")
    filename = f"owner-backup-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(5)}.sqlite3"
    target = directory / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(target, flags, 0o600)
        os.close(handle)
        with _open_readonly(source) as source_db, sqlite3.connect(target, timeout=5) as target_db:
            source_db.backup(target_db, pages=100, sleep=0.05)
        if os.name == "posix":
            target.chmod(0o600)
        summary = inspect(target)
        with target.open("rb") as handle:
            sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"status": "created", "backup_path": str(target), "bytes": target.stat().st_size,
            "sha256": sha256, "table_counts": summary["counts"],
            "warning": "Sensitive backup. Encrypt it before off-host transfer and test restores separately."}


def verify_restore(path: Path) -> dict:
    original = _regular_db(path)
    # Restore into a disposable DB; never overwrite an operator's live database.
    with tempfile.TemporaryDirectory(prefix="cs-restore-drill-") as tmp:
        target = Path(tmp) / "restored.sqlite3"
        with _open_readonly(original) as source, sqlite3.connect(target) as dest:
            source.backup(dest)
        target.chmod(0o600)
        report = inspect(target)
    return {"status": "restore_verified", "table_counts": report["counts"],
            "notice": "Test restore only. No live database was modified."}


def retention(path: Path, *, apply: bool = False, now: float | None = None) -> dict:
    dbpath = _regular_db(path)
    clock = time.time() if now is None else float(now)
    if not (1_600_000_000 < clock < 4_000_000_000):
        raise OperationsError("Invalid maintenance clock")
    with sqlite3.connect(dbpath, timeout=10) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
        _integrity(conn)
        filters = {
            "expired_sessions": ("sessions", "expires_at < ?", (clock,)),
            "old_events": ("telemetry_events", "received_at < ?", (clock - EVENT_RETENTION,)),
            "old_alerts": ("detection_alerts", "window_start < ?", (int(clock - ALERT_RETENTION),)),
            "expired_pending_challenges": ("domains", "verified_at IS NULL AND challenge_expires_at IS NOT NULL AND challenge_expires_at < ?", (clock,)),
        }
        counts = {label: int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition}", args).fetchone()[0])
                  for label, (table, condition, args) in filters.items()}
        if apply:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (clock,))
            conn.execute("DELETE FROM telemetry_events WHERE received_at < ?", (clock - EVENT_RETENTION,))
            conn.execute("DELETE FROM detection_alerts WHERE window_start < ?", (int(clock - ALERT_RETENTION),))
            conn.execute("UPDATE domains SET challenge_hash=NULL,challenge_expires_at=NULL WHERE verified_at IS NULL AND challenge_expires_at IS NOT NULL AND challenge_expires_at < ?", (clock,))
            conn.commit()
        else:
            conn.rollback()
    return {"status": "applied" if apply else "dry_run", "eligible": counts,
            "note": "Credentials and verified domains are never deleted by retention."}
