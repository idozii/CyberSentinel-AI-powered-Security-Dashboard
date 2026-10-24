"""Step 15 - private staging operations; no VPS, DNS or external traffic."""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from owner_api.operations import OperationsError, backup, inspect, retention, verify_restore
from owner_api.store import OwnerStore
from owner_api.telemetry import TelemetryStore
from scripts.step15_ops import main as ops_main
from scripts.step15_preflight import audit as preflight


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "private" / "owner.sqlite3"
        self.owner = OwnerStore(self.db)
        self.events = TelemetryStore(self.owner)
        self.uid = self.owner.register("hidden-owner@example.com", "strong-secret-password-123")["id"]
        domain = self.owner.create_domain(self.uid, "owned-site.org")
        self.did = domain["id"]
        with self.owner._db(write=True) as con:
            con.execute("UPDATE domains SET verified_at=? WHERE id=?", (time.time(), self.did))
        self.key = self.events.issue_key(self.uid, self.did, "private-agent")["agent_key"]

    def sample(self, idx=0, *, stamp=None):
        return {"event_id": f"cs{idx:030d}", "occurred_at": int(time.time()) if stamp is None else stamp,
                "source_ref": "a" * 32, "method": "POST", "path_group": "login",
                "status_code": 401, "duration_ms": 8.0, "request_bytes": 100, "response_bytes": 250}

    def add_events(self, n=5):
        self.assertEqual(self.events.ingest(self.key, self.did, [self.sample(i) for i in range(n)])["accepted"], n)

    def test_inspect_schema_and_counts(self):
        x = inspect(self.db)
        self.assertEqual(x["status"], "ok")
        self.assertEqual(x["counts"]["users"], 1)
        self.assertEqual(x["counts"]["domains"], 1)
        self.assertEqual(len(x["schema_checked"]), 6)

    def test_online_backup_is_consistent_and_restore_verified(self):
        self.add_events()
        result = backup(self.db, self.root / "backups")
        self.assertEqual(result["status"], "created")
        copied = Path(result["backup_path"])
        self.assertTrue(copied.is_file())
        self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
        self.assertEqual(copied.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(result["table_counts"]["telemetry_events"], 5)
        self.assertEqual(result["table_counts"]["detection_alerts"], 1)
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(verify_restore(copied)["table_counts"]["telemetry_events"], 5)

    def test_online_snapshot_not_changed_by_following_writes(self):
        first = backup(self.db, self.root / "backups")
        self.add_events()
        self.assertEqual(inspect(Path(first["backup_path"]))["counts"]["telemetry_events"], 0)
        self.assertEqual(inspect(self.db)["counts"]["telemetry_events"], 5)

    def test_report_does_not_output_email_password_or_key(self):
        x = backup(self.db, self.root / "backups")
        blob = json.dumps(x)
        for secret in ("hidden-owner@example.com", "strong-secret-password-123", self.key):
            self.assertNotIn(secret, blob)

    def test_missing_and_symlink_database_rejected(self):
        with self.assertRaises(OperationsError):
            inspect(self.root / "missing.sqlite3")
        link = self.root / "linked.sqlite3"
        link.symlink_to(self.db)
        with self.assertRaisesRegex(OperationsError, "symlink"):
            inspect(link)

    def test_rejects_insecure_db_permissions(self):
        if os.name != "posix":
            self.skipTest("POSIX permission check")
        self.db.chmod(0o644)
        with self.assertRaisesRegex(OperationsError, "chmod 600"):
            inspect(self.db)
        self.db.chmod(0o600)

    def test_rejects_symlink_backup_dir(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(real)
        with self.assertRaisesRegex(OperationsError, "symlink"):
            backup(self.db, alias)

    def test_rejects_world_readable_backup_directory(self):
        if os.name != "posix":
            self.skipTest("POSIX permission check")
        dest = self.root / "public"
        dest.mkdir(mode=0o755)
        with self.assertRaisesRegex(OperationsError, "chmod 700"):
            backup(self.db, dest)

    def test_backup_cannot_be_in_source_directory(self):
        with self.assertRaisesRegex(OperationsError, "separate directory"):
            backup(self.db, self.db.parent)

    def test_bad_restore_input_cannot_overwrite_live_db(self):
        invalid = self.root / "bad.sqlite3"
        invalid.write_bytes(b"not a database")
        invalid.chmod(0o600)
        before = self.db.read_bytes()
        with self.assertRaises(sqlite3.DatabaseError):
            verify_restore(invalid)
        self.assertEqual(self.db.read_bytes(), before)

    def test_retention_defaults_to_dry_run(self):
        old = time.time() - (8 * 86400)
        self.add_events()
        with self.owner._db(write=True) as con:
            con.execute("UPDATE telemetry_events SET received_at=?", (old,))
        result = retention(self.db)
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(result["eligible"]["old_events"], 5)
        self.assertEqual(inspect(self.db)["counts"]["telemetry_events"], 5)

    def test_retention_purges_aged_events_alerts_sessions_and_challenges(self):
        self.add_events()
        old = time.time() - 9 * 86400
        new_challenge = self.owner.create_domain(self.uid, "pending-domain.net")
        token = self.owner.login("hidden-owner@example.com", "strong-secret-password-123")["access_token"]
        self.assertTrue(token)
        with self.owner._db(write=True) as con:
            con.execute("UPDATE sessions SET expires_at=?", (old,))
            con.execute("UPDATE telemetry_events SET received_at=?", (old,))
            con.execute("UPDATE detection_alerts SET window_start=?", (int(old),))
            con.execute("UPDATE domains SET challenge_expires_at=? WHERE id=?", (old, new_challenge["id"]))
        report = retention(self.db, apply=True)
        self.assertEqual(report["status"], "applied")
        self.assertEqual(report["eligible"]["old_events"], 5)
        self.assertEqual(report["eligible"]["old_alerts"], 1)
        self.assertEqual(report["eligible"]["expired_sessions"], 1)
        self.assertEqual(report["eligible"]["expired_pending_challenges"], 1)
        after = inspect(self.db)["counts"]
        self.assertEqual(after["telemetry_events"], 0)
        self.assertEqual(after["detection_alerts"], 0)
        self.assertEqual(after["sessions"], 0)
        self.assertEqual(after["users"], 1)
        self.assertEqual(after["domains"], 2)
        with self.owner._db() as con:
            self.assertIsNone(con.execute("SELECT challenge_hash FROM domains WHERE id=?", (new_challenge["id"],)).fetchone()[0])
            self.assertIsNotNone(con.execute("SELECT verified_at FROM domains WHERE id=?", (self.did,)).fetchone()[0])

    def test_recent_events_and_alerts_are_retained(self):
        self.add_events()
        x = retention(self.db, apply=True)
        self.assertEqual(x["eligible"]["old_events"], 0)
        self.assertEqual(inspect(self.db)["counts"]["detection_alerts"], 1)

    def test_invalid_clock_fails_closed(self):
        for value in (0, 1e12):
            with self.assertRaisesRegex(OperationsError, "clock"):
                retention(self.db, apply=True, now=value)

    def test_cli_inspect_and_missing_backup_does_not_delete(self):
        self.assertEqual(ops_main(["inspect", "--db", str(self.db)]), 0)
        self.assertEqual(ops_main(["restore-check", "--backup-file", str(self.root / "missing")]), 2)
        self.assertEqual(inspect(self.db)["counts"]["users"], 1)

    def test_static_staging_preflight(self):
        repo = Path(__file__).resolve().parents[1]
        report = preflight(repo)
        self.assertEqual(report["status"], "pass", report)
        self.assertTrue(all(report["checks"].values()))

    def test_static_preflight_rejects_portal_bound_to_public_interface(self):
        repo = Path(__file__).resolve().parents[1]
        fixture = self.root / "config"
        for relative in ("deploy/cybersentinel-portal.service.example", "deploy/cybersentinel-backup.service.example",
                         "deploy/cybersentinel-backup.timer.example", "deploy/cybersentinel-retention.service.example",
                         "deploy/cybersentinel-retention.timer.example", "deploy/Caddyfile.ingest.example",
                         "deploy/cybersentinel-owner.service.example", "owner_api/operations.py", "scripts/step15_ops.py",
                         "scripts/step14_preflight.py"):
            src = repo / relative
            tgt = fixture / relative
            tgt.parent.mkdir(parents=True, exist_ok=True)
            tgt.write_bytes(src.read_bytes())
        portal = fixture / "deploy/cybersentinel-portal.service.example"
        portal.write_text(portal.read_text().replace("--server.address 127.0.0.1", "--server.address 0.0.0.0"))
        result = preflight(fixture)
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["checks"]["private_portal"])


if __name__ == "__main__":
    unittest.main()
