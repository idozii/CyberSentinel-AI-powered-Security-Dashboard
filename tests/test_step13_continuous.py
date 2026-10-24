"""Step 13 - durable delivery, rotation and failure mode regression tests."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.continuous import MAX_QUEUE, ContinuousAgent, Outbox
from cybersentinel_agent.watch_cli import single_instance, main as watch_main

DOMAIN = "a" * 32
KEY = "csa_" + "k" * 43


def event(number: int, code=401, ip="198.51.100.12") -> bytes:
    row = {
        "time_iso8601": datetime.now(timezone.utc).isoformat(),
        "remote_addr": ip, "request_method": "POST", "uri": "/login?password=private",
        "request_id": "demo" + f"{number:025d}", "status": str(code),
        "request_time": "0.015", "request_length": "140", "bytes_sent": "225",
        "http_cookie": "dont-store-this", "user_agent": "dont-store-this-either"
    }
    return (json.dumps(row, separators=(",", ":")) + "\n").encode()


class LocalServer:
    def __init__(self):
        self.delivered = set()
        self.calls = 0
        self.failures = 0
        self.fail_status = None

    def __call__(self, server, domain, events, key):
        assert server == "http://127.0.0.1:8002"
        assert domain == DOMAIN
        assert key == KEY
        self.calls += 1
        if self.failures:
            self.failures -= 1
            raise AgentError("Cannot deliver batch to local owner API")
        if self.fail_status:
            raise AgentError(f"Local ingest rejected request (HTTP {self.fail_status})")
        accepted = duplicates = 0
        for row in events:
            if row["event_id"] in self.delivered:
                duplicates += 1
            else:
                self.delivered.add(row["event_id"])
                accepted += 1
        return {"accepted": accepted, "duplicates": duplicates, "alerts_updated": 0}


class ContinuousAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "access.log"
        self.state = self.root / "private" / "state.sqlite3"
        self.srv = LocalServer()
        self.agents = []

    def make_agent(self, **kwargs):
        a = ContinuousAgent(self.log, self.state, DOMAIN, KEY, sender=self.srv, **kwargs)
        self.agents.append(a)
        self.addCleanup(a.close)
        return a

    def append(self, *nums):
        with self.log.open("ab") as f:
            for i in nums:
                f.write(event(i))

    def test_initial_default_skips_existing_log_and_follows_new_lines(self):
        self.append(1)
        a = self.make_agent()
        self.assertEqual(a.step()["queued"], 0)
        self.append(2)
        self.assertEqual(a.step()["accepted_total"], 1)
        self.assertEqual(len(self.srv.delivered), 1)

    def test_from_start_reads_and_sends_sanitized_data(self):
        self.append(1, 2)
        a = self.make_agent(from_start=True)
        r = a.step()
        self.assertEqual(r["accepted_total"], 2)
        self.assertEqual(a.store.size(), 0)
        self.assertEqual(r["read_lines"], 2)
        self.assertNotIn("private", self.state.read_bytes().decode("latin1", errors="ignore"))
        self.assertNotIn("dont-store", self.state.read_bytes().decode("latin1", errors="ignore"))
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.parent.stat().st_mode & 0o777, 0o700)

    def test_partial_line_not_consumed_until_newline(self):
        data = event(1)
        self.log.write_bytes(data[:-1])
        a = self.make_agent(from_start=True)
        self.assertEqual(a.step()["read_lines"], 0)
        self.assertIsNone(a.store.cursor(str(self.log)))
        with self.log.open("ab") as f:
            f.write(b"\n")
        self.assertEqual(a.step()["accepted_total"], 1)

    def test_network_failure_persists_pending_and_restart_replays(self):
        self.append(1, 2)
        self.srv.failures = 1
        a = self.make_agent(from_start=True)
        r = a.step()
        self.assertEqual(r["queued"], 2)
        a.close()
        b = self.make_agent()
        self.assertEqual(b.flush()["accepted"], 2)
        self.assertEqual(b.step()["read_lines"], 0)
        self.assertEqual(b.store.size(), 0)

    def test_server_receipt_then_crash_causes_idempotent_replay(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        self.assertEqual(a.poll(), 1)
        original = a.store.confirm
        def crash(_):
            raise RuntimeError("simulated power loss after server receipt")
        a.store.confirm = crash
        with self.assertRaisesRegex(RuntimeError, "power loss"):
            a.flush()
        a.store.confirm = original
        b = self.make_agent()
        self.assertEqual(b.flush()["duplicates"], 1)
        self.assertEqual(len(self.srv.delivered), 1)

    def test_renamed_rotation_drains_old_then_new(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        self.assertEqual(a.step()["accepted_total"], 1)
        self.log.rename(self.root / "access.log.1")
        # Append to the old descriptor before new file is created.
        with (self.root / "access.log.1").open("ab") as f:
            f.write(event(2))
        self.append(3)
        self.assertEqual(a.step()["accepted_total"], 3)
        self.assertEqual(len(self.srv.delivered), 3)

    def test_restart_recovers_rotated_inode(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        self.assertEqual(a.step()["accepted_total"], 1)
        a.close()
        self.log.rename(self.root / "access.log.1")
        with (self.root / "access.log.1").open("ab") as f:
            f.write(event(2))
        self.append(3)
        b = self.make_agent()
        self.assertEqual(b.step()["accepted_total"], 2)
        self.assertFalse(b.warn_unrecoverable_rotation)

    def test_missing_rotated_file_warns_instead_of_false_success(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        a.step(); a.close()
        discarded = self.root / "discarded.log"
        self.log.rename(discarded)
        self.append(2)
        discarded.unlink()
        b = self.make_agent()
        r = b.step()
        self.assertTrue(r["rotation_recovery_warning"])
        self.assertEqual(r["accepted_total"], 1)

    def test_copytruncate_detects_shrinking_file(self):
        self.append(1, 2, 3)
        a = self.make_agent(from_start=True)
        self.assertEqual(a.step()["accepted_total"], 3)
        # A much shorter log file with the same inode.
        self.log.write_bytes(event(4))
        self.assertEqual(a.step()["accepted_total"], 4)

    def test_outbox_backpressure_stops_cursor(self):
        self.append(1, 2, 3)
        a = self.make_agent(from_start=True)
        with patch("cybersentinel_agent.continuous.MAX_QUEUE", 2):
            self.assertEqual(a.poll(), 2)
            self.assertEqual(a.poll(), 0)
        self.assertEqual(a.store.size(), 2)
        self.assertEqual(a.flush()["accepted"], 2)
        self.assertEqual(a.step()["accepted_total"], 3)

    def test_invalid_json_keeps_offset_and_has_no_raw_storage(self):
        self.log.write_bytes(b'{not valid}\n')
        a = self.make_agent(from_start=True)
        with self.assertRaisesRegex(AgentError, "Invalid JSON"):
            a.step()
        self.assertIsNone(a.store.cursor(str(self.log)))
        self.assertNotIn("not valid", self.state.read_bytes().decode("latin1", errors="ignore"))

    def test_overlong_line_rejected(self):
        self.log.write_bytes(b"a" * 8193 + b"\n")
        a = self.make_agent(from_start=True)
        with self.assertRaisesRegex(AgentError, "8 KB"):
            a.step()

    def test_transient_retry_and_backoff(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        a.poll()
        self.srv.fail_status = 429
        first = a.flush()
        self.assertEqual(first["state"], "retry")
        self.assertEqual(a.flush()["state"], "backoff")
        self.srv.fail_status = None
        a.retry_after = 0.0
        self.assertEqual(a.flush()["accepted"], 1)
        self.assertEqual(a.store.size(), 0)

    def test_permanent_http_error_keeps_outbox(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        a.poll()
        self.srv.fail_status = 401
        with self.assertRaisesRegex(AgentError, "Permanent ingest"):
            a.flush()
        self.assertEqual(a.store.size(), 1)

    def test_incorrect_server_receipt_cannot_delete_outbox(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        a.poll()
        a.sender = lambda *args: {"accepted": 0, "duplicates": 0}
        with self.assertRaisesRegex(AgentError, "Unexpected server receipt"):
            a.flush()
        self.assertEqual(a.store.size(), 1)

    def test_expired_queue_requires_explicit_confirmation(self):
        self.append(1)
        a = self.make_agent(from_start=True)
        a.poll()
        a.clock = lambda: time.time() + 1000
        with self.assertRaisesRegex(AgentError, "freshness limit"):
            a.flush()
        with self.assertRaisesRegex(AgentError, "confirm-loss"):
            a.store.purge_expired()
        self.assertEqual(a.store.purge_expired(confirm_loss=True, clock=a.clock), 1)

    def test_binding_rejects_change_of_domain_key_or_log(self):
        self.make_agent()
        with self.assertRaisesRegex(AgentError, "different domain"):
            ContinuousAgent(self.log, self.state, "b" * 32, KEY)
        with self.assertRaisesRegex(AgentError, "different domain"):
            ContinuousAgent(self.log, self.state, DOMAIN, "csa_" + "z" * 43)
        with self.assertRaisesRegex(AgentError, "different domain"):
            ContinuousAgent(self.root / "other.log", self.state, DOMAIN, KEY)

    def test_rejects_symlinked_input_and_state(self):
        actual = self.root / "actual.log"
        actual.write_bytes(event(1))
        self.log.symlink_to(actual)
        with self.assertRaisesRegex(AgentError, "symlinked NGINX"):
            self.make_agent()
        self.log.unlink()
        target = self.root / "db.sqlite3"
        target.touch()
        self.state.parent.mkdir(exist_ok=True)
        self.state.symlink_to(target)
        with self.assertRaisesRegex(AgentError, "symlink"):
            self.make_agent()

    def test_incorrect_network_origin_rejected(self):
        with self.assertRaises(AgentError):
            self.make_agent(server="https://example.com")

    def test_lock_prevents_two_watchers(self):
        with single_instance(self.state):
            with self.assertRaisesRegex(AgentError, "Another agent"):
                with single_instance(self.state):
                    pass

    def test_cli_rejects_absent_agent_key(self):
        self.log.write_bytes(event(1))
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit) as ctx:
            watch_main(["--input", str(self.log), "--domain-id", DOMAIN, "--iterations", "1"])
        self.assertEqual(ctx.exception.code, 2)

    def test_saved_log_cursor_and_queue_same_transaction_on_bad_row(self):
        self.log.write_bytes(event(1) + b'{bad-json}\n')
        a = self.make_agent(from_start=True)
        with self.assertRaises(AgentError):
            a.poll()
        saved = a.store.cursor(str(self.log))
        self.assertGreater(saved[2], 0)
        self.assertEqual(a.store.size(), 1)
        a.close()
        b = self.make_agent()
        with self.assertRaises(AgentError):
            b.poll()
        self.assertEqual(b.flush()["accepted"], 1)


if __name__ == "__main__":
    unittest.main()
