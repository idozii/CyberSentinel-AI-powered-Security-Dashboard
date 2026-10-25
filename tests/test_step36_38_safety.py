"""Offline, no-network recovery and privacy regression for Steps 36-38."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.continuous import Outbox
from cybersentinel_agent.state_cli import inspect_state
from scripts.step37_ops_report import report
from scripts.step38_outbox_recovery import backup_state, restore_state
from scripts.step36_38_release import rehearse


class LocalRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.state = self.private / 'active.sqlite3'
        db = Outbox(self.state)
        db.bind('a' * 32, 'csd_fake_test_only_token', '/tmp/demo-only-nginx.jsonl')
        self.ev = {'event_id': 'a' * 32, 'occurred_at': int(time.time()),
                   'source_ref': 'b' * 32, 'method': 'GET', 'path_group': 'login',
                   'status_code': 401, 'duration_ms': 1.0, 'request_bytes': 10,
                   'response_bytes': 2}
        db.save_line('/tmp/demo-only-nginx.jsonl', 2, 3, 127, self.ev)

    def test_snapshot_restore_and_binding_cursors(self):
        backup = self.private / 'saved.sqlite3'
        recovered = self.private / 'restored.sqlite3'
        b = backup_state(self.state, backup)
        self.assertEqual(b['pending_events'], 1)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        r = restore_state(backup, recovered, confirm=True)
        self.assertEqual(r['pending_events'], 1)
        self.assertEqual(recovered.stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(recovered) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT offset FROM cursors').fetchone()[0], 127)
        self.assertEqual(inspect_state(recovered)['status'], 'pending')
        self.assertNotIn('csd_fake_test_only_token', json.dumps(b))
        self.assertNotIn('/tmp/demo-only-nginx.jsonl', json.dumps(r))

    def test_no_overwrite_and_confirmation(self):
        backup = self.private / 'saved.sqlite3'
        backup_state(self.state, backup)
        with self.assertRaises(AgentError):
            backup_state(self.state, backup)
        with self.assertRaises(AgentError):
            restore_state(backup, self.private / 'new.sqlite3')
        with self.assertRaises(AgentError):
            restore_state(backup, self.state, confirm=True)
        self.assertEqual(inspect_state(self.state)['pending_events'], 1)

    def test_refuse_symlink_insecure_folder_and_bad_db(self):
        linked = self.private / 'link.sqlite3'
        linked.symlink_to(self.state)
        with self.assertRaises(AgentError):
            backup_state(linked, self.private / 'not-created.sqlite3')
        insecure = self.root / 'world-readable'
        insecure.mkdir(mode=0o755)
        with self.assertRaises(AgentError):
            backup_state(self.state, insecure / 'unsafe.sqlite3')
        bad = self.private / 'corrupt.sqlite3'
        bad.write_bytes(b'not-an-sqlite-db')
        bad.chmod(0o600)
        with self.assertRaises(AgentError):
            restore_state(bad, self.private / 'restored.sqlite3', confirm=True)

    def test_operational_report_redacted_and_stale_warns(self):
        initial = report(state=self.state)
        self.assertEqual(initial['status'], 'pass')
        self.assertEqual(initial['beta_gate'], 'blocked')
        self.assertEqual(initial['outbox']['pending_events'], 1)
        self.assertNotIn(str(self.state), json.dumps(initial))
        self.assertNotIn('csd_fake_test_only_token', json.dumps(initial))
        with sqlite3.connect(self.state) as db:
            db.execute('UPDATE queue SET occurred_at=?', (int(time.time()) - 900,))
        old = report(state=self.state)
        self.assertEqual(old['status'], 'attention')
        self.assertTrue(old['outbox']['near_or_past_freshness_limit'])
        self.assertEqual(inspect_state(self.state)['pending_events'], 1)

    def test_rehearsal_still_blocks_beta(self):
        result = rehearse()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['beta_gate'], 'blocked')
        self.assertTrue(all(result['checks'].values()))


if __name__ == '__main__':
    unittest.main()
