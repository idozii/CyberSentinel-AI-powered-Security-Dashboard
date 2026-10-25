"""Steps 33-35: real DemoStore delivery through existing durable SQLite outbox.

All traffic is in-process FastAPI TestClient. No Neon, sockets or public Internet.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.continuous import ContinuousAgent, validate_watcher_identity
from cybersentinel_agent.state_cli import inspect_state, main as state_main
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step19_generate_logs import generate


class DurableDemoDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.log = self.base/'access.jsonl'
        self.state = self.base/'private'/'agent.sqlite3'
        self.db = DemoStore()
        self.key = self.db.issue_key()
        self.did = self.db.domain_id.hex
        self.http = TestClient(create_demo_app(self.db, enabled=True))
        self.addCleanup(self.http.close)
        self.agents = []

    def make_agent(self, sender, **kwargs):
        agent = ContinuousAgent(self.log, self.state, self.did, self.key,
                                server='http://127.0.0.1:8019', sender=sender, **kwargs)
        self.agents.append(agent)
        self.addCleanup(agent.close)
        return agent

    def sender(self, server, domain, events, key):
        self.assertEqual(server, 'http://127.0.0.1:8019')
        resp = self.http.post('/agent/v1/ingest', json={'domain_id':domain, 'events':events},
                              headers={'Authorization': 'Bearer ' + key})
        if resp.status_code != 200:
            raise AgentError(f'Ingest HTTP {resp.status_code}')
        return resp.json()

    def put_login_events(self):
        self.log.write_text(''.join(json.dumps(row) + '\n' for row in generate('login')))

    def test_local_demo_key_routes_to_only_local_demo(self):
        validate_watcher_identity('http://127.0.0.1:8019', self.key)
        with self.assertRaises(AgentError):
            validate_watcher_identity('http://127.0.0.1:8008', self.key)
        with self.assertRaises(AgentError):
            validate_watcher_identity('https://collector.example.org', self.key)
        with self.assertRaises(AgentError):
            validate_watcher_identity('http://127.0.0.1:8019', 'csa_'+'x'*43)

    def test_staging_requires_structural_csp_key(self):
        key = 'csp_' + uuid.uuid4().hex + '_' + 'X'*43
        validate_watcher_identity('http://127.0.0.1:8008', key)
        validate_watcher_identity('https://collector.valid-domain.org', key)
        with self.assertRaises(AgentError):
            validate_watcher_identity('http://127.0.0.1:8019', key)
        with self.assertRaises(AgentError):
            validate_watcher_identity('http://127.0.0.1:8008', 'csp_fake')
        # Existing Step 14 remote HTTPS bridge still accepts a legacy owner key.
        validate_watcher_identity('https://collector.valid-domain.org', 'csa_' + 'k'*43)

    def test_loss_of_ack_restart_and_dedup(self):
        self.put_login_events()
        lost_ack = {'once': True}
        def sender(server, domain, events, key):
            result = self.sender(server, domain, events, key)
            if lost_ack['once']:
                lost_ack['once'] = False
                raise AgentError('Connection dropped after server receipt')
            return result
        a = self.make_agent(sender, from_start=True)
        result = a.step()
        self.assertEqual(result['queued'], 5)
        self.assertEqual(self.db.snapshot()['total_events'], 5)
        self.assertEqual(self.db.snapshot()['total_alerts'], 1)
        self.assertEqual(inspect_state(self.state)['pending_events'], 5)
        a.close()
        b = self.make_agent(self.sender)
        flushed = b.flush()
        self.assertEqual(flushed['duplicates'], 5)
        self.assertEqual(b.store.size(), 0)
        self.assertEqual(inspect_state(self.state)['status'], 'empty')
        self.assertEqual(self.db.snapshot()['total_events'], 5)
        self.assertEqual(self.db.snapshot()['total_alerts'], 1)
        self.assertEqual(b.poll(), 0)

    def test_offline_preserves_queue_and_cursor(self):
        self.put_login_events()
        def outage(*args):
            raise AgentError('Offline - unable to connect')
        a = self.make_agent(outage, from_start=True)
        r = a.step()
        self.assertEqual(r['delivery']['state'], 'retry')
        self.assertEqual(r['queued'], 5)
        a.close()
        b = self.make_agent(self.sender)
        self.assertEqual(b.flush()['accepted'], 5)
        self.assertEqual(b.poll(), 0)

    def test_state_inspection_is_read_only_and_redacted(self):
        self.put_login_events()
        a = self.make_agent(lambda *args: (_ for _ in ()).throw(AgentError('offline')), from_start=True)
        a.poll()
        before = self.state.read_bytes()
        info = inspect_state(self.state)
        self.assertEqual(info['status'], 'pending')
        self.assertEqual(info['pending_events'], 5)
        self.assertTrue(info['state_bound'])
        serialized = json.dumps(info)
        for secret in (self.key, self.did, '198.51.100', str(self.log)):
            self.assertNotIn(secret, serialized)
        self.assertEqual(before, self.state.read_bytes())

    def test_state_inspection_rejects_symlink_and_world_readable(self):
        self.put_login_events()
        a = self.make_agent(self.sender)
        link = self.base/'linked.sqlite3'
        link.symlink_to(self.state)
        with self.assertRaises(AgentError):
            inspect_state(link)
        self.state.chmod(0o644)
        with self.assertRaises(AgentError):
            inspect_state(self.state)
        self.state.chmod(0o600)

    def test_stale_queue_requires_operator_action_without_deletion(self):
        self.put_login_events()
        a = self.make_agent(self.sender, from_start=True)
        a.poll()
        self.assertEqual(inspect_state(self.state, now=time.time()+300)['status'], 'needs_operator_action')
        with self.assertRaises(AgentError):
            a.store.purge_expired()
        a.clock = lambda: time.time() + 300
        with self.assertRaises(AgentError):
            a.flush()
        self.assertEqual(a.store.size(), 5)

    def test_rotating_key_does_not_reuse_bound_outbox(self):
        self.put_login_events()
        self.make_agent(self.sender, from_start=True).poll()
        new_key = self.db.issue_key()
        self.assertNotEqual(new_key, self.key)
        with self.assertRaisesRegex(AgentError, 'different domain'):
            ContinuousAgent(self.log, self.state, self.did, new_key,
                            server='http://127.0.0.1:8019')

    def test_legacy_owner_watch_stays_supported(self):
        validate_watcher_identity('http://127.0.0.1:8002', 'csa_'+'k'*43)
        with self.assertRaises(AgentError):
            validate_watcher_identity('http://127.0.0.1:8002', self.key)


if __name__ == '__main__':
    unittest.main()
