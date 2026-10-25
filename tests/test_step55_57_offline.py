"""No-network regression: admission capacity, identity boundary and no-go gate."""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from hosted_api.tenant_session_boundary import TenantSessionBoundary
from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step52_credential_custody import DisposableCredentialCustody
from scripts.step57_architecture_gate import assess
from scripts.install_step55_57 import install, UNIT_ANCHOR, PG_ANCHOR

ROLES = ('cs46_aaaaaaaaaaaa_a', 'cs46_aaaaaaaaaaaa_b')


class FakeConnection:
    def __init__(self, role):
        self.role = role

    def execute(self, query, *args):
        return self

    def fetchone(self):
        return (self.role, self.role)


class TenantAdmissionOffline(unittest.TestCase):
    def fixture(self):
        broker = object.__new__(DisposableCredentialBroker)
        broker._scenario = SimpleNamespace(roles=ROLES)
        broker._guard = Mock()
        broker._resolve = Mock(side_effect=lambda token: {
            'synthetic-secret-a': 0, 'synthetic-secret-b': 1,
        }[token])
        broker._ci_operator_disable_and_terminate = Mock(return_value=2)

        @contextmanager
        def fake_session(token):
            yield FakeConnection(ROLES[broker._resolve(token)])

        broker.session = fake_session
        custody = DisposableCredentialCustody(broker)
        boundary = TenantSessionBoundary(custody, max_per_tenant=1)
        return boundary, custody, broker

    def test_two_tenants_have_independent_capacity(self):
        boundary, _, _ = self.fixture()
        with boundary.borrow('synthetic-secret-a') as a:
            self.assertEqual(a.fetchone(), ROLES[:1]*2)
            with self.assertRaises(PermissionError):
                with boundary.borrow('synthetic-secret-a'):
                    self.fail('Per-tenant limit bypassed')
            with boundary.borrow('synthetic-secret-b') as b:
                self.assertEqual(b.role, ROLES[1])
                self.assertEqual(boundary.report()['active_fixture_sessions'], 2)
        self.assertEqual(boundary.report()['active_fixture_sessions'], 0)
        self.assertEqual(boundary.report()['denied_requests'], 1)

    def test_failed_authentication_does_not_leak_or_consume_capacity(self):
        boundary, _, _ = self.fixture()
        with self.assertRaises(PermissionError):
            with boundary.borrow('super-sensitive-invalid-bearer'):
                self.fail('Invalid token accepted')
        self.assertEqual(boundary.report()['active_fixture_sessions'], 0)
        with boundary.borrow('synthetic-secret-a'):
            pass
        payload = json.dumps(boundary.report())
        for secret in ('synthetic-secret-a','synthetic-secret-b','super-sensitive-invalid-bearer'):
            self.assertNotIn(secret,payload)

    def test_connection_failure_releases_slot(self):
        boundary, _, broker = self.fixture()
        @contextmanager
        def unavailable(_):
            raise RuntimeError('Synthetic database outage')
            yield  # pragma: no cover
        broker.session = unavailable
        with self.assertRaises(RuntimeError):
            with boundary.borrow('synthetic-secret-a'):
                self.fail('Outage was ignored')
        self.assertEqual(boundary.report()['active_fixture_sessions'], 0)

    def test_disable_blocks_first_tenant_even_after_operator_failure(self):
        boundary, _, broker = self.fixture()
        broker._ci_operator_disable_and_terminate.side_effect = RuntimeError('Simulated failure')
        with self.assertRaises(RuntimeError):
            boundary._ci_operator_disable(0)
        with self.assertRaises(PermissionError):
            with boundary.borrow('synthetic-secret-a'):
                self.fail('Fail-open after operator error')
        with boundary.borrow('synthetic-secret-b'):
            pass
        self.assertEqual(boundary.report()['blocked_fixture_logins'], 1)

    def test_mismatched_database_identity_is_rejected_and_slot_released(self):
        boundary, _, broker = self.fixture()
        @contextmanager
        def mismatched(_):
            yield FakeConnection('cs46_ffffffffffff_b')
        broker.session = mismatched
        with self.assertRaises(PermissionError):
            with boundary.borrow('synthetic-secret-a'):
                self.fail('Unexpected session accepted')
        self.assertEqual(boundary.report()['active_fixture_sessions'], 0)

    def test_seal_blocks_sessions_but_does_not_claim_revoke_existing(self):
        boundary, custody, _ = self.fixture()
        with boundary.borrow('synthetic-secret-a'):
            boundary.seal()
            self.assertEqual(boundary.report()['active_fixture_sessions'], 1)
            with self.assertRaises(RuntimeError):
                with boundary.borrow('synthetic-secret-b'):
                    self.fail('Sealed admission accepted')
        self.assertFalse(custody.report()['enabled'])
        self.assertEqual(boundary.report()['active_fixture_sessions'], 0)

    def test_bad_configuration_and_fixture_index_rejected(self):
        boundary, custody, _ = self.fixture()
        with self.assertRaises(TypeError):
            TenantSessionBoundary(object())
        for val in (True, 0, 17, 1.5):
            with self.subTest(value=val), self.assertRaises(ValueError):
                TenantSessionBoundary(custody,max_per_tenant=val)
        for val in (True,-1,2):
            with self.subTest(value=val), self.assertRaises(ValueError):
                boundary._ci_operator_disable(val)

    def test_installer_idempotent_and_preserves_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root/'.github/workflows/ci.yml'
            p.parent.mkdir(parents=True)
            original = ('name: existing CI\n'
                        'test_step52_54_pg.py -v\n'
                        'test_step52_54_offline.py -v\n'
                        + UNIT_ANCHOR + PG_ANCHOR + 'trailer: unchanged\n')
            p.write_text(original)
            self.assertTrue(install(root,check_only=True))
            self.assertEqual(p.read_text(), original)
            self.assertTrue(install(root))
            after = p.read_text()
            self.assertFalse(install(root))
            self.assertEqual(p.read_text(), after)
            self.assertEqual(after.count('test_step55_57_pg.py -v'),1)
            self.assertTrue(after.endswith('trailer: unchanged\n'))

    def test_installer_rejects_unexpected_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            p=root/'.github/workflows/ci.yml'
            p.parent.mkdir(parents=True)
            p.write_text('name: CI\n'+UNIT_ANCHOR+PG_ANCHOR)
            with self.assertRaises(RuntimeError):
                install(root)

    def test_readiness_gate_does_not_authorize_public_beta(self):
        result=assess()
        self.assertEqual(result['status'],'ready_for_ci_review',result)
        self.assertTrue(all(result['checks'].values()),result)
        self.assertEqual(result['decision'],'NO_GO')
        self.assertFalse(result['public_beta_allowed'])
        self.assertFalse(result['production_pool_or_distributed_revocation_proven'])
        self.assertFalse(result['staging_migrated'])


if __name__ == '__main__':
    unittest.main()
