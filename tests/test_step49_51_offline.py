"""Offline fail-closed checks. No real DB, network, JWT or secrets."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.install_step49_51 import install, UNIT_NEW, PG_NEW, UNIT_ANCHOR, PG_ANCHOR
from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step51_application_canary import IsolatedApplicationCanary
from scripts.step51_release_gate import assess


class FakeVerifier:
    def verify(self, token):
        if token == 'synthetic-a':
            return SimpleNamespace(issuer='https://issuer.example/', subject='tenant-a')
        if token == 'synthetic-b':
            return SimpleNamespace(issuer='https://issuer.example/', subject='tenant-b')
        raise PermissionError('bad token')


def fake_scenario():
    prefix = 'cs46_123456abcdef'
    return SimpleNamespace(
        admin_dsn='NOT_A_REAL_DSN', name=prefix, roles=(prefix+'_a', prefix+'_b'),
        created=True, reverted=False, created_roles=[prefix+'_a', prefix+'_b'],
        passwords=('synthetic-secret-1', 'synthetic-secret-2'), _guard=lambda: None,
    )


class BrokerOfflineTests(unittest.TestCase):
    def setUp(self):
        self.scenario = fake_scenario()
        self.bindings = (
            ('https://issuer.example/', 'tenant-a', self.scenario.roles[0]),
            ('https://issuer.example/', 'tenant-b', self.scenario.roles[1]),
        )
        patcher = patch('scripts.step49_credential_broker.protected_ci')
        patcher.start()
        self.addCleanup(patcher.stop)

    def broker(self, bindings=None):
        return DisposableCredentialBroker(self.scenario, FakeVerifier(),
                                          self.bindings if bindings is None else bindings)

    def test_unverified_or_unprovisioned_requests_fail_closed(self):
        broker = self.broker()
        self.assertEqual(broker._resolve('synthetic-a'), 0)
        self.assertEqual(broker._resolve('synthetic-b'), 1)
        for token in ('not-provisioned', '', None, 42):
            with self.subTest(token=repr(token)), self.assertRaises(PermissionError):
                broker._resolve(token)

    def test_provisioning_requires_exact_fixture_identity_role_mapping(self):
        with self.assertRaises(ValueError):
            self.broker((self.bindings[0][0:2] + (self.scenario.roles[1],), self.bindings[1]))
        self.scenario.created = False
        with self.assertRaises(RuntimeError):
            self.broker()

    def test_revoked_tenant_denied_without_affecting_other_identity(self):
        broker = self.broker()
        broker._disabled.add(0)
        with self.assertRaises(PermissionError):
            broker._resolve('synthetic-a')
        self.assertEqual(broker._resolve('synthetic-b'), 1)

    def test_operator_controls_reject_non_fixture_tenant_indices(self):
        broker = self.broker()
        for index in (-1, 2, True, '0'):
            with self.subTest(index=repr(index)):
                with self.assertRaises(ValueError):
                    broker._ci_operator_rotate(index)
                with self.assertRaises(ValueError):
                    broker._ci_operator_disable_and_terminate(index)

    def test_canary_rejects_invalid_update_ids_before_db_connection(self):
        canary = IsolatedApplicationCanary(self.broker())
        with self.assertRaises(ValueError):
            canary.acknowledge('synthetic-a', 'some-alert-id')

    def test_workflow_installer_is_idempotent_and_preserves_prior_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root/'.github/workflows/ci.yml'
            file.parent.mkdir(parents=True)
            original = ('name: Existing CI\n'
                        'test_step46_48_offline.py -v\n'
                        'test_step46_48_pg.py -v\n'
                        + UNIT_ANCHOR + PG_ANCHOR + 'end: preserved\n')
            file.write_text(original, encoding='utf-8')
            self.assertTrue(install(root, check_only=True))
            self.assertEqual(file.read_text(), original)
            self.assertTrue(install(root))
            self.assertFalse(install(root))
            self.assertFalse(install(root, check_only=True))
            edited = file.read_text()
            self.assertEqual(edited.count(UNIT_NEW), 1)
            self.assertEqual(edited.count(PG_NEW), 1)
            self.assertIn('end: preserved\n', edited)

    def test_gate_requires_ci_and_refuses_public_beta(self):
        report = assess()
        self.assertEqual(report['status'], 'ready_for_ci', report)
        self.assertFalse(report['public_beta_allowed'])
        self.assertFalse(report['production_secret_vault'])
        self.assertFalse(report['real_oidc_broker_integrated'])
        self.assertFalse(report['isolated_pg_success_claimed'])


if __name__ == '__main__':
    unittest.main()
