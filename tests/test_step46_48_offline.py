"""Offline security regressions; never touch a database."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.install_step46_48 import install, PG_ANCHOR, UNIT_ANCHOR
from scripts.step46_trusted_binding import TrustedRoleBroker
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal
from scripts.step48_release_gate import assess


class VerifiedFixture:
    def __init__(self, identity):
        self.identity = identity
        self.calls = []

    def verify(self, token):
        self.calls.append(token)
        if token == 'bad':
            raise ValueError('Mock rejected input')
        return self.identity


class Offline(unittest.TestCase):
    def setUp(self):
        self.roles = ('cs46_012345abcdef_a', 'cs46_012345abcdef_b')
        self.mapping = (('https://issuer.example.org/', 'one', self.roles[0]),
                        ('https://issuer.example.org/', 'two', self.roles[1]))

    def test_verified_identity_is_only_role_selector(self):
        verifier = VerifiedFixture(SimpleNamespace(issuer='https://issuer.example.org/', subject='two'))
        broker = TrustedRoleBroker(verifier, self.mapping)
        self.assertEqual(broker.resolve('opaque-token').login_role, self.roles[1])
        self.assertEqual(verifier.calls, ['opaque-token'])
        verifier.identity = SimpleNamespace(issuer='https://issuer.example.org/', subject='wrong')
        with self.assertRaises(PermissionError):
            broker.resolve('opaque-token')
        with self.assertRaises(ValueError):
            TrustedRoleBroker(verifier, (self.mapping[0], self.mapping[0]))

    def test_fail_closed_broker_token_and_binding(self):
        verifier = VerifiedFixture(SimpleNamespace(issuer='https://issuer.example.org/', subject='one'))
        broker = TrustedRoleBroker(verifier, self.mapping)
        for value in (None, '', 'x' * 9000):
            with self.assertRaises(PermissionError):
                broker.resolve(value)
        with self.assertRaises(ValueError):
            TrustedRoleBroker(verifier, (self.mapping[0], ('https://issuer.example.org/', 'two', 'cybersentinel_runtime')))
        with self.assertRaises(ValueError):
            TrustedRoleBroker(verifier, (self.mapping[1], self.mapping[0]))
        with self.assertRaises(ValueError):
            TrustedRoleBroker(verifier, (self.mapping[0], ('https://issuer.example.org/', 'two', 'cs46_abcdef012345_b')))

    def test_rehearsal_refuses_local_and_remote_environments(self):
        for dsn in ('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/cybersentinel_stage',
                    'postgresql://postgres:ci-ephemeral-admin@neon.example/cybersentinel_stage'):
            with self.subTest(dsn=dsn), patch.dict(os.environ, {'GITHUB_ACTIONS': 'false',
                                          'CYBERSENTINEL_ISOLATED_PG_CI': '0'}):
                with self.assertRaises(RuntimeError):
                    DisposableSchemaRehearsal(dsn)

    def test_installer_preserves_ci_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ci = root / '.github/workflows/ci.yml'
            ci.parent.mkdir(parents=True)
            ci.write_text('existing-header\ntest_step44_45_pg.py -v\n'
                          'test_step44_45_offline.py -v\n'
                          + UNIT_ANCHOR + PG_ANCHOR + 'existing-footer\n')
            self.assertTrue(install(root, check_only=True))
            self.assertTrue(install(root))
            self.assertFalse(install(root))
            content = ci.read_text()
            self.assertIn('existing-header', content)
            self.assertIn('existing-footer', content)
            self.assertEqual(content.count('test_step46_48_pg.py -v'), 1)
            self.assertEqual(content.count('test_step46_48_offline.py -v'), 1)

    def test_gate_never_authorizes_public_beta(self):
        result = assess()
        self.assertEqual(result['status'], 'ready_for_disposable_ci', result)
        self.assertFalse(result['public_beta_allowed'])
        self.assertFalse(result['staging_migrated'])
        self.assertFalse(result['auth0_production_broker_integrated'])
        self.assertFalse(result['ci_postgres_tests_verified'])


if __name__ == '__main__':
    unittest.main()
