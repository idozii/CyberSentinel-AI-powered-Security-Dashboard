"""Disposable PostgreSQL 17 witness of risk under a STOLEN runtime credential.

IMPORTANT: only tests local CI database. Never point to Neon. This is a
controlled threat-model demonstration, not a feature to impersonate users.
"""
from __future__ import annotations

import os
import unittest
import uuid
from scripts.step39_actor_boundary import disposable_test_dsn

from hosted_api.identity import Identity
from hosted_api.postgres import HostedStore, identity_id
from scripts.step16_migrate import run as migrate_001
from scripts.step18_migrate import run as migrate_002

ADMIN = os.environ.get('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
RUNTIME = os.environ.get('CYBERSENTINEL_TEST_PG_RUNTIME_DSN', '')


@unittest.skipUnless(ADMIN and RUNTIME and
                     os.getenv('GITHUB_ACTIONS') == 'true' and
                     os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1',
                     'Only enabled on GitHub Actions disposable PostgreSQL service')
class RuntimeCredentialCompromiseWitness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(disposable_test_dsn(d) for d in (ADMIN, RUNTIME)):
            raise RuntimeError('Refusing non-disposable PostgreSQL database: localhost/ci only')
        migrate_001(ADMIN)
        migrate_002(ADMIN)
        cls.store = HostedStore(RUNTIME)

    def test_shared_role_actor_can_be_changed_by_direct_sql_login(self):
        # Both accounts and domains are fabricated specifically for disposable CI.
        nonce = uuid.uuid4().hex
        owner_a = Identity('https://issuer.example.org/', 'actor-a-'+nonce)
        owner_b = Identity('https://issuer.example.org/', 'actor-b-'+nonce)
        self.store.ensure_identity(owner_a)
        self.store.ensure_identity(owner_b)
        domain_b = self.store.create_domain(owner_b, 'ci-only-'+nonce+'.org')
        self.store.verify_domain(owner_b, uuid.UUID(domain_b['id']), lambda _: [domain_b['txt_value']])
        with self.store._connect() as db:
            # No app-issued Auth0 identity is involved. Represents direct access
            # if the shared DB runtime credential itself has been compromised.
            db.execute("SELECT set_config('cs.actor_id', %s, true)", (str(identity_id(owner_a)),))
            before = db.execute('SELECT count(*) AS n FROM cs.domains').fetchone()['n']
            db.execute("SELECT set_config('cs.actor_id', %s, true)", (str(identity_id(owner_b)),))
            after = db.execute('SELECT count(*) AS n FROM cs.domains WHERE id=%s',
                               (uuid.UUID(domain_b['id']),)).fetchone()['n']
        self.assertEqual(before, 0)
        self.assertEqual(after, 1, 'Revisit threat model if the mutable actor design changes')
        with self.store._connect() as db:
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.domains').fetchone()['n'], 0)


if __name__ == '__main__':
    unittest.main()
