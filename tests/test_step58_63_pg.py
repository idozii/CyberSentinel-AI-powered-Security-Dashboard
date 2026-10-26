"""Signed RS256 OIDC -> actual HTTP -> PostgreSQL forced RLS: CI disposable only."""
from __future__ import annotations

import os
import time
import unittest
from unittest.mock import Mock

ADMIN = os.environ.get('CYBERSENTINEL_TEST_PG_ADMIN_DSN','')
from scripts.step39_actor_boundary import disposable_test_dsn
ENABLED = (os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


@unittest.skipUnless(ENABLED, 'Only disposable PostgreSQL 17 GitHub CI')
class SignedTenantHttpPg(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from fastapi.testclient import TestClient
        from hosted_api.disposable_tenant_http import create_disposable_http_pilot
        from hosted_api.identity import OIDCVerifier
        from hosted_api.settings import HostedSettings
        from hosted_api.tenant_session_boundary import TenantSessionBoundary
        from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal
        from scripts.step49_credential_broker import DisposableCredentialBroker
        from scripts.step52_credential_custody import DisposableCredentialCustody

        self.scenario = DisposableSchemaRehearsal(ADMIN)
        try:
            self.scenario.prepare()
            self.scenario.install_additive_policies()
            self.scenario.seed_synthetic()
            self.signing_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
            cfg=HostedSettings.validate('https://issuer.example.org/', 'cybersentinel-ci',
                    'https://issuer.example.org/.well-known/jwks.json',
                    'postgresql://invalid:invalid@localhost/unused')
            verifier=OIDCVerifier(cfg,jwks_client=Mock(get_signing_key_from_jwt=Mock(return_value=Mock(
                key=self.signing_key.public_key(),algorithm_name='RS256'))))
            broker=DisposableCredentialBroker(self.scenario,verifier, (
                (cfg.issuer,'actor-a',self.scenario.roles[0]),
                (cfg.issuer,'actor-b',self.scenario.roles[1])))
            custody=DisposableCredentialCustody(broker)
            self.boundary=TenantSessionBoundary(custody,max_per_tenant=1)
            self.app=create_disposable_http_pilot(self.boundary,enabled=True)
            self.client=TestClient(self.app)
            self.issuer=cfg.issuer
        except Exception:
            self.scenario.close()
            raise

    def tearDown(self):
        self.client.close()
        self.scenario.close()

    def token(self,subject='actor-a',issuer=None,expired=False):
        import jwt
        now=int(time.time())
        claims={'iss':issuer or self.issuer,'aud':'cybersentinel-ci','sub':subject,
                'iat':now-600 if expired else now,'exp':now-300 if expired else now+120}
        return jwt.encode(claims,self.signing_key,algorithm='RS256',headers={'kid':'fixture-key'})

    def overview(self, token):
        from hosted_api.disposable_tenant_http import PATH
        return self.client.get(PATH,headers={'Authorization':'Bearer '+token})

    def test_verified_signed_tenants_five_real_tables(self):
        from scripts.step47_schema_rehearsal import TABLES
        for subject in ('actor-a','actor-b'):
            r=self.overview(self.token(subject))
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(r.json()['table_counts'],{table:1 for table in TABLES})
            self.assertFalse(r.json()['public'])
            self.assertNotIn(self.scenario.roles[0],r.text)

    def test_invalid_issuer_subject_and_expiry_rejected(self):
        for token in (self.token('not-provisioned'),
                      self.token(issuer='https://attacker.example/'),
                      self.token(expired=True)):
            with self.subTest(token_type=token[:20]):
                r=self.overview(token)
                self.assertEqual(r.status_code,401,r.text)
                self.assertNotIn('postgres',r.text.lower())

    def test_tenant_capacity_and_revocation_with_http(self):
        from hosted_api.disposable_tenant_http import PATH
        token_a=self.token('actor-a')
        token_b=self.token('actor-b')
        with self.boundary.borrow(token_a):
            # This tenant is at capacity; other tenant stays independently available.
            self.assertEqual(self.overview(token_a).status_code,401)
            self.assertEqual(self.overview(token_b).status_code,200)
        self.boundary._ci_operator_disable(0)
        self.assertEqual(self.overview(token_a).status_code,401)
        self.assertEqual(self.overview(token_b).status_code,200)
        self.boundary.seal()
        self.assertEqual(self.overview(token_b).status_code,503)


if __name__ == '__main__':
    unittest.main()
