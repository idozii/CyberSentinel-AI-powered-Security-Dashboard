"""Step 16 - cryptographic OIDC and private hosted API unit tests; no network."""
from __future__ import annotations

import time
import unittest
from unittest.mock import Mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from hosted_api.identity import OIDCVerifier, Identity, IdentityRejected
from hosted_api.main import create_app
from hosted_api.postgres import identity_id
from hosted_api.settings import HostedSettings

CFG = HostedSettings.validate('https://issuer.example.org/', 'cybersentinel-owner-api',
                              'https://issuer.example.org/.well-known/jwks.json',
                              'postgresql://example:fake@localhost/example')


class KeySet:
    def __init__(self, private):
        self.public = private.public_key()
    def get_signing_key_from_jwt(self, _token):
        return Mock(key=self.public, algorithm_name='RS256')


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.verifier = OIDCVerifier(CFG, jwks_client=KeySet(cls.private))

    def encode(self, **changes):
        now = int(time.time())
        data = {'iss': CFG.issuer, 'aud': CFG.audience, 'sub': 'user-123',
                'iat': now, 'exp': now + 180}
        data.update(changes)
        return jwt.encode(data, self.private, algorithm='RS256', headers={'kid': 'k1'})

    def test_valid_access_token_and_stable_owner_id(self):
        identity = self.verifier.verify(self.encode())
        self.assertEqual(identity, Identity(CFG.issuer, 'user-123'))
        self.assertEqual(identity_id(identity), identity_id(identity))
        self.assertNotEqual(identity_id(identity), identity_id(Identity(CFG.issuer, 'other')))

    def test_wrong_issuer_and_audience(self):
        for claims in ({'iss': 'https://evil.example/'}, {'aud': 'unrelated'}):
            with self.subTest(claims=claims), self.assertRaises(IdentityRejected):
                self.verifier.verify(self.encode(**claims))

    def test_expired_and_missing_required_claims(self):
        for claims in ({'exp': int(time.time())-500}, {'sub': ''}, {'iat': None}):
            with self.subTest(claims=claims), self.assertRaises(IdentityRejected):
                self.verifier.verify(self.encode(**claims))

    def test_unsigned_hs256_and_malicious_header_rejected(self):
        unsigned = jwt.encode({'iss':CFG.issuer}, key='', algorithm='none', headers={'kid':'k1'})
        with self.assertRaises(IdentityRejected):
            self.verifier.verify(unsigned)
        hs = jwt.encode({'iss':CFG.issuer}, key='hmac-secret-with-at-least-thirty-two-bytes-123456', algorithm='HS256', headers={'kid':'k1'})
        with self.assertRaises(IdentityRejected):
            self.verifier.verify(hs)
        token = jwt.encode({'iss':CFG.issuer, 'aud':CFG.audience, 'sub':'u',
                            'exp': int(time.time())+60, 'iat':int(time.time())},
                           self.private, algorithm='RS256', headers={'kid':'k1', 'jku':'https://evil.example/jwks'})
        with self.assertRaises(IdentityRejected):
            self.verifier.verify(token)

    def test_invalid_configuration(self):
        for issuer, jwks in [('http://issuer.example.org','https://issuer.example.org/jwks'),
                             ('https://issuer.example.org','http://issuer.example.org/jwks'),
                             ('https://localhost','https://issuer.example.org/jwks'),
                             ('https://10.0.0.5','https://issuer.example.org/jwks')]:
            with self.subTest(issuer=issuer, jwks=jwks), self.assertRaises(ValueError):
                HostedSettings.validate(issuer,'aud',jwks,'postgresql://not-used')


class FakeStore:
    def __init__(self):
        self.known = []
    def ensure_identity(self, subject):
        self.known.append(subject)
        return {'id': str(identity_id(subject))}
    def list_domains(self, subject):
        return []
    def create_domain(self, subject, domain):
        return {'domain': domain, 'verified': False}
    def verify_domain(self, subject, domain_id, resolver):
        return {'verified': False}


class APIStagingTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.verifier = OIDCVerifier(CFG, jwks_client=KeySet(self.private))
        self.client = TestClient(create_app(CFG, verifier=self.verifier, store=self.store, dns_lookup=lambda _: []))

    def token(self):
        now = int(time.time())
        return jwt.encode({'iss':CFG.issuer,'aud':CFG.audience,'sub':'alice', 'iat':now,'exp':now+120},
                          self.private,algorithm='RS256',headers={'kid':'k1'})

    def test_authentication_required_and_no_public_registration(self):
        self.assertEqual(self.client.get('/hosted/v1/me').status_code, 401)
        self.assertEqual(self.client.get('/hosted/v1/domains').status_code, 401)
        self.assertEqual(self.client.post('/owner/register').status_code, 404)
        self.assertEqual(self.client.post('/hosted/v1/register').status_code, 404)
        self.assertEqual(self.client.get('/docs').status_code, 404)
        self.assertEqual(self.client.get('/openapi.json').status_code, 404)

    def test_health_discloses_private_staging_and_no_migrated_telemetry(self):
        body = self.client.get('/hosted/v1/health').json()
        self.assertFalse(body['public_signup'])
        self.assertFalse(body['live_telemetry_migrated'])

    def test_valid_token_returns_pseudonymous_account_without_email(self):
        response = self.client.get('/hosted/v1/me',headers={'Authorization':'Bearer '+self.token()})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(len(self.store.known),1)
        self.assertFalse(response.json()['email_collected'])
        self.assertNotIn('subject',response.json())
        self.assertEqual(response.headers['cache-control'],'no-store')

    def test_reject_untrusted_host_and_non_loopback(self):
        self.assertEqual(self.client.get('/hosted/v1/health',headers={'Host':'remote.example.org'}).status_code,400)
        api = create_app(CFG, verifier=self.verifier, store=self.store)
        external = TestClient(api,client=('192.0.2.4',4321))
        self.assertEqual(external.get('/hosted/v1/health').status_code,403)


if __name__ == '__main__':
    unittest.main()
