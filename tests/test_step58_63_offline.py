"""Fast, offline HTTP integration-contract tests for the isolated vertical slice."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from hosted_api.disposable_tenant_http import (
    PATH, create_disposable_http_pilot, require_disposable,
)
from hosted_api.tenant_session_boundary import TenantSessionBoundary
from scripts.install_step58_63 import install, UNIT_ANCHOR, PG_ANCHOR
from scripts.step63_security_gate import assess


def offline_boundary() -> TenantSessionBoundary:
    bound = object.__new__(TenantSessionBoundary)
    scenario = SimpleNamespace(
        created=True, reverted=False,
        roles=('cs46_aaaaaaaaaaaa_a', 'cs46_aaaaaaaaaaaa_b'),
        created_roles=['cs46_aaaaaaaaaaaa_a', 'cs46_aaaaaaaaaaaa_b'],
        _guard=Mock(),
    )
    bound._custody = SimpleNamespace(_broker=SimpleNamespace(_scenario=scenario))
    bound._check = Mock()
    return bound


class HttpPilotOffline(unittest.TestCase):
    def test_default_disabled_even_with_boundary(self):
        with self.assertRaises(RuntimeError):
            create_disposable_http_pilot(offline_boundary())

    def test_no_authentication_works_without_guarded_ci(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false',
                                      'CYBERSENTINEL_ISOLATED_PG_CI': '0'}):
            with self.assertRaises(RuntimeError):
                create_disposable_http_pilot(offline_boundary(), enabled=True)

    def test_wrong_provider_and_unprovisioned_fixture_refused(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true',
                                      'CYBERSENTINEL_ISOLATED_PG_CI': '1'}):
            with self.assertRaises(TypeError):
                require_disposable(object())
            bound = offline_boundary()
            bound._custody._broker._scenario.created_roles.pop()
            with self.assertRaises(RuntimeError):
                create_disposable_http_pilot(bound, enabled=True)

    def fixture(self):
        fake = Mock()
        fake.overview.return_value = {k: 1 for k in (
            'identities','domains','agent_keys','telemetry_events','detection_alerts')}
        env = patch.dict(os.environ, {'GITHUB_ACTIONS': 'true',
                                      'CYBERSENTINEL_ISOLATED_PG_CI': '1'})
        factory = patch('hosted_api.disposable_tenant_http.IsolatedTenantBoundaryCanary',
                        return_value=fake)
        return env, factory, fake

    def test_http_auth_query_and_method_safety(self):
        env, factory, fake = self.fixture()
        with env, factory:
            with TestClient(create_disposable_http_pilot(offline_boundary(), enabled=True)) as client:
                self.assertEqual(client.get(PATH).status_code, 401)
                self.assertEqual(client.get(PATH + '?owner_id=evil',
                                            headers={'Authorization': 'Bearer ci-a'}).status_code, 400)
                self.assertEqual(client.post(PATH).status_code, 405)
                self.assertEqual(client.get('/openapi.json').status_code, 404)
                self.assertEqual(client.get(PATH,headers={'Authorization':'Basic secret'}).status_code,401)
                ok = client.get(PATH,headers={'Authorization': 'Bearer ci-a'})
                self.assertEqual(ok.status_code,200,ok.text)
                self.assertEqual(ok.json()['table_counts']['identities'],1)
                self.assertFalse(ok.json()['public'])
                self.assertEqual(ok.headers['Cache-Control'], 'no-store')
                self.assertEqual(fake.overview.call_args.args[0], 'ci-a')

    def test_invalid_bearer_never_leaks_secret(self):
        env, factory, fake = self.fixture()
        fake.overview.side_effect = PermissionError('sensitive bearer secret-a')
        with env, factory:
            with TestClient(create_disposable_http_pilot(offline_boundary(), enabled=True)) as client:
                response = client.get(PATH,headers={'Authorization':'Bearer secret-a'})
                self.assertEqual(response.status_code,401)
                self.assertNotIn('secret-a',response.text)

    def test_db_outage_fails_closed(self):
        env, factory, fake = self.fixture()
        fake.overview.side_effect = RuntimeError('database passphrase 123')
        with env, factory:
            with TestClient(create_disposable_http_pilot(offline_boundary(), enabled=True)) as client:
                response = client.get(PATH,headers={'Authorization':'Bearer ci-a'})
                self.assertEqual(response.status_code,503)
                self.assertNotIn('passphrase',response.text)

    def test_remote_client_and_untrusted_host_denied(self):
        env, factory, fake = self.fixture()
        with env, factory:
            app = create_disposable_http_pilot(offline_boundary(), enabled=True)
            with TestClient(app,client=('192.0.2.9',41000)) as client:
                self.assertEqual(client.get(PATH,headers={'Authorization':'Bearer ci-a'}).status_code,403)
            with TestClient(app) as client:
                self.assertEqual(client.get(PATH,headers={'Host':'attacker.example',
                                              'Authorization':'Bearer ci-a'}).status_code,400)
            fake.overview.assert_not_called()

    def test_installer_idempotent_and_guarded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            ci=root/'.github/workflows/ci.yml'
            ci.parent.mkdir(parents=True)
            original='name: test\n'+ 'test_step55_57_pg.py -v\n'+ 'test_step55_57_offline.py -v\n'+UNIT_ANCHOR+PG_ANCHOR
            ci.write_text(original)
            self.assertTrue(install(root,check_only=True))
            self.assertEqual(ci.read_text(),original)
            self.assertTrue(install(root))
            self.assertFalse(install(root))
            self.assertEqual(ci.read_text().count('test_step58_63_pg.py -v'),1)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            ci=root/'.github/workflows/ci.yml'
            ci.parent.mkdir(parents=True)
            ci.write_text('no anchors')
            with self.assertRaises(RuntimeError):
                install(root)

    def test_release_gate_no_go(self):
        result=assess()
        self.assertEqual(result['status'],'ready_for_ci_review',result)
        self.assertEqual(result['decision'],'NO_GO')
        self.assertFalse(result['public_beta_allowed'])
        self.assertFalse(result['legacy_hosted_api_migrated'])
        self.assertTrue(all(result['checks'].values()),result)


if __name__ == '__main__':
    unittest.main()
