"""Step 19: isolated local demo, forged request rejection and agent E2E contract."""
from __future__ import annotations

import os
import secrets
import time
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

from cybersentinel_agent.client import AgentError, to_minimal_event, validate_ingest_origin, send_events
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step19_generate_logs import generate


class Step19DemoTest(unittest.TestCase):
    def setUp(self):
        self.store = DemoStore()
        self.client = TestClient(create_demo_app(self.store, enabled=True), follow_redirects=False)
        self.domain = self.store.domain_id.hex
        self.key = self.store.issue_key()

    def _evs(self, count=5, *, status=401, group='login'):
        t = int(time.time())
        source = 'f' * 32
        return [dict(event_id=uuid.uuid4().hex, occurred_at=t, source_ref=source,
                     method='GET', path_group=group, status_code=status, duration_ms=2.0,
                     request_bytes=32, response_bytes=19) for _ in range(count)]

    def _post(self, events, *, key=None, domain=None):
        return self.client.post('/agent/v1/ingest',
                                json={'domain_id': domain or self.domain, 'events': events},
                                headers={'Authorization': 'Bearer ' + (key if key is not None else self.key)})

    def test_opt_in_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Explicitly export'):
                create_demo_app()

    def test_health_and_dashboard_never_need_remote_services(self):
        self.assertEqual(self.client.get('/health').json(),
                         {'status':'ok','mode':'isolated-local-demo','public':False,'persistent':False})
        r=self.client.get('/')
        self.assertEqual(r.status_code,200)
        self.assertIn('Local Demo',r.text)
        self.assertIn(self.domain,r.text)
        self.assertIn('demo_csrf',r.cookies)
        self.assertEqual(self.client.get('/docs').status_code,404)

    def test_csrf_and_one_time_key_issuance(self):
        r=self.client.get('/')
        cookie=r.cookies.get('demo_csrf')
        self.assertEqual(self.client.post('/demo/key',data={'_csrf':'invalid'}).status_code,403)
        self.assertEqual(self.client.post('/demo/key',data={'_csrf':cookie},headers={'Origin':'https://evil.example'}).status_code,403)
        new=self.client.post('/demo/key',data={'_csrf':cookie})
        self.assertEqual(new.status_code,200)
        self.assertIn('csd_',new.text)
        self.assertNotIn(self.key,new.text)
        self.assertEqual(self._post(self._evs(1)).status_code,401)
        self.assertNotIn(self.store._token_hash or 'impossible', self.client.get('/').text)
        self.assertNotIn(self.key,self.client.get('/').text)

    def test_browser_form_origin_policy_keeps_csrf_and_blocks_opaque_origin(self):
        page = self.client.get('/')
        # A no-referrer page can submit browser forms with Origin: null.
        # The policy must let same-origin forms send their actual origin.
        self.assertEqual(page.headers.get('referrer-policy'), 'same-origin')
        csrf = page.cookies['demo_csrf']
        body = {'_csrf': csrf}
        self.assertEqual(self.client.post('/demo/key', data=body,
                         headers={'Origin': 'null'}).status_code, 403)
        self.assertEqual(self.client.post('/demo/key', data=body,
                         headers={'Origin': 'http://localhost:8019'}).status_code, 403)
        valid = self.client.post('/demo/key', data=body,
                                 headers={'Origin': 'http://127.0.0.1:8019'})
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertIn('Copy this agent key now', valid.text)

    def test_ingest_alert_dedup_acknowledge(self):
        events=self._evs()
        r=self._post(events)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual((r.json()['accepted'],r.json()['duplicates'],r.json()['alerts_updated']), (5,0,1))
        r2=self._post(events)
        self.assertEqual((r2.json()['accepted'],r2.json()['duplicates'],r2.json()['alerts_updated']), (0,5,0))
        data=self.store.snapshot()
        self.assertEqual(data['total_events'],5)
        self.assertEqual(data['total_alerts'],1)
        self.assertEqual(data['alerts'][0]['rule_id'],'repeated_login_failures')
        csrf=self.client.get('/').cookies['demo_csrf']
        a=data['alerts'][0]['id']
        self.assertEqual(self.client.post('/demo/ack/'+a,data={'_csrf':csrf}).status_code,200)
        self.assertEqual(self.store.snapshot()['alerts'][0]['status'],'acknowledged')
        self.assertEqual(self.client.post('/demo/ack/'+uuid.uuid4().hex,data={'_csrf':csrf}).status_code,404)

    def test_batched_traffic_threshold(self):
        events=self._evs(40,status=200,group='api')
        a=self._post(events[:25]);b=self._post(events[25:])
        self.assertEqual((a.status_code,b.status_code),(200,200))
        self.assertIn('request_volume_spike',[r['rule_id'] for r in self.store.snapshot()['alerts']])

    def test_unverified_or_other_domain_and_live_tokens_denied(self):
        event=self._evs(1)
        self.assertEqual(self._post(event,domain=uuid.uuid4().hex).status_code,401)
        self.assertEqual(self._post(event,key='csp_'+secrets.token_urlsafe(48)).status_code,401)
        self.assertEqual(self.client.post('/agent/v1/ingest',json={'domain_id':self.domain,'events':event}).status_code,401)
        self.assertEqual(self.store.snapshot()['total_events'],0)

    def test_strict_schema_freshness_and_no_partial_write(self):
        valid=self._evs(1)[0]
        self.assertEqual(self._post([valid,{**valid,'event_id':uuid.uuid4().hex,'occurred_at':int(time.time())-600}]).status_code,422)
        self.assertEqual(self.store.snapshot()['total_events'],0)
        self.assertEqual(self._post([{**valid,'remote_addr':'192.0.2.1'}]).status_code,422)
        self.assertEqual(self._post([{**valid,'method':'TRACE'}]).status_code,422)
        self.assertEqual(self.store.snapshot()['total_events'],0)

    def test_duplicate_inside_batch_not_double_counted(self):
        ev=self._evs(1)[0]
        data=self._post([ev,ev]).json()
        self.assertEqual((data['accepted'],data['duplicates']),(1,1))

    def test_rate_and_capacity_atomic(self):
        self.assertEqual(self._post(self._evs(25)).status_code,200)
        for _ in range(3):
            self.assertEqual(self._post(self._evs(25)).status_code,200)
        self.assertEqual(self.store.snapshot()['total_events'],100)
        self.assertEqual(self._post(self._evs(25)).status_code,429)
        self.assertEqual(self.store.snapshot()['total_events'],100)

    def test_server_origin_allow_list_blocks_hostnames_and_incorrect_scheme(self):
        self.assertEqual(validate_ingest_origin('http://127.0.0.1:8019'), 'http://127.0.0.1:8019')
        for url in ('http://localhost:8019','http://127.0.0.1:8020','http://127.0.0.1:8019/path',
                    'https://127.0.0.1:8019','http://0.0.0.0:8019'):
            with self.subTest(url=url),self.assertRaises(AgentError):
                validate_ingest_origin(url)
        self.assertEqual(self.client.get('/',headers={'Host':'evil.example'}).status_code,400)

    def test_end_to_end_adapter_event_contract(self):
        rows=generate('login')
        events=[to_minimal_event(row,self.key) for row in rows]
        r=self._post(events)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['alerts_updated'],1)

    def test_reject_staging_keys_in_local_agent_before_network(self):
        ev=self._evs(1)
        with self.assertRaisesRegex(AgentError,'only local demo keys'):
            send_events('http://127.0.0.1:8019', self.domain, ev, 'csp_'+secrets.token_urlsafe(48))
        with self.assertRaisesRegex(AgentError,'cannot be used'):
            send_events('http://127.0.0.1:8008', self.domain, ev, self.key)

    def test_generated_dashboard_does_not_reflect_untrusted_event_values(self):
        ev=self._evs(1)[0]
        ev['path_group']='<script>alert(1)</script>'
        self.assertEqual(self._post([ev]).status_code,422)
        self.assertNotIn('<script>',self.client.get('/').text)


if __name__=='__main__':
    unittest.main()
