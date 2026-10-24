"""Offline regression for combined Steps 22-25. No live credentials or network."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from cybersentinel_agent.demo_cli import run as run_agent
from cybersentinel_agent.client import AgentError
from hosted_api.demo_triage import select_alerts
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step19_generate_logs import generate
from scripts.step23_agent_doctor import diagnose
from scripts.step24_failure_analysis import analyze
from scripts.step25_release import release_smoke
from scripts.step25_demo import main as demo_launcher


class FasttrackDemoTest(unittest.TestCase):
    def setUp(self):
        self.db=DemoStore()
        self.client=TestClient(create_demo_app(self.db, enabled=True))
        self.key=self.db.issue_key()
        self.domain=self.db.domain_id.hex

    def tearDown(self):
        self.client.close()

    def _events(self, n=5, *, status=401, group='login'):
        src='a'*32
        return [dict(event_id=uuid.uuid4().hex, occurred_at=int(time.time()),
                     source_ref=src,method='GET',path_group=group,status_code=status,
                     duration_ms=1.2,request_bytes=64,response_bytes=12) for _ in range(n)]

    def _send(self, events):
        return self.client.post('/agent/v1/ingest',json={'domain_id':self.domain,'events':events},
                                headers={'Authorization':'Bearer '+self.key})

    def test_triage_filters_and_pseudonym_evidence(self):
        self.assertEqual(self._send(self._events()).status_code,200)
        r=self.client.get('/demo/alerts?status=open&severity=high&rule=repeated_login_failures')
        self.assertEqual(r.status_code,200)
        self.assertIn('Matching alerts: 1',r.text)
        self.assertEqual(self.client.get('/demo/alerts?severity=medium').status_code,200)
        self.assertIn('Matching alerts: 0',self.client.get('/demo/alerts?severity=medium').text)
        a=self.db.snapshot()['alerts'][0]['id']
        e=self.client.get('/demo/alerts/'+a)
        self.assertEqual(e.status_code,200)
        self.assertIn('Events in evidence window: 5',e.text)
        self.assertNotIn(self.key,e.text)
        self.assertIn('aaaaaaaaaaaa',e.text)
        self.assertNotIn('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',e.text)

    def test_filter_rejects_injection_and_unknown_rule(self):
        self._send(self._events())
        for url in ('/demo/alerts?status=evil','/demo/alerts?rule=unknown',
                    '/demo/alerts?severity=critical','/demo/alerts?query='+'A'*65):
            self.assertEqual(self.client.get(url).status_code,422,url)
        html=self.client.get('/demo/alerts?query=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        self.assertEqual(html.status_code,200)
        self.assertNotIn('<script>',html.text)
        self.assertIn('&lt;script&gt;',html.text)
        self.assertEqual(self.client.get('/demo/alerts/'+uuid.uuid4().hex).status_code,404)
        self.assertEqual(self.client.get('/demo/alerts/anything-invalid').status_code,404)

    def test_acknowledge_visible_in_triage_and_rotation(self):
        self._send(self._events())
        page=self.client.get('/')
        token=page.cookies['demo_csrf']
        ident=self.db.snapshot()['alerts'][0]['id']
        result=self.client.post('/demo/ack/'+ident,data={'_csrf':token},
                                headers={'Origin':'http://127.0.0.1:8019'})
        self.assertEqual(result.status_code,200)
        self.assertEqual(len(self.db.triage(status='acknowledged')),1)
        self.db.issue_key()
        self.assertEqual(len(self.db.triage()),0)
        self.assertEqual(self._send(self._events()).status_code,401)

    def test_local_agent_dry_run_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'demo.jsonl'
            path.write_text(''.join(json.dumps(v)+'\n' for v in generate('login')),encoding='utf-8')
            report=run_agent(path,self.domain,self.key,dry_run=True)
            self.assertEqual(report['events_validated'],5)
            self.assertFalse(report['transmitted'])
            self.assertNotIn(self.key,json.dumps(report))
            self.assertEqual(diagnose(path,key=self.key)['events_validated'],5)
            with self.assertRaises(AgentError):
                run_agent(path,self.domain,'csp_fake',dry_run=True)

    def test_doctor_failure_is_bounded_and_local(self):
        with patch('scripts.step23_agent_doctor.request.build_opener') as opener:
            opener.return_value.open.side_effect=OSError('offline')
            result=diagnose(check_server=True,key=self.key)
        self.assertFalse(result['server_healthy'])
        self.assertTrue(result['no_secrets_printed'])

    def test_step24_manually_labeled_extension_is_separate(self):
        report=analyze()
        self.assertEqual(report['scenario_count'],11)
        self.assertEqual(report['scenario_rule_pairs'],44)
        self.assertEqual(len(report['manifest_sha256']),64)
        self.assertIn('Manually',report['label_provenance'])
        names={r['scenario'] for r in report['scenarios']}
        self.assertIn('distributed_low_rate_login',names)
        self.assertNotIn(self.key,json.dumps(report))

    def test_step25_full_release_smoke(self):
        report=release_smoke()
        self.assertEqual(report['status'],'pass')
        self.assertTrue(all(report['checks'].values()))

    def test_launcher_refuses_staging_secrets(self):
        with patch.dict(os.environ,{'CYBERSENTINEL_PG_RUNTIME_DSN':'dummy'}):
            with self.assertRaises(SystemExit):
                demo_launcher()

    def test_triage_pure_filter_does_not_modify_alert(self):
        alert=dict(id=uuid.uuid4().hex,status='open',rule_id='http_404_burst',
                   title='HTTP 404 response burst',severity='medium')
        self.assertEqual(len(select_alerts([alert],query='404')),1)
        self.assertEqual(alert['status'],'open')


if __name__=='__main__':
    unittest.main()
