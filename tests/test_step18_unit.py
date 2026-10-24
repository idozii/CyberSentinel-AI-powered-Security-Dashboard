"""Step 18 smoke checks that run offline without any PostgreSQL credentials."""
from __future__ import annotations

import time
import unittest
import uuid

from fastapi.testclient import TestClient

from cybersentinel_agent.client import AgentError, validate_ingest_origin
from hosted_api.ingest import create_ingest_app
from hosted_api.monitoring import MonitoringStore, validate_events
from hosted_api.postgres import HostedError
from scripts.step18_migrate import SQL_PATH


class StubMonitoring:
    def __init__(self):
        self.calls = []
    def ingest(self, token, domain_id, events):
        self.calls.append((token,domain_id,events))
        return {'accepted':len(events),'duplicates':0,'alerts_updated':0,'domain_id':domain_id.hex}


class HostedIngestOffline(unittest.TestCase):
    def setUp(self):
        self.store=StubMonitoring()
        self.client=TestClient(create_ingest_app(store=self.store))
        self.domain=uuid.uuid4().hex
        self.event=dict(event_id=uuid.uuid4().hex,occurred_at=int(time.time()),source_ref=uuid.uuid4().hex,
                        method='GET',path_group='login',status_code=401,duration_ms=3.5,
                        request_bytes=33,response_bytes=19)
        self.body={'domain_id':self.domain,'events':[self.event]}

    def test_ingest_requires_bearer_and_strict_event_schema(self):
        self.assertEqual(self.client.post('/agent/v1/ingest',json=self.body).status_code,401)
        response=self.client.post('/agent/v1/ingest',json=self.body,headers={'Authorization':'Bearer abc'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(len(self.store.calls),1)
        extra=dict(self.event);extra['remote_addr']='192.0.2.1'
        self.assertEqual(self.client.post('/agent/v1/ingest',json={'domain_id':self.domain,'events':[extra]},
                   headers={'Authorization':'Bearer abc'}).status_code,422)

    def test_no_docs_and_body_limit(self):
        self.assertEqual(self.client.get('/docs').status_code,404)
        self.assertEqual(self.client.get('/openapi.json').status_code,404)
        self.assertEqual(self.client.post('/agent/v1/ingest',content=b'a'*32769).status_code,413)

    def test_validation_rejects_malformed_and_stale(self):
        with self.assertRaises(HostedError):
            validate_events([{**self.event,'occurred_at':int(time.time())-1000}],time.time())
        with self.assertRaises(HostedError):
            validate_events([{**self.event,'source_ref':'192.0.2.1'}],time.time())
        with self.assertRaises(HostedError):
            validate_events([{**self.event,'extra':'raw-url'}],time.time())

    def test_agent_legacy_and_new_localhost_origins(self):
        self.assertEqual(validate_ingest_origin('http://127.0.0.1:8008'),'http://127.0.0.1:8008')
        self.assertEqual(validate_ingest_origin('http://127.0.0.1:8002'),'http://127.0.0.1:8002')
        for url in ('http://localhost:8008','http://127.0.0.1:8009','http://127.0.0.1:8008/agent/v1/ingest'):
            with self.subTest(url=url), self.assertRaises(AgentError):
                validate_ingest_origin(url)

    def test_migration_contains_rls_and_tenant_fk(self):
        sql=SQL_PATH.read_text(encoding='utf-8')
        self.assertEqual(sql.count('ENABLE ROW LEVEL SECURITY'),3)
        self.assertEqual(sql.count('FORCE ROW LEVEL SECURITY'),3)
        self.assertEqual(sql.count('CREATE POLICY'),3)
        self.assertIn('FOREIGN KEY (domain_id, owner_id)',sql)
        self.assertNotIn('SECURITY DEFINER',sql)


if __name__ == '__main__':
    unittest.main()
