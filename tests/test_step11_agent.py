"""Step 11: owner-isolated local telemetry ingestion, privacy adapter and key controls."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from owner_api.main import create_app
from cybersentinel_agent.client import AgentError, load_events, to_minimal_event, validate_local_server, send_events
from scripts.normalize_dashes import normalized


class AgentIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "owner" / "local.sqlite3"
        self.dns = {}
        self.client = TestClient(create_app(self.path, txt_lookup=lambda name: self.dns.get(name, [])))
        self.a = self.account("alice@mydomain.com")
        self.b = self.account("bob@mydomain.com")
        self.a_domain = self.domain(self.a, "alice-domain.org")
        self.b_domain = self.domain(self.b, "bob-domain.net")

    def account(self, email):
        r = self.client.post("/owner/register", json={"email": email, "password": "a-valid-password-12345"})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.post("/owner/login", json={"email": email, "password": "a-valid-password-12345"})
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def domain(self, auth, hostname):
        r = self.client.post("/owner/domains", headers=auth, json={"domain": hostname})
        self.assertEqual(r.status_code, 201)
        return r.json()

    def verify(self, auth, claim):
        self.dns[claim["txt_name"]] = [claim["txt_value"]]
        r = self.client.post(f"/owner/domains/{claim['id']}/verify", headers=auth)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def key(self, auth, domain_id, label="nginx-local"):
        r = self.client.post(f"/owner/domains/{domain_id}/agent-keys", json={"label": label}, headers=auth)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def event(self, **update):
        data = {"event_id": "abcd1234abcd1234abcd1234abcd1234", "occurred_at": int(time.time()),
                "source_ref": "a" * 32, "method": "GET", "path_group": "other",
                "status_code": 200, "duration_ms": 12.0, "request_bytes": 105,
                "response_bytes": 310}
        data.update(update)
        return data

    def push(self, key, did, events=None):
        return self.client.post("/agent/v1/ingest", json={"domain_id": did, "events": events or [self.event()]},
                                headers={"Authorization": "Bearer " + key})

    def test_health_marks_ingestion_not_live_detection(self):
        j = self.client.get("/owner/health").json()
        self.assertTrue(j["agent_ingestion"])
        self.assertFalse(j["live_monitoring"])

    def test_cannot_issue_key_before_verification(self):
        r = self.client.post(f"/owner/domains/{self.a_domain['id']}/agent-keys", headers=self.a, json={"label": "demo"})
        self.assertEqual(r.status_code, 409)

    def test_cannot_issue_key_for_other_owners_domain(self):
        self.verify(self.a, self.a_domain)
        r = self.client.post(f"/owner/domains/{self.a_domain['id']}/agent-keys", headers=self.b, json={"label": "demo"})
        self.assertEqual(r.status_code, 404)

    def test_key_returned_once_only_hash_stored(self):
        self.verify(self.a, self.a_domain)
        key = self.key(self.a, self.a_domain["id"])
        rows = self.client.get(f"/owner/domains/{self.a_domain['id']}/agent-keys", headers=self.a).json()["keys"]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("agent_key", rows[0])
        self.assertNotIn("token_hash", rows[0])
        with sqlite3.connect(self.path) as db:
            db_hash = db.execute("SELECT token_hash FROM agent_keys").fetchone()[0]
        self.assertEqual(len(db_hash), 64)
        self.assertNotEqual(db_hash, key["agent_key"])
        self.assertNotIn(key["agent_key"], self.path.read_bytes().decode("latin-1", errors="ignore"))

    def test_round_trip_and_idempotent_replay(self):
        self.verify(self.a, self.a_domain)
        key = self.key(self.a, self.a_domain["id"])
        r = self.push(key["agent_key"], self.a_domain["id"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["accepted"], 1)
        r = self.push(key["agent_key"], self.a_domain["id"])
        self.assertEqual(r.json()["duplicates"], 1)
        j = self.client.get(f"/owner/domains/{self.a_domain['id']}/telemetry", headers=self.a).json()
        self.assertEqual(j["total_events"], 1)
        self.assertNotIn("uri", j["events"][0])
        self.assertNotIn("remote_addr", j["events"][0])
        self.assertNotIn("password", j["events"][0])

    def test_bad_key_and_wrong_domain_cannot_ingest(self):
        self.verify(self.a, self.a_domain)
        self.verify(self.b, self.b_domain)
        key = self.key(self.a, self.a_domain["id"])
        self.assertEqual(self.push(key["agent_key"], self.b_domain["id"]).status_code, 401)
        self.assertEqual(self.push("csa_"+"y"*45, self.a_domain["id"]).status_code, 401)
        self.assertEqual(self.client.get(f"/owner/domains/{self.b_domain['id']}/telemetry", headers=self.b).json()["total_events"],0)

    def test_other_owner_cannot_read_or_revoke(self):
        self.verify(self.a, self.a_domain)
        key = self.key(self.a, self.a_domain["id"])
        url = f"/owner/domains/{self.a_domain['id']}"
        self.assertEqual(self.client.get(url+"/telemetry", headers=self.b).status_code, 404)
        self.assertEqual(self.client.get(url+"/agent-keys", headers=self.b).status_code, 404)
        self.assertEqual(self.client.delete(url+"/agent-keys/"+key["id"], headers=self.b).status_code, 404)

    def test_revocation_blocks_ingest_and_domain_delete_cascades(self):
        self.verify(self.a, self.a_domain)
        key = self.key(self.a, self.a_domain["id"])
        self.assertEqual(self.push(key["agent_key"],self.a_domain["id"]).status_code,200)
        url = f"/owner/domains/{self.a_domain['id']}/agent-keys/{key['id']}"
        self.assertEqual(self.client.delete(url,headers=self.a).status_code,204)
        self.assertEqual(self.push(key["agent_key"],self.a_domain["id"]).status_code,401)
        self.assertEqual(self.client.delete(f"/owner/domains/{self.a_domain['id']}",headers=self.a).status_code,204)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0],0)

    def test_passwords_cookies_raw_ip_and_url_rejected_by_schema(self):
        self.verify(self.a,self.a_domain)
        key=self.key(self.a,self.a_domain["id"])
        for field in ("password", "cookie", "remote_addr", "request_uri", "query", "raw"):
            ev=self.event(**{field:"private"})
            self.assertEqual(self.push(key["agent_key"],self.a_domain["id"],[ev]).status_code,422)
        self.assertEqual(self.client.get(f"/owner/domains/{self.a_domain['id']}/telemetry",headers=self.a).json()["total_events"],0)

    def test_future_old_invalid_types_and_category_rejected(self):
        self.verify(self.a,self.a_domain)
        key=self.key(self.a,self.a_domain["id"])
        for ev in [self.event(occurred_at=int(time.time())-600), self.event(status_code=999),
                   self.event(source_ref="127.0.0.1"), self.event(path_group="../../../etc"),
                   self.event(status_code="200")]:
            self.assertEqual(self.push(key["agent_key"],self.a_domain["id"],[ev]).status_code,422)

    def test_limit_body_and_batch_size(self):
        self.verify(self.a,self.a_domain)
        key=self.key(self.a,self.a_domain["id"])
        events=[self.event(event_id=f"ev{'a'*30}{i}") for i in range(26)]
        self.assertEqual(self.push(key["agent_key"],self.a_domain["id"],events).status_code,422)
        data=b"a"*40000
        r=self.client.post("/agent/v1/ingest",data=data,headers={"Authorization":"Bearer "+key["agent_key"]})
        self.assertEqual(r.status_code,413)
        self.assertEqual(self.client.get(f"/owner/domains/{self.a_domain['id']}/telemetry?limit=200",headers=self.a).status_code,422)

    def test_key_count_limit(self):
        self.verify(self.a,self.a_domain)
        for i in range(3):
            self.key(self.a,self.a_domain["id"],f"agent-{i}")
        r=self.client.post(f"/owner/domains/{self.a_domain['id']}/agent-keys",headers=self.a,json={"label":"overflow"})
        self.assertEqual(r.status_code,429)

    def test_externally_supplied_client_rejected(self):
        external=TestClient(create_app(self.path,txt_lookup=lambda _ : []),client=("192.0.2.5",5000))
        self.assertEqual(external.post("/agent/v1/ingest").status_code,403)

    def test_agent_never_sends_raw_identifiers(self):
        row={"time_iso8601":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
             "remote_addr":"203.0.113.3","request_method":"POST","uri":"/login?password=private",
             "status":"401","request_time":"0.032","request_length":"143","bytes_sent":"320",
             "request_id":"0123456789abcdef0123456789abcdef","http_cookie":"secret123","http_user_agent":"private-agent"}
        transformed=to_minimal_event(row,"csa_"+"z"*43)
        self.assertEqual(transformed["path_group"],"login")
        self.assertEqual(transformed["status_code"],401)
        self.assertEqual(transformed["duration_ms"],32.0)
        text=json.dumps(transformed)
        for secret in ("203.0.113.3","password","private","uri","http_cookie","request_id"):
            self.assertNotIn(secret,text)
        self.assertEqual(len(transformed["source_ref"]),32)

    def test_agent_deterministic_event_ids_and_daily_pseudonyms(self):
        stamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        row={"time_iso8601":stamp,"remote_addr":"198.51.100.2","request_method":"GET","uri":"/health",
             "status":"200","request_time":"0.01","request_id":"abcdefghijklmnop"}
        a=to_minimal_event(row,"csa_"+"z"*43)
        b=to_minimal_event(row,"csa_"+"z"*43)
        self.assertEqual(a,b)
        self.assertNotEqual(a["source_ref"],to_minimal_event(row,"csa_"+"y"*43)["source_ref"])

    def test_local_agent_rejects_remote_or_redirecting_server(self):
        for site in ["https://example.com", "http://192.168.1.10:8002", "http://127.0.0.1:8003",
                     "http://127.0.0.1:8002@evil.example", "http://localhost:8002",
                     "http://127.0.0.1:8002/private"]:
            with self.subTest(site=site), self.assertRaises(AgentError):
                validate_local_server(site)
        self.assertEqual(validate_local_server("http://127.0.0.1:8002"),"http://127.0.0.1:8002")

    def test_log_reader_does_not_include_extra_fields(self):
        now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        row={"time_iso8601":now,"remote_addr":"192.0.2.1","request_method":"GET",
             "uri":"/health?token=x","status":"200","request_time":"0.0",
             "request_id":"12345678abcdefgh","http_cookie":"top-secret"}
        path=Path(self.temp.name)/"logs.jsonl"
        path.write_text(json.dumps(row)+"\n")
        got=load_events(path,"csa_"+"k"*43)
        self.assertEqual(len(got),1)
        self.assertNotIn("top-secret",json.dumps(got))

    def test_unicode_dash_normalization_preserves_cli_flags(self):
        self.assertEqual(normalized("hello \u2014 world \u2013 others --host"),"hello - world - others --host")

if __name__=="__main__":
    unittest.main()
