"""Step 12: isolated owner alerts from real (but simulated/local) telemetry."""
from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from owner_api.main import create_app


class RuleAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "owner.sqlite3"
        self.dns = {}
        self.client = TestClient(create_app(self.db, txt_lookup=lambda name: self.dns.get(name, [])))
        self.owners = [self._register("alice@demo.com"), self._register("bob@demo.com")]
        self.domains = [self._domain(self.owners[0], "alice-demo.org"), self._domain(self.owners[1], "bob-demo.org")]
        self.keys = [self._key(self.owners[i], self.domains[i]) for i in (0, 1)]
        self.current_window = (int(time.time()) // 60) * 60
        self.timepoint = int(time.time())

    def _register(self, email):
        r = self.client.post("/owner/register", json={"email": email, "password": "correct-long-password-123"})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.post("/owner/login", json={"email": email, "password": "correct-long-password-123"})
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def _domain(self, owner, hostname):
        r = self.client.post("/owner/domains", headers=owner, json={"domain": hostname})
        self.assertEqual(r.status_code, 201, r.text)
        d = r.json()
        self.dns[d["txt_name"]] = [d["txt_value"]]
        r = self.client.post(f"/owner/domains/{d['id']}/verify", headers=owner)
        self.assertEqual(r.status_code, 200, r.text)
        return d["id"]

    def _key(self, owner, did):
        r = self.client.post(f"/owner/domains/{did}/agent-keys", headers=owner, json={"label": "nginx"})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["agent_key"]

    def event(self, n, *, code=401, group="login", source="a" * 32, when=None):
        return {"event_id": "cs" + f"{n:030d}", "occurred_at": int(when or self.timepoint),
                "source_ref": source, "method": "POST" if group == "login" else "GET",
                "path_group": group, "status_code": code, "duration_ms": 10.0,
                "request_bytes": 130, "response_bytes": 260}

    def push(self, events, owner=0):
        return self.client.post("/agent/v1/ingest", headers={"Authorization": "Bearer " + self.keys[owner]},
                                json={"domain_id": self.domains[owner], "events": events})

    def alerts(self, owner=0, did=None, params=None):
        did = did or self.domains[owner]
        return self.client.get(f"/owner/domains/{did}/alerts", headers=self.owners[owner], params=params)

    def test_health_does_not_claim_24_hour_monitoring(self):
        result = self.client.get("/owner/health").json()
        self.assertTrue(result["local_rule_alerts"])
        self.assertFalse(result["live_monitoring"])

    def test_no_alert_before_login_threshold(self):
        self.assertEqual(self.push([self.event(i) for i in range(4)]).status_code, 200)
        self.assertEqual(self.alerts().json()["total_alerts"], 0)

    def test_five_failed_logins_create_explainable_alert(self):
        r = self.push([self.event(i) for i in range(5)])
        self.assertEqual(r.status_code, 200, r.text)
        body = self.alerts().json()
        self.assertEqual(body["total_alerts"], 1)
        alert = body["alerts"][0]
        self.assertEqual(alert["rule_id"], "repeated_login_failures")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["observed_count"], 5)
        self.assertEqual(alert["threshold_count"], 5)
        self.assertEqual(alert["status"], "open")
        self.assertNotIn("password", str(alert).lower())

    def test_more_events_update_same_alert_without_duplicate(self):
        first = self.push([self.event(i) for i in range(5)])
        self.assertEqual(first.status_code, 200)
        first_alert = self.alerts().json()["alerts"][0]
        more = self.push([self.event(i) for i in range(5, 7)])
        self.assertEqual(more.json()["alerts_updated"], 1)
        rows = self.alerts().json()["alerts"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], first_alert["id"])
        self.assertEqual(rows[0]["observed_count"], 7)

    def test_replayed_events_do_not_trigger_extra_alerts(self):
        events = [self.event(i) for i in range(5)]
        self.assertEqual(self.push(events).json()["alerts_updated"], 1)
        duplicate = self.push(events)
        self.assertEqual(duplicate.json()["accepted"], 0)
        self.assertEqual(duplicate.json()["duplicates"], 5)
        self.assertEqual(duplicate.json()["alerts_updated"], 0)
        self.assertEqual(self.alerts().json()["total_alerts"], 1)

    def test_404_burst_is_not_called_confirmed_scan(self):
        self.assertEqual(self.push([self.event(i, code=404, group="other") for i in range(8)]).status_code, 200)
        row = self.alerts().json()["alerts"][0]
        self.assertEqual(row["rule_id"], "http_404_burst")
        self.assertIn("Could be normal", row["explanation"])

    def test_server_errors_generate_alert(self):
        self.assertEqual(self.push([self.event(i, code=503, group="api") for i in range(5)]).status_code, 200)
        self.assertEqual(self.alerts().json()["alerts"][0]["rule_id"], "server_error_burst")

    def test_high_volume_across_bounded_batches(self):
        for part in (range(0, 20), range(20, 40)):
            r = self.push([self.event(i, code=200, group="health") for i in part])
            self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.alerts().json()["alerts"][0]["rule_id"], "request_volume_spike")

    def test_sources_do_not_merge(self):
        self.push([self.event(i, source="a" * 32) for i in range(3)] +
                  [self.event(i + 100, source="b" * 32) for i in range(3)])
        self.assertEqual(self.alerts().json()["total_alerts"], 0)

    def test_separate_windows_do_not_merge(self):
        # Occurred_at is bounded by +/-5 minutes. Use adjacent minute windows.
        earlier = self.current_window - 60 + 10
        later = self.current_window + 10
        if later > int(time.time()) + 300:
            self.skipTest("Local wall clock unexpectedly distant")
        rows = [self.event(i, when=earlier) for i in range(3)] + \
               [self.event(i + 100, when=later) for i in range(3)]
        self.assertEqual(self.push(rows).status_code, 200)
        self.assertEqual(self.alerts().json()["total_alerts"], 0)

    def test_domain_isolation_and_cross_owner_read_denied(self):
        self.push([self.event(i) for i in range(5)])
        self.assertEqual(self.alerts(owner=1).json()["total_alerts"], 0)
        self.assertEqual(self.alerts(owner=1, did=self.domains[0]).status_code, 404)
        self.assertEqual(self.alerts(owner=0, did=self.domains[1]).status_code, 404)
        self.assertEqual(self.client.get(f"/owner/domains/{self.domains[0]}/alerts").status_code, 401)

    def test_acknowledge_idempotent_and_tenant_scoped(self):
        self.push([self.event(i) for i in range(5)])
        row = self.alerts().json()["alerts"][0]
        url = f"/owner/domains/{self.domains[0]}/alerts/{row['id']}/acknowledge"
        self.assertEqual(self.client.post(url, headers=self.owners[1]).status_code, 404)
        self.assertEqual(self.client.post(url, headers=self.owners[0]).json()["status"], "acknowledged")
        self.assertEqual(self.client.post(url, headers=self.owners[0]).json()["status"], "acknowledged")
        self.assertEqual(self.alerts(params={"status": "open"}).json()["total_alerts"], 0)
        self.assertEqual(self.alerts(params={"status": "acknowledged"}).json()["total_alerts"], 1)
        self.push([self.event(i) for i in range(5, 7)])
        self.assertEqual(self.alerts().json()["alerts"][0]["status"], "acknowledged")

    def test_invalid_query_limits_and_unknown_id_rejected(self):
        self.assertEqual(self.alerts(params={"status": "forged"}).status_code, 422)
        self.assertEqual(self.alerts(params={"limit": 101}).status_code, 422)
        self.assertEqual(self.alerts(params={"limit": 0}).status_code, 422)
        self.assertEqual(self.client.post(f"/owner/domains/{self.domains[0]}/alerts/../acknowledge",
                                          headers=self.owners[0]).status_code in (404, 405), True)

    def test_alerts_cascade_when_domain_deleted(self):
        self.push([self.event(i) for i in range(5)])
        self.assertEqual(self.client.delete(f"/owner/domains/{self.domains[0]}",headers=self.owners[0]).status_code, 204)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM detection_alerts").fetchone()[0], 0)

    def test_revoked_agent_cannot_generate_alerts(self):
        key_list = self.client.get(f"/owner/domains/{self.domains[0]}/agent-keys",
                                   headers=self.owners[0]).json()["keys"]
        kid = key_list[0]["id"]
        self.assertEqual(self.client.delete(f"/owner/domains/{self.domains[0]}/agent-keys/{kid}",
                                            headers=self.owners[0]).status_code, 204)
        self.assertEqual(self.push([self.event(i) for i in range(5)]).status_code, 401)
        self.assertEqual(self.alerts().json()["total_alerts"], 0)


if __name__ == "__main__":
    unittest.main()
