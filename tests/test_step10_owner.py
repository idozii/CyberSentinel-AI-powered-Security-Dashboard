"""Step 10: authenticated, tenant-isolated DNS TXT ownership proof, no network calls."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from contextlib import closing
from unittest.mock import patch

from fastapi.testclient import TestClient

from owner_api.dns_verify import LookupUnavailable, lookup_txt
from owner_api.main import create_app
from owner_api.store import OwnerStore, normalize_domain, normalize_email, OwnerError


class OwnerAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "accounts" / "local.sqlite3"
        self.records = {}
        self.queries = []

        def fake_dns(name):
            self.queries.append(name)
            return self.records.get(name, [])

        self.client = TestClient(create_app(self.db, txt_lookup=fake_dns))

    def register(self, name, password="strong-password-1234"):
        return self.client.post("/owner/register", json={"email": name, "password": password})

    def login(self, email, password="strong-password-1234"):
        return self.client.post("/owner/login", json={"email": email, "password": password})

    def auth(self, name):
        self.assertEqual(self.register(name).status_code, 201)
        r = self.login(name)
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def add(self, header, name="owned-domain.net"):
        return self.client.post("/owner/domains", headers=header, json={"domain": name})

    def test_health_indicates_no_live_ingestion(self):
        r = self.client.get("/owner/health")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["live_monitoring"])

    def test_auth_required_all_owner_resources(self):
        for route in ("/owner/me", "/owner/domains"):
            self.assertEqual(self.client.get(route).status_code, 401)
        self.assertEqual(self.client.post("/owner/domains", json={"domain": "example.org"}).status_code, 401)

    def test_password_argon2id_and_session_is_hashed(self):
        headers = self.auth("FIRST@EXAMPLE.ORG")
        with closing(sqlite3.connect(self.db)) as conn, conn:
            password_hash = conn.execute("SELECT password_hash FROM users").fetchone()[0]
            token_hash = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
        self.assertIn("$argon2id$", password_hash)
        self.assertNotIn("strong-password-1234", password_hash)
        self.assertEqual(len(token_hash),64)
        self.assertNotEqual(token_hash,headers["Authorization"].split()[-1])
        self.assertEqual(self.client.get("/owner/me", headers=headers).json()["email"], "first@example.org")

    def test_no_duplicate_users_and_min_password(self):
        self.assertEqual(self.register("account@example.org").status_code,201)
        self.assertEqual(self.register("ACCOUNT@EXAMPLE.ORG").status_code,409)
        self.assertEqual(self.register("other@example.org", "tiny").status_code,422)
        self.assertEqual(self.register("bad-mail", "strong-password-1234").status_code,422)

    def test_failed_login_rate_limit_and_successful_login_reset(self):
        self.register("a@example.org")
        for _ in range(5):
            self.assertEqual(self.login("a@example.org", "wrong-password").status_code,401)
        self.assertEqual(self.login("a@example.org").status_code,401)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            locked = conn.execute("SELECT locked_until FROM users").fetchone()[0]
        self.assertGreater(locked,time.time())

    def test_logout_revokes_session(self):
        h = self.auth("a@example.org")
        self.assertEqual(self.client.post("/owner/logout",headers=h).status_code,204)
        self.assertEqual(self.client.get("/owner/me",headers=h).status_code,401)

    def test_expired_session_rejected(self):
        h = self.auth("a@example.org")
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE sessions SET expires_at=?", (time.time()-10,))
        self.assertEqual(self.client.get("/owner/me",headers=h).status_code,401)

    def test_domain_normalized_and_challenge_only_shown_at_issue(self):
        h = self.auth("a@example.org")
        claim = self.add(h,"My-Domain.NET.")
        self.assertEqual(claim.status_code,201)
        data=claim.json()
        self.assertEqual(data["domain"],"my-domain.net")
        self.assertEqual(data["txt_name"],"_cybersentinel-verify.my-domain.net")
        self.assertTrue(data["txt_value"].startswith("cybersentinel-verification="))
        record=self.client.get("/owner/domains",headers=h).json()["domains"][0]
        self.assertNotIn("txt_value",record)
        self.assertNotIn("challenge_hash",record)

    def test_domain_validator_rejects_local_private_and_urls(self):
        for bad in ["localhost", "foo.local", "127.0.0.1", "10.0.0.1", "http://example.org", "foo:443",
                    "foo..org", "foo.org/path", "foo.internal", "foo.test", "com", "☃.com", "foo.onion"]:
            with self.subTest(bad=bad):
                with self.assertRaises(OwnerError):
                    normalize_domain(bad)

    def test_domain_tenant_isolation(self):
        a = self.auth("a@example.org")
        b = self.auth("b@example.org")
        own = self.add(a).json()
        p = f"/owner/domains/{own['id']}"
        self.assertEqual(self.client.get("/owner/domains",headers=b).json()["domains"],[])
        self.assertEqual(self.client.post(p+"/verify",headers=b).status_code,404)
        self.assertEqual(self.client.post(p+"/rotate-challenge",headers=b).status_code,404)
        self.assertEqual(self.client.delete(p,headers=b).status_code,404)
        self.assertEqual(self.queries,[])

    def test_valid_dns_proof_verifies_domain(self):
        a=self.auth("a@example.org")
        d=self.add(a).json()
        self.records[d["txt_name"]]=["some-unrelated-txt",d["txt_value"]]
        r=self.client.post(f"/owner/domains/{d['id']}/verify",headers=a)
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()["verified"])
        self.assertEqual(self.queries,[d["txt_name"]])

    def test_wrong_dns_proof_does_not_verify(self):
        a=self.auth("a@example.org")
        d=self.add(a).json()
        self.records[d["txt_name"]]=["cybersentinel-verification=guessed"]
        self.assertEqual(self.client.post(f"/owner/domains/{d['id']}/verify",headers=a).status_code,422)
        self.assertFalse(self.client.get("/owner/domains",headers=a).json()["domains"][0]["verified"])

    def test_rotated_challenge_invalidates_old_dns_proof(self):
        a=self.auth("a@example.org")
        d=self.add(a).json()
        fresh=self.client.post(f"/owner/domains/{d['id']}/rotate-challenge",headers=a).json()
        self.records[d["txt_name"]]=[d["txt_value"]]
        self.assertEqual(self.client.post(f"/owner/domains/{d['id']}/verify",headers=a).status_code,422)
        self.records[d["txt_name"]]=[fresh["txt_value"]]
        self.assertEqual(self.client.post(f"/owner/domains/{d['id']}/verify",headers=a).status_code,200)

    def test_expired_challenge_rejected_without_dns_call(self):
        a=self.auth("a@example.org")
        d=self.add(a).json()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE domains SET challenge_expires_at=? WHERE id=?",(time.time()-1,d["id"]))
        self.assertEqual(self.client.post(f"/owner/domains/{d['id']}/verify",headers=a).status_code,409)
        self.assertEqual(self.queries,[])

    def test_multiple_pending_claims_but_only_one_verified_owner(self):
        a=self.auth("a@example.org")
        b=self.auth("b@example.org")
        da=self.add(a,"same-site.org").json()
        db=self.add(b,"same-site.org").json()
        self.records[da["txt_name"]]=[da["txt_value"]]
        self.assertEqual(self.client.post(f"/owner/domains/{da['id']}/verify",headers=a).status_code,200)
        self.records[db["txt_name"]]=[db["txt_value"]]
        self.assertEqual(self.client.post(f"/owner/domains/{db['id']}/verify",headers=b).status_code,409)
        self.assertFalse(self.client.get("/owner/domains",headers=b).json()["domains"][0]["verified"])

    def test_claim_delete_allows_new_verified_owner(self):
        a=self.auth("a@example.org")
        b=self.auth("b@example.org")
        da=self.add(a,"sharedsite.org").json()
        db=self.add(b,"sharedsite.org").json()
        self.records[da["txt_name"]]=[da["txt_value"]]
        self.client.post(f"/owner/domains/{da['id']}/verify",headers=a)
        self.assertEqual(self.client.delete(f"/owner/domains/{da['id']}",headers=a).status_code,204)
        self.records[db["txt_name"]]=[db["txt_value"]]
        self.assertEqual(self.client.post(f"/owner/domains/{db['id']}/verify",headers=b).status_code,200)

    def test_no_network_access_when_client_is_not_loopback(self):
        external=TestClient(create_app(self.db,txt_lookup=lambda _: []),client=("192.0.2.12",42112))
        self.assertEqual(external.get("/owner/health").status_code,403)

    def test_untrusted_host_rejected(self):
        self.assertEqual(self.client.get("/owner/health",headers={"Host":"security.example.com"}).status_code,400)

    def test_dns_lookup_timeout_is_controlled(self):
        with patch("owner_api.dns_verify.dns.resolver.resolve", side_effect=__import__("dns").exception.Timeout):
            with self.assertRaises(LookupUnavailable):
                lookup_txt("_cybersentinel-verify.owned.org")

    def test_sensitive_session_responses_are_no_store(self):
        self.register("secure@example.org")
        result = self.login("secure@example.org")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers.get("cache-control"), "no-store")
        self.assertEqual(result.headers.get("x-content-type-options"), "nosniff")

    def test_owner_database_is_blocked_from_git(self):
        from scripts.release_audit import unsafe_tracked_path
        self.assertTrue(unsafe_tracked_path("simulations/runtime/owner/owner_local.sqlite3"))
        self.assertTrue(unsafe_tracked_path("simulations/runtime/owner/owner_local.sqlite3-journal"))

    def test_default_db_permissions_restricted(self):
        if os.name != "posix":
            self.skipTest("POSIX-only file permission test")
        self.assertEqual(self.db.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.db.parent.stat().st_mode & 0o777,0o700)


if __name__=="__main__":
    unittest.main()
