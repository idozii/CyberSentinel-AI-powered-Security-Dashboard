"""Tenant-scoped PostgreSQL staging repository.

Runtime role must be cybersentinel_runtime, without BYPASSRLS or ownership.
All tenant transactions set actor_id with is_local=true; no session pooling leak.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from owner_api.store import normalize_domain, OwnerError
from hosted_api.identity import Identity

NAMESPACE = uuid.UUID('7d4931ca-54cf-485b-96d0-d9b36bbca703')


class HostedError(ValueError):
    def __init__(self, detail: str, code: int = 400):
        super().__init__(detail)
        self.code = code


def identity_id(identity: Identity) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, identity.issuer + '\x00' + identity.subject)


class HostedStore:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def _connect(self):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(self.dsn, connect_timeout=4, row_factory=dict_row)

    @staticmethod
    def _set_actor(conn, uid: uuid.UUID):
        role = conn.execute('''SELECT current_user AS name, rolsuper, rolbypassrls
                               FROM pg_roles WHERE rolname=current_user''').fetchone()
        if role['name'] != 'cybersentinel_runtime' or role['rolsuper'] or role['rolbypassrls']:
            raise HostedError('Unsafe PostgreSQL application role', 503)
        conn.execute("SELECT set_config('cs.actor_id', %s, true)", (str(uid),))

    def ensure_identity(self, identity: Identity) -> dict:
        uid = identity_id(identity)
        with self._connect() as conn:
            self._set_actor(conn, uid)
            result = conn.execute('''INSERT INTO cs.identities(id, issuer, subject) VALUES (%s,%s,%s)
                ON CONFLICT (issuer, subject) DO UPDATE SET last_seen_at=now()
                RETURNING id''', (uid, identity.issuer, identity.subject)).fetchone()
            if result['id'] != uid:
                raise HostedError('Unexpected identity mapping', 500)
        return {'id': str(uid)}

    def list_domains(self, identity: Identity) -> list[dict]:
        uid = identity_id(identity)
        with self._connect() as conn:
            self._set_actor(conn, uid)
            rows = conn.execute('''SELECT id, domain, verified_at FROM cs.domains
                                   WHERE owner_id=%s ORDER BY domain''', (uid,)).fetchall()
            return [{'id': str(r['id']), 'domain': r['domain'],
                     'verified': r['verified_at'] is not None} for r in rows]

    def create_domain(self, identity: Identity, domain: str) -> dict:
        from psycopg.errors import UniqueViolation
        try:
            normalized = normalize_domain(domain)
        except OwnerError as exc:
            raise HostedError(str(exc), exc.status) from exc
        uid = identity_id(identity)
        did = uuid.uuid4()
        token = 'cybersentinel-verification=' + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        try:
            with self._connect() as conn:
                self._set_actor(conn, uid)
                conn.execute('''INSERT INTO cs.domains(id,owner_id,domain,challenge_hash,challenge_expires_at)
                                VALUES (%s,%s,%s,%s,%s)''',
                             (did, uid, normalized, digest, expiry))
        except UniqueViolation as exc:
            raise HostedError('Domain already added', 409) from exc
        return {'id': str(did), 'domain': normalized, 'verified': False,
                'txt_name': '_cybersentinel-verify.' + normalized,
                'txt_value': token, 'expires_at': expiry.isoformat()}

    def pending_proof(self, identity: Identity, domain_id: uuid.UUID) -> dict:
        uid = identity_id(identity)
        with self._connect() as conn:
            self._set_actor(conn, uid)
            row = conn.execute('''SELECT domain,challenge_hash,challenge_expires_at,verified_at
                                  FROM cs.domains WHERE id=%s AND owner_id=%s''',
                               (domain_id,uid)).fetchone()
        if row is None:
            raise HostedError('Domain not found', 404)
        if row['verified_at'] is not None:
            return {'domain': row['domain'], 'already_verified': True}
        if not row['challenge_hash'] or not row['challenge_expires_at'] or row['challenge_expires_at'] <= datetime.now(timezone.utc):
            raise HostedError('Challenge expired - request a new domain claim', 409)
        return {'domain': row['domain'], 'challenge_hash': row['challenge_hash']}

    def confirm_proof(self, identity: Identity, domain_id: uuid.UUID, expected_digest: str) -> dict:
        from psycopg.errors import UniqueViolation
        uid = identity_id(identity)
        try:
            with self._connect() as conn:
                self._set_actor(conn, uid)
                row = conn.execute('''UPDATE cs.domains SET verified_at=now(), challenge_hash=NULL,
                                       challenge_expires_at=NULL
                     WHERE id=%s AND owner_id=%s AND verified_at IS NULL AND challenge_hash=%s
                     AND challenge_expires_at > now() RETURNING id,domain,verified_at''',
                                   (domain_id, uid, expected_digest)).fetchone()
                if row is None:
                    raise HostedError('Challenge changed or expired', 409)
        except UniqueViolation as exc:
            raise HostedError('Domain already verified by another owner', 409) from exc
        return {'id': str(row['id']), 'domain': row['domain'], 'verified': True}

    def verify_domain(self, identity: Identity, domain_id: uuid.UUID, lookup) -> dict:
        from owner_api.dns_verify import LookupUnavailable
        proof = self.pending_proof(identity, domain_id)
        if proof.get('already_verified'):
            return {'id': str(domain_id), 'domain': proof['domain'], 'verified': True}
        try:
            records = lookup('_cybersentinel-verify.' + proof['domain'])
        except LookupUnavailable as exc:
            raise HostedError('DNS lookup unavailable', 503) from exc
        if not isinstance(records, list):
            raise HostedError('Invalid DNS lookup result', 503)
        matched = any(isinstance(t, str) and hmac.compare_digest(
            hashlib.sha256(t.encode()).hexdigest(), proof['challenge_hash']) for t in records[:30])
        if not matched:
            raise HostedError('DNS proof not found', 422)
        return self.confirm_proof(identity, domain_id, proof['challenge_hash'])
