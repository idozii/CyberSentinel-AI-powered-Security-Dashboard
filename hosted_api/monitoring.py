"""Tenant-scoped PostgreSQL agent keys, minimal events and explainable alerts.

Private staging only. Never use a migration/owner DSN for this store.
An agent token includes an untrusted owner UUID prefix solely to select an RLS
actor; bearer authorization always requires an exact SHA-256 match in that actor's
verified domain. No SECURITY DEFINER functions or role switching.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
import uuid
from datetime import datetime, timezone

from hosted_api.identity import Identity
from hosted_api.postgres import HostedError, HostedStore, identity_id
from owner_api.detection import RULES, WINDOW_SECONDS
from owner_api.telemetry import MAX_ACTIVE_KEYS, MAX_EVENTS_PER_BATCH, MAX_EVENTS_PER_MINUTE, RETENTION_SECONDS

TOKEN_RE = re.compile(r'^csp_([a-f0-9]{32})_([A-Za-z0-9_-]{40,64})$')
LABEL_RE = re.compile(r'^[\x20-\x7e]{1,64}$')
EVENT_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')
SOURCE_RE = re.compile(r'^[a-f0-9]{32}$')
METHODS = frozenset({'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'})
GROUPS = frozenset({'login','health','admin','api','other'})
TITLES = {
    'repeated_login_failures': 'Repeated login failures',
    'http_404_burst': 'HTTP 404 response burst',
    'server_error_burst': 'HTTP 5xx error burst',
    'request_volume_spike': 'High request volume',
}


def validate_events(events: list[dict], now: float) -> None:
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS_PER_BATCH:
        raise HostedError('Batch must contain 1..25 events', 422)
    expected = {'event_id','occurred_at','source_ref','method','path_group','status_code',
                'duration_ms','request_bytes','response_bytes'}
    import math
    for e in events:
        if not isinstance(e, dict) or set(e) != expected:
            raise HostedError('Unexpected telemetry fields', 422)
        if (not isinstance(e['event_id'], str) or not EVENT_RE.fullmatch(e['event_id'])
                or not isinstance(e['source_ref'], str) or not SOURCE_RE.fullmatch(e['source_ref'])
                or e['method'] not in METHODS or e['path_group'] not in GROUPS):
            raise HostedError('Invalid telemetry category', 422)
        if (type(e['occurred_at']) is not int or abs(e['occurred_at'] - now) > 300
                or type(e['status_code']) is not int or not 100 <= e['status_code'] <= 599):
            raise HostedError('Event outside allowed time or status range', 422)
        if (type(e['duration_ms']) not in (int,float) or not math.isfinite(e['duration_ms'])
                or not 0 <= e['duration_ms'] <= 120000):
            raise HostedError('Invalid event duration', 422)
        for key in ('request_bytes','response_bytes'):
            if type(e[key]) is not int or not 0 <= e[key] <= 100000000:
                raise HostedError('Invalid event size', 422)


class MonitoringStore(HostedStore):
    @staticmethod
    def _domain(conn, owner: uuid.UUID, did: uuid.UUID):
        row = conn.execute('''SELECT id,domain FROM cs.domains
            WHERE id=%s AND owner_id=%s AND verified_at IS NOT NULL''', (did,owner)).fetchone()
        if not row:
            raise HostedError('Verified domain not found', 404)
        return row

    def issue_key(self, subject: Identity, domain_id: uuid.UUID, label: str) -> dict:
        if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
            raise HostedError('Invalid agent key label', 422)
        owner = identity_id(subject)
        token = f'csp_{owner.hex}_{secrets.token_urlsafe(32)}'
        digest = hashlib.sha256(token.encode()).hexdigest()
        key_id = uuid.uuid4()
        with self._connect() as conn:
            self._set_actor(conn, owner)
            self._domain(conn, owner, domain_id)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s, 18))', (str(domain_id),))
            active = conn.execute('''SELECT count(*) AS n FROM cs.agent_keys
                WHERE owner_id=%s AND domain_id=%s AND revoked_at IS NULL''', (owner,domain_id)).fetchone()['n']
            if active >= MAX_ACTIVE_KEYS:
                raise HostedError('Maximum active agent keys reached', 429)
            conn.execute('''INSERT INTO cs.agent_keys (id,owner_id,domain_id,token_hash,label)
                VALUES (%s,%s,%s,%s,%s)''', (key_id,owner,domain_id,digest,label))
        return {'id':str(key_id),'label':label,'domain_id':str(domain_id),
                'agent_key':token,'notice':'Copy once. Only the SHA-256 digest is stored.'}

    def list_keys(self, subject: Identity, domain_id: uuid.UUID) -> list[dict]:
        owner = identity_id(subject)
        with self._connect() as conn:
            self._set_actor(conn, owner)
            self._domain(conn, owner, domain_id)
            rows = conn.execute('''SELECT id,label,created_at,last_used_at
                FROM cs.agent_keys WHERE domain_id=%s AND owner_id=%s AND revoked_at IS NULL
                ORDER BY created_at DESC''', (domain_id,owner)).fetchall()
        return [{'id':str(r['id']), 'label':r['label'],
                 'created_at':r['created_at'].isoformat(),
                 'last_used_at':r['last_used_at'].isoformat() if r['last_used_at'] else None}
                for r in rows]

    def revoke_key(self, subject: Identity, domain_id: uuid.UUID, key_id: uuid.UUID):
        owner = identity_id(subject)
        with self._connect() as conn:
            self._set_actor(conn, owner)
            self._domain(conn, owner, domain_id)
            changed = conn.execute('''UPDATE cs.agent_keys SET revoked_at=now()
                WHERE id=%s AND owner_id=%s AND domain_id=%s AND revoked_at IS NULL''',
                (key_id,owner,domain_id))
            if changed.rowcount != 1:
                raise HostedError('Active agent key not found',404)

    def ingest(self, token: str, domain_id: uuid.UUID, events: list[dict]) -> dict:
        now = time.time()
        validate_events(events, now)
        match = TOKEN_RE.fullmatch(token) if isinstance(token,str) else None
        if not match:
            raise HostedError('Invalid agent credentials',401)
        owner = uuid.UUID(hex=match.group(1))
        digest = hashlib.sha256(token.encode()).hexdigest()
        accepted = duplicates = updated = 0
        windows = set()
        with self._connect() as conn:
            self._set_actor(conn, owner)
            # RLS and exact token digest BOTH apply. FOR UPDATE prevents concurrent revoke
            # from completing while this authenticated ingest transaction is active.
            key = conn.execute('''SELECT id FROM cs.agent_keys WHERE owner_id=%s
                AND domain_id=%s AND token_hash=%s AND revoked_at IS NULL
                AND EXISTS (SELECT 1 FROM cs.domains WHERE id=%s AND owner_id=%s AND verified_at IS NOT NULL)
                FOR UPDATE''', (owner,domain_id,digest,domain_id,owner)).fetchone()
            if key is None:
                raise HostedError('Invalid agent credentials or domain',401)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,18))', (str(domain_id),))
            # Bounded retention of the authenticated owner's domain only.
            conn.execute('''DELETE FROM cs.telemetry_events WHERE owner_id=%s AND domain_id=%s
                AND received_at < now() - interval '7 days' ''', (owner,domain_id))
            conn.execute('''DELETE FROM cs.detection_alerts WHERE owner_id=%s AND domain_id=%s
                AND window_start < %s''', (owner,domain_id,int(now)-RETENTION_SECONDS))
            count = conn.execute('''SELECT count(*) AS n FROM cs.telemetry_events
                WHERE owner_id=%s AND domain_id=%s AND received_at >= now() - interval '60 seconds' ''',
                (owner,domain_id)).fetchone()['n']
            if count + len(events) > MAX_EVENTS_PER_MINUTE:
                raise HostedError('Telemetry rate limit reached',429)
            for ev in events:
                inserted = conn.execute('''INSERT INTO cs.telemetry_events
                    (id,owner_id,domain_id,agent_event_id,occurred_at,source_ref,method,path_group,
                     status_code,duration_ms,request_bytes,response_bytes)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (domain_id,agent_event_id) DO NOTHING RETURNING id''',
                    (uuid.uuid4(),owner,domain_id,ev['event_id'],ev['occurred_at'],ev['source_ref'],
                     ev['method'],ev['path_group'],ev['status_code'],ev['duration_ms'],
                     ev['request_bytes'],ev['response_bytes'])).fetchone()
                if inserted:
                    accepted += 1
                    windows.add((ev['source_ref'], (ev['occurred_at']//WINDOW_SECONDS)*WINDOW_SECONDS))
                else:
                    duplicates += 1
            for source, start in sorted(windows):
                totals = conn.execute('''SELECT count(*) AS requests,
                    count(*) FILTER(WHERE path_group='login' AND status_code=401) AS failed_logins,
                    count(*) FILTER(WHERE status_code=404) AS http_404,
                    count(*) FILTER(WHERE status_code BETWEEN 500 AND 599) AS http_5xx
                    FROM cs.telemetry_events WHERE owner_id=%s AND domain_id=%s AND source_ref=%s
                        AND occurred_at >= %s AND occurred_at < %s''',
                    (owner,domain_id,source,start,start+WINDOW_SECONDS)).fetchone()
                for rule_id, threshold, counter, severity, explanation in RULES:
                    if totals[counter] < threshold:
                        continue
                    affected = conn.execute('''INSERT INTO cs.detection_alerts
                        (id,owner_id,domain_id,source_ref,window_start,rule_id,severity,title,
                         explanation,observed_count,threshold_count)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (domain_id,source_ref,window_start,rule_id)
                        DO UPDATE SET observed_count=EXCLUDED.observed_count,updated_at=now()
                        WHERE cs.detection_alerts.observed_count < EXCLUDED.observed_count''',
                        (uuid.uuid4(),owner,domain_id,source,start,rule_id,severity,TITLES[rule_id],
                         explanation,totals[counter],threshold))
                    updated += affected.rowcount
            conn.execute('UPDATE cs.agent_keys SET last_used_at=now() WHERE id=%s AND owner_id=%s',
                         (key['id'],owner))
        return {'accepted':accepted,'duplicates':duplicates,'alerts_updated':updated,'domain_id':domain_id.hex}

    def recent(self, subject: Identity, domain_id: uuid.UUID, limit: int = 50) -> dict:
        if not 1 <= limit <= 100:
            raise HostedError('Invalid event limit',422)
        owner = identity_id(subject)
        with self._connect() as conn:
            self._set_actor(conn, owner)
            self._domain(conn, owner, domain_id)
            rows = conn.execute('''SELECT agent_event_id,occurred_at,received_at,source_ref,method,
                path_group,status_code,duration_ms,request_bytes,response_bytes
                FROM cs.telemetry_events WHERE owner_id=%s AND domain_id=%s
                ORDER BY received_at DESC,id DESC LIMIT %s''', (owner,domain_id,limit)).fetchall()
            count = conn.execute('''SELECT count(*) AS n FROM cs.telemetry_events
                WHERE owner_id=%s AND domain_id=%s''', (owner,domain_id)).fetchone()['n']
        return {'domain_id':domain_id.hex,'total_events':count,'events':[
                {**r,'received_at':r['received_at'].timestamp()} for r in rows]}

    def list_alerts(self, subject: Identity, domain_id: uuid.UUID,
                    limit: int = 50, status: str | None = None) -> dict:
        if not 1 <= limit <= 100 or status not in (None,'open','acknowledged'):
            raise HostedError('Invalid alert filter',422)
        owner = identity_id(subject)
        with self._connect() as conn:
            self._set_actor(conn, owner)
            self._domain(conn, owner, domain_id)
            rows = conn.execute('''SELECT id,rule_id,severity,title,explanation,source_ref,
                window_start,observed_count,threshold_count,status,first_detected_at,
                updated_at,acknowledged_at FROM cs.detection_alerts
                WHERE owner_id=%s AND domain_id=%s AND (%s::text IS NULL OR status=%s)
                ORDER BY window_start DESC,first_detected_at DESC,id DESC LIMIT %s''',
                (owner,domain_id,status,status,limit)).fetchall()
            total = conn.execute('''SELECT count(*) AS n FROM cs.detection_alerts WHERE
                owner_id=%s AND domain_id=%s AND (%s::text IS NULL OR status=%s)''',
                (owner,domain_id,status,status)).fetchone()['n']
        return {'domain_id':domain_id.hex,'total_alerts':total,'alerts':[
            {**r, 'id':str(r['id']),
             'first_detected_at':r['first_detected_at'].timestamp(),
             'updated_at':r['updated_at'].timestamp(),
             'acknowledged_at':r['acknowledged_at'].timestamp() if r['acknowledged_at'] else None}
            for r in rows]}

    def acknowledge(self, subject: Identity, domain_id: uuid.UUID, alert_id: uuid.UUID) -> dict:
        owner = identity_id(subject)
        with self._connect() as conn:
            self._set_actor(conn,owner)
            self._domain(conn,owner,domain_id)
            row = conn.execute('''UPDATE cs.detection_alerts SET status='acknowledged',
                acknowledged_at=COALESCE(acknowledged_at,now())
                WHERE id=%s AND owner_id=%s AND domain_id=%s
                RETURNING id,status,acknowledged_at''',
                (alert_id,owner,domain_id)).fetchone()
            if row is None:
                raise HostedError('Alert not found',404)
        return {'id':str(row['id']),'status':row['status'],
                'acknowledged_at':row['acknowledged_at'].timestamp()}
