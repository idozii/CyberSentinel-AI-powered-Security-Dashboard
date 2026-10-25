"""Synthetic read/update canary over Step 47's five-table tenant RLS.

No FastAPI route, public ingress, real OIDC tokens, external secrets or Neon.
Request inputs never specify owner_id, DB role, database URL or policy GUC.
"""
from __future__ import annotations

import uuid

from scripts.step49_credential_broker import DisposableCredentialBroker


class IsolatedApplicationCanary:
    def __init__(self, broker: DisposableCredentialBroker):
        self._broker = broker

    def overview(self, token: str) -> dict:
        """A simplified owner dashboard query, under PostgreSQL login RLS."""
        with self._broker.session(token) as db:
            domains = db.execute('SELECT id,domain FROM cs.domains ORDER BY domain').fetchall()
            alerts = db.execute('SELECT id,status FROM cs.detection_alerts ORDER BY id').fetchall()
            events = db.execute('SELECT count(*) FROM cs.telemetry_events').fetchone()[0]
            keys = db.execute('SELECT count(*) FROM cs.agent_keys').fetchone()[0]
            identities = db.execute('SELECT count(*) FROM cs.identities').fetchone()[0]
        return {
            'domains': [{'id': str(ident), 'domain': domain} for ident, domain in domains],
            'alerts': [{'id': str(ident), 'status': status} for ident, status in alerts],
            'events': events,
            'agent_keys': keys,
            'identities': identities,
        }

    def acknowledge(self, token: str, alert_id: uuid.UUID) -> bool:
        """RLS rejects another tenant's alert even with a known UUID."""
        if type(alert_id) is not uuid.UUID:
            raise ValueError('Invalid alert identifier')
        with self._broker.session(token) as db:
            changed = db.execute('''UPDATE cs.detection_alerts
                SET status = 'acknowledged', acknowledged_at = now()
                WHERE id = %s AND status = 'open' ''', (alert_id,))
            return changed.rowcount == 1
