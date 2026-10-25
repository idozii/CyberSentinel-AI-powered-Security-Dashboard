"""Step 53: fail-closed synthetic owner-canary cutover and rollback rehearsal.

Does not route FastAPI requests or switch live connections. 'Baseline' is a
read-only fixture oracle in an isolated database, NOT the shared-runtime app.
Rollback here means disabling the experimental path, not failing open to the
legacy cs.actor_id runtime role.
"""
from __future__ import annotations

import uuid
from enum import Enum

from scripts.step47_schema_rehearsal import TABLES, DisposableSchemaRehearsal
from scripts.step52_credential_custody import DisposableCredentialCustody


class Phase(str, Enum):
    READY = 'ready'
    SHADOW = 'shadow'
    CANARY = 'canary'
    ROLLED_BACK = 'rolled_back'


class DisposableCutoverDrill:
    def __init__(self, scenario: DisposableSchemaRehearsal,
                 custody: DisposableCredentialCustody):
        scenario._guard()
        if not scenario.created or scenario.reverted or len(scenario.created_roles) != 2:
            raise RuntimeError('Step 47 disposable roles and schema required')
        if custody._broker._scenario is not scenario:
            raise ValueError('Custody and scenario must be identical')
        self._scenario = scenario
        self._custody = custody
        self._phase = Phase.READY
        self._observed: set[int] = set()
        self._oracle: dict[int, dict[str, int]] = {}
        self._faults: list[str] = []

    @property
    def phase(self) -> str:
        return self._phase.value

    def _fixture_oracle(self) -> dict[int, dict[str, int]]:
        from psycopg import sql
        result: dict[int, dict[str, int]] = {}
        with self._scenario._admin() as db:
            for idx, owner in enumerate(self._scenario.owners):
                counters = {}
                for table in TABLES:
                    owner_col = 'id' if table == 'identities' else 'owner_id'
                    counters[table] = db.execute(
                        sql.SQL('SELECT count(*) FROM cs.{} WHERE {} = %s').format(
                            sql.Identifier(table), sql.Identifier(owner_col)), (owner,)
                    ).fetchone()[0]
                result[idx] = counters
        if any(set(values) != set(TABLES) or any(n != 1 for n in values.values())
               for values in result.values()):
            raise AssertionError('Expected one synthetic row per tenant in all five tables')
        return result

    def begin_shadow(self) -> None:
        if self._phase is not Phase.READY:
            raise RuntimeError('Cannot start shadow from current phase')
        self._oracle = self._fixture_oracle()
        self._phase = Phase.SHADOW

    def _counts(self, token: str) -> dict[str, int]:
        from psycopg import sql
        with self._custody.session(token) as db:
            return {table: db.execute(
                sql.SQL('SELECT count(*) FROM cs.{}').format(sql.Identifier(table))
            ).fetchone()[0] for table in TABLES}

    def shadow_probe(self, token: str, fixture_index: int) -> dict[str, int]:
        if self._phase is not Phase.SHADOW:
            raise RuntimeError('Shadow mode inactive')
        if type(fixture_index) is not int or fixture_index not in (0, 1):
            raise ValueError('Invalid fixture index')
        # In this synthetic harness a token is deliberately bound to one role.
        # Supplying the wrong fixture index fails equality rather than switching roles.
        # Counts alone are identical for both fixture tenants; verify the
        # resolved role/tenant before comparing them with the fixture oracle.
        resolved_index = self._custody._broker._resolve(token)
        counts = self._counts(token)
        if resolved_index != fixture_index or counts != self._oracle[fixture_index]:
            self.rollback('shadow_mismatch')
            raise AssertionError('Shadow result diverged from owner-scoped fixture oracle')
        self._observed.add(fixture_index)
        return counts

    def activate_canary(self) -> None:
        if self._phase is not Phase.SHADOW or self._observed != {0, 1}:
            raise RuntimeError('Both synthetic tenants must pass shadow checks')
        self._phase = Phase.CANARY

    def canary_overview(self, token: str) -> dict[str, int]:
        if self._phase is not Phase.CANARY:
            raise RuntimeError('Experimental canary is not active')
        return self._counts(token)

    def canary_acknowledge(self, token: str, alert_id: uuid.UUID) -> bool:
        if self._phase is not Phase.CANARY:
            raise RuntimeError('Experimental canary is not active')
        if type(alert_id) is not uuid.UUID:
            raise ValueError('Invalid alert ID')
        with self._custody.session(token) as db:
            updated = db.execute(
                "UPDATE cs.detection_alerts SET status='acknowledged', "
                'acknowledged_at=now() WHERE id=%s AND status=\'open\'', (alert_id,)
            )
            return updated.rowcount == 1

    def rollback(self, reason: str = 'operator_requested') -> None:
        if self._phase not in (Phase.SHADOW, Phase.CANARY):
            raise RuntimeError('No active rehearsal to roll back')
        if reason not in ('operator_requested', 'shadow_mismatch',
                          'dependency_outage', 'security_regression'):
            raise ValueError('Invalid controlled failure reason')
        self._faults.append(reason)
        # Fail closed. NEVER fall back to shared-runtime GUC impersonation.
        self._custody.seal()
        self._phase = Phase.ROLLED_BACK

    def report(self) -> dict:
        return {
            'phase': self.phase,
            'observed_synthetic_tenants': len(self._observed),
            'fixture_only': True,
            'fallback_to_shared_runtime': False,
            'failure_categories': list(self._faults),
            'staging_cutover_performed': False,
            'rollback_of_live_database_tested': False,
        }
