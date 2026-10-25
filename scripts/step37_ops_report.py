"""Offline privacy-minimizing agent readiness and operational health summary.

No network calls, no API secrets, no data samples, no DSN, no host paths in JSON.
This is a local diagnostic, NOT a production monitoring pipeline.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.state_cli import inspect_state
from scripts.step27_tenant_audit import offline_audit


def report(*, state: Path | None = None) -> dict:
    source = offline_audit()
    checks = {'rls_migrations_statically_present': source['status'] == 'pass'}
    result = {'component': 'local-agent-readiness', 'beta_gate': 'blocked',
              'checks': checks, 'limitations': 'Local-only. No live Neon, uptime or real tenant availability evidence.'}
    if state is not None:
        # inspect_state is read-only and returns aggregate counts, never payloads.
        queue = inspect_state(state)
        result['outbox'] = {k: queue[k] for k in ('status', 'pending_events', 'oldest_age_seconds',
                                'near_or_past_freshness_limit', 'queue_capacity')}
        checks['outbox_not_stale_or_full'] = queue['status'] not in ('needs_operator_action', 'backpressure')
    result['status'] = 'pass' if all(checks.values()) else 'attention'
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Offline, privacy-safe operational readiness status')
    p.add_argument('--state', type=Path, help='Optional existing private agent outbox state')
    args = p.parse_args(argv)
    try:
        outcome = report(state=args.state)
    except (AgentError, OSError) as exc:
        p.exit(2, f'Operational report unavailable: {exc}\n')
    print(json.dumps(outcome, sort_keys=True, indent=2))
    return 0 if outcome['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
