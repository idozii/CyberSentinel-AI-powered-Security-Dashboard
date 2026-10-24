"""Fail-closed candidate beta evidence checklist - never deploys anything.

Even twelve self-attested checkboxes do not constitute independent approval.
Only verified external evidence and a manual release owner can authorize a beta.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

KEYS = (
    'controlled_domain_dns_verified', 'reviewed_tls_termination',
    'private_owner_portal', 'public_ingest_hardening',
    'real_multi_tenant_authorization', 'durable_agent_delivery_and_recovery',
    'real_observability_and_alerts', 'backup_restore_drill_on_deployment',
    'privacy_legal_approval', 'external_security_review',
    'authorized_beta_traffic_and_consent', 'incident_response_and_key_rotation',
)
DEFAULT = Path(__file__).resolve().parents[1] / 'deployment/step30/beta_evidence.example.json'


def assess(evidence: object) -> dict:
    if not isinstance(evidence, dict) or set(evidence) != set(KEYS):
        raise ValueError('Evidence must have exactly the documented checklist keys')
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError('Every evidence field must be a boolean; never place credentials here')
    missing = [key for key in KEYS if not evidence[key]]
    return {
        'status': 'blocked' if missing else 'manual_independent_review_required',
        'missing_conditions': missing,
        'reported_complete': len(KEYS) - len(missing),
        'required_conditions': len(KEYS),
        'authorization_to_deploy_publicly': False,
        'limitations': 'Self-attested checkboxes are NOT evidence of security or consent. Public beta requires external review and human release approval.',
    }


def main() -> int:
    p = argparse.ArgumentParser(description='Fail-closed readiness audit for a future limited beta')
    p.add_argument('--evidence', type=Path, default=DEFAULT, help='Local JSON file (do not store secrets)')
    p.add_argument('--expect-blocked', action='store_true', help='CI mode: assert default example fails closed')
    args = p.parse_args()
    try:
        report = assess(json.loads(args.evidence.read_text(encoding='utf-8')))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        # No content or path is echoed to avoid exposing user-provided evidence.
        print(json.dumps({'status': 'invalid_evidence', 'error_type': type(exc).__name__}, indent=2))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.expect_blocked:
        return 0 if report['status'] == 'blocked' else 2
    # A self-attested result is never authorization to deploy.
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
