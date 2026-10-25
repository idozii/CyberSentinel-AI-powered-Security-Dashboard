"""Safe local report for future HTTPS deployment and restore evidence.

Creates no network connections, credentials, deployment or migration. A report
is NOT authorization and must never be used as a bypass for the beta gate.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from scripts.step30_beta_gate import DEFAULT, assess
from scripts.step39_actor_boundary import audit

ROOT = Path(__file__).resolve().parents[1]


def readiness(root: Path = ROOT) -> dict:
    gate = assess(json.loads((root / 'deployment/step30/beta_evidence.example.json').read_text(encoding='utf-8')))
    actor = audit(root)
    return {
        'report_version': 1,
        'scope': 'local-only; no network, DNS, TLS, database backup or restore executed',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'blocked',
        'public_beta_allowed': False,
        'actor_boundary': actor['finding'],
        'actor_boundary_review_required': True,
        'beta_gate': gate['status'],
        'remaining_external_conditions': gate['missing_conditions'],
        'checklist': [
            'Replace shared mutable cs.actor_id trust for compromised runtime credentials',
            'Validate isolation with two independent tenants and a compromised-credential test',
            'Perform a real backup AND restore into a separate isolated database; document RPO and RTO',
            'Review TLS termination, request origin, forwarded headers, reverse proxy and secret injection',
            'Verify DNS control and obtain permission for all monitored traffic',
            'Obtain independent security and operational sign-off before any public beta',
        ],
    }


def _save_create_only(path: Path, data: dict, *, root: Path = ROOT) -> None:
    path = path.expanduser().resolve(strict=False)
    root = root.resolve()
    if path == root or root in path.parents or not path.parent.is_dir():
        raise ValueError('Output must be placed in an existing directory outside the repository')
    payload = json.dumps(data, sort_keys=True, indent=2) + '\n'
    # Atomic create; never follow a pre-existing symlink or overwrite evidence.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            file.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description='Read-only limited beta assessment: always blocked')
    parser.add_argument('--output', type=Path, help='Create a new local JSON report OUTSIDE the repository')
    args = parser.parse_args()
    result = readiness()
    if args.output:
        try:
            _save_create_only(args.output, result)
        except (ValueError, OSError) as exc:
            parser.error(type(exc).__name__ + ': output must be a new safe path')
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['status'] == 'blocked' else 2


if __name__ == '__main__':
    raise SystemExit(main())
