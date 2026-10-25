"""Read-only NO-GO gate. CI prototype success cannot approve a public beta."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'scripts/step49_credential_broker.py',
    'scripts/step51_application_canary.py',
    'scripts/step51_release_gate.py',
    'scripts/install_step49_51.py',
    'tests/test_step49_51_offline.py',
    'tests/test_step49_51_pg.py',
    'docs/STEP49_51_SECURITY.md',
    'docs/HUONG_DAN_BUOC_49_51.md',
)


def assess(root: Path = ROOT) -> dict:
    missing = [name for name in FILES if not (root / name).is_file()]
    ci_file = root / '.github/workflows/ci.yml'
    ci = ci_file.read_text(encoding='utf-8') if ci_file.is_file() else ''
    hosted_file = root / 'hosted_api/postgres.py'
    hosted = hosted_file.read_text(encoding='utf-8') if hosted_file.is_file() else ''
    checks = {
        'package_files_present': not missing,
        'offline_test_registered': 'test_step49_51_offline.py -v' in ci,
        'postgres_test_registered': 'test_step49_51_pg.py -v' in ci,
        'postgres_guarded': "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'shared_runtime_still_present': "set_config('cs.actor_id'" in hosted,
    }
    return {
        'status': 'ready_for_ci' if all(checks.values()) else 'incomplete',
        'checks': checks,
        'missing': missing,
        'isolated_pg_success_claimed': False,
        'production_secret_vault': False,
        'real_oidc_broker_integrated': False,
        'neon_modified': False,
        'public_beta_allowed': False,
        'next': 'Verify Step 49-51 disposable PG integration in GitHub Actions, then independently review real credential broker and migration.'
    }


def main() -> int:
    report = assess()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'ready_for_ci' else 2


if __name__ == '__main__':
    raise SystemExit(main())
