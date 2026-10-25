"""Idempotent README / GitHub CI wiring. Does not alter application or database."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PG_ANCHOR = '      - name: Step 39 stolen-runtime-credential threat-model witness in disposable PostgreSQL\n'
UNIT_ANCHOR = '      - name: Dependency consistency\n'
PG_BLOCK = '''      - name: Step 41 independent login role tenant-isolation PostgreSQL proof
        env:
          CYBERSENTINEL_ISOLATED_PG_CI: '1'
        run: python -m unittest discover -s tests -p test_step41_role_isolation_pg.py -v
'''
UNIT_BLOCK = '''      - name: Step 41 offline role-boundary design and safety checks
        run: |
          python -m unittest discover -s tests -p test_step41_offline.py -v
          python -m scripts.step41_preflight
          python -m scripts.step41_release
'''
README_BLOCK = '''

### Step 41 - Isolated database-login tenant boundary proof

Step 41 demonstrates RLS based on a tenant's *database login role* with a
read-only role-to-owner mapping, not on the mutable `cs.actor_id` GUC. The
proof creates disposable test users/tables in GitHub CI PostgreSQL 17 only.
**It does not migrate the application, change the existing shared runtime
credential, or authorize public beta.** Never run the test against Neon.

Run `python -m scripts.step41_release` and read
`docs/HUONG_DAN_BUOC_41.md` and `docs/STEP41_TENANT_ROLE_SECURITY.md`.
'''


def install(root: Path = ROOT) -> dict:
    ci_path, readme_path = root/'.github/workflows/ci.yml', root/'README.md'
    original_ci, original_readme = ci_path.read_text(), readme_path.read_text()
    if PG_ANCHOR not in original_ci or UNIT_ANCHOR not in original_ci:
        raise RuntimeError('Unexpected CI layout; edit manually after review')
    updated_ci = original_ci
    if 'test_step41_role_isolation_pg.py -v' not in updated_ci:
        updated_ci = updated_ci.replace(PG_ANCHOR, PG_BLOCK + PG_ANCHOR, 1)
    if 'python -m scripts.step41_release' not in updated_ci:
        updated_ci = updated_ci.replace(UNIT_ANCHOR, UNIT_BLOCK + UNIT_ANCHOR, 1)
    updated_readme = original_readme
    if '### Step 41 - Isolated database-login tenant boundary proof' not in updated_readme:
        updated_readme += README_BLOCK
    if updated_ci != original_ci:
        ci_path.write_text(updated_ci, encoding='utf-8')
    if updated_readme != original_readme:
        readme_path.write_text(updated_readme, encoding='utf-8')
    return {'ci_changed': updated_ci != original_ci,
            'readme_changed': updated_readme != original_readme}


def main() -> int:
    print(json.dumps(install(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
