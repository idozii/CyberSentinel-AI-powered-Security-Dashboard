"""Idempotent Step 39-40 integration with existing README and GitHub CI.

Changes no application, migration, database or production credentials.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_UNIT_ANCHOR = '      - name: Dependency consistency\n'
CI_PG_ANCHOR = '      - name: Step 27 read-only RLS runtime metadata inspection\n'
CI_UNIT = '''      - name: Steps 39-40 offline boundary audit and readiness gate
        run: |
          python -m unittest discover -s tests -p test_step39_40_safety.py -v
          python -m scripts.step39_40_preflight
          python -m scripts.step39_40_release
'''
CI_PG = '''      - name: Step 39 stolen-runtime-credential threat-model witness in disposable PostgreSQL
        env:
          CYBERSENTINEL_ISOLATED_PG_CI: '1'
        run: python -m unittest discover -s tests -p test_step39_actor_spoof_pg.py -v
'''
README = '''

### Steps 39-40 - Fail-closed public beta boundary audit

The checked-in shared PostgreSQL runtime role uses a mutable `cs.actor_id` GUC.
If the runtime DB credential is compromised, this GUC is not a database-enforced
proof of tenant identity. A disposable PostgreSQL 17 CI witness documents the
threat; production credentials and Neon are never used in this test. The
step40 readiness report and restore/HTTPS runbook do NOT deploy, back up or
restore live infrastructure. Public beta remains **NO-GO**.

Run `python -m scripts.step39_40_release` and see
`docs/HUONG_DAN_BUOC_39_40.md`.
'''


def install(root: Path = ROOT) -> dict:
    workflow = root / '.github/workflows/ci.yml'
    readme = root / 'README.md'
    ci = workflow.read_text(encoding='utf-8')
    read = readme.read_text(encoding='utf-8')
    if CI_UNIT_ANCHOR not in ci or CI_PG_ANCHOR not in ci:
        raise RuntimeError('CI anchors missing - do not auto-modify an unexpected workflow')
    if 'test_step39_actor_spoof_pg.py -v' not in ci:
        ci = ci.replace(CI_PG_ANCHOR, CI_PG + CI_PG_ANCHOR, 1)
    if 'python -m scripts.step39_40_release' not in ci:
        ci = ci.replace(CI_UNIT_ANCHOR, CI_UNIT + CI_UNIT_ANCHOR, 1)
    if '### Steps 39-40 - Fail-closed public beta boundary audit' not in read:
        read += README
    changed = {'ci_changed': ci != workflow.read_text(encoding='utf-8'),
               'readme_changed': read != readme.read_text(encoding='utf-8')}
    if changed['ci_changed']:
        workflow.write_text(ci, encoding='utf-8')
    if changed['readme_changed']:
        readme.write_text(read, encoding='utf-8')
    return changed


def main():
    p = argparse.ArgumentParser(description='Install Steps 39-40 safety checks into CI and README')
    p.parse_args()
    print(install())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
