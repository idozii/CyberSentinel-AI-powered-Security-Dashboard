"""Idempotently register Step 44-45 checks in the existing CI workflow.

Preserve the rest of ci.yml byte-for-byte. Refuse unknown anchor revisions.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT_ANCHOR = '      - name: Dependency consistency\n'
PG_ANCHOR = ('      - name: Step 39 stolen-runtime-credential threat-model '
             'witness in disposable PostgreSQL\n')
UNIT_LINE = '      - name: Steps 44-45 disposable credential and security gates\n'
PG_LINE = '      - name: Steps 44-45 disposable role lifecycle PostgreSQL proof\n'
UNIT_INSERT = '''      - name: Steps 44-45 disposable credential and security gates
        run: |
          python -m unittest discover -s tests -p test_step44_45_offline.py -v
          python -m scripts.step45_security_gate
'''
PG_INSERT = '''      - name: Steps 44-45 disposable role lifecycle PostgreSQL proof
        env:
          CYBERSENTINEL_ISOLATED_PG_CI: '1'
        run: python -m unittest discover -s tests -p test_step44_45_pg.py -v
'''


def install(root: Path = ROOT, *, check_only: bool = False) -> bool:
    path = root / '.github/workflows/ci.yml'
    original = path.read_text(encoding='utf-8')
    if (original.count(UNIT_LINE), original.count(PG_LINE)) == (1, 1):
        if (original.count('test_step44_45_offline.py -v') != 1
                or original.count('test_step44_45_pg.py -v') != 1):
            raise RuntimeError('CI Step 44-45 registration inconsistent')
        return False
    if check_only:
        raise RuntimeError('Step 44-45 CI checks have not been installed')
    if UNIT_LINE in original or PG_LINE in original:
        raise RuntimeError('Partial Step 44-45 CI registration; review manually')
    if original.count(UNIT_ANCHOR) != 1 or original.count(PG_ANCHOR) != 1:
        raise RuntimeError('Unknown CI anchors; refusing to overwrite workflow')
    if ('test_step42_43_offline.py -v' not in original
            or 'test_step42_43_pg.py -v' not in original):
        raise RuntimeError('Steps 42-43 CI not present; sync main first')
    updated = (original.replace(UNIT_ANCHOR, UNIT_INSERT + UNIT_ANCHOR)
               .replace(PG_ANCHOR, PG_INSERT + PG_ANCHOR))
    path.write_text(updated, encoding='utf-8')
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    modified = install(check_only=args.check)
    print('CI verified' if args.check else
          'CI updated' if modified else 'CI already registered')


if __name__ == '__main__':
    main()
