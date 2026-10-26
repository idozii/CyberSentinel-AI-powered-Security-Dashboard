"""Fail-closed, idempotent GitHub Actions installer; retains existing workflow."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT_ANCHOR = '      - name: Dependency consistency\n'
PG_ANCHOR = '      - name: Step 39 stolen-runtime-credential threat-model witness in disposable PostgreSQL\n'
UNIT_NEW = (
    '      - name: Steps 58-63 HTTP pilot offline contract and NO-GO gate\n'
    '        run: |\n'
    '          python -m unittest discover -s tests -p test_step58_63_offline.py -v\n'
    '          python -m scripts.step63_security_gate\n'
)
PG_NEW = (
    '      - name: Steps 58-63 signed OIDC to HTTP to PostgreSQL tenant boundary\n'
    '        env:\n'
    "          CYBERSENTINEL_ISOLATED_PG_CI: '1'\n"
    '        run: python -m unittest discover -s tests -p test_step58_63_pg.py -v\n'
)


def install(root: Path = ROOT, *, check_only: bool = False) -> bool:
    path = root / '.github/workflows/ci.yml'
    original = path.read_text(encoding='utf-8')
    if UNIT_NEW in original and PG_NEW in original:
        return False
    if UNIT_NEW in original or PG_NEW in original:
        raise RuntimeError('Partial installer state; manual review required')
    if (original.count(UNIT_ANCHOR) != 1 or original.count(PG_ANCHOR) != 1
            or 'test_step55_57_pg.py -v' not in original
            or 'test_step55_57_offline.py -v' not in original):
        raise RuntimeError('Unexpected CI workflow; no changes made')
    modified = original.replace(UNIT_ANCHOR, UNIT_NEW + UNIT_ANCHOR)
    modified = modified.replace(PG_ANCHOR, PG_NEW + PG_ANCHOR)
    if not check_only:
        path.write_text(modified, encoding='utf-8')
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    change = install(check_only=args.check_only)
    print(('would_update' if args.check_only else 'updated') if change else 'already_installed')


if __name__ == '__main__':
    main()
