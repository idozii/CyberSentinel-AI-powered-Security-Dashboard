"""Idempotently insert a CI-only step into the existing GitHub workflow."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT_ANCHOR = '      - name: Dependency consistency\n'
PG_ANCHOR = '      - name: Step 39 stolen-runtime-credential threat-model witness in disposable PostgreSQL\n'
UNIT_NEW = (
    '      - name: Steps 49-51 isolated credential broker and canary offline tests\n'
    '        run: |\n'
    '          python -m unittest discover -s tests -p test_step49_51_offline.py -v\n'
    '          python -m scripts.step51_release_gate\n'
)
PG_NEW = (
    '      - name: Steps 49-51 isolated credential broker, revoke and canary PostgreSQL proof\n'
    '        env:\n'
    "          CYBERSENTINEL_ISOLATED_PG_CI: '1'\n"
    '        run: python -m unittest discover -s tests -p test_step49_51_pg.py -v\n'
)


def install(root: Path = ROOT, *, check_only: bool = False) -> bool:
    path = root / '.github/workflows/ci.yml'
    original = path.read_text(encoding='utf-8')
    if UNIT_NEW in original and PG_NEW in original:
        return False
    if UNIT_NEW in original or PG_NEW in original:
        raise RuntimeError('Partial CI installation; manual review required')
    if (original.count(UNIT_ANCHOR) != 1 or original.count(PG_ANCHOR) != 1
            or 'test_step46_48_pg.py -v' not in original
            or 'test_step46_48_offline.py -v' not in original):
        raise RuntimeError('Unexpected workflow version; refusing automatic edit')
    updated = original.replace(UNIT_ANCHOR, UNIT_NEW + UNIT_ANCHOR)
    updated = updated.replace(PG_ANCHOR, PG_NEW + PG_ANCHOR)
    if not check_only:
        path.write_text(updated, encoding='utf-8')
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    changed = install(check_only=args.check_only)
    print(('would_update' if changed else 'already_installed') if args.check_only
          else ('updated' if changed else 'already_installed'))


if __name__ == '__main__':
    main()
