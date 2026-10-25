"""Safely integrate Step 36-38 CI and README changes into the current checkout.

Do not ship reconstructed copies of historical files, which may differ from
GitHub main. This installer only inserts bounded sections at stable anchors.
It is idempotent and refuses unexpected CI structure before writing anything.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_MARKER = '      - name: Steps 36-38 private recovery and operational regression\n'
CI_BLOCK = '''      - name: Steps 36-38 private recovery and operational regression
        run: |
          python -m unittest discover -s tests -p test_step36_38_safety.py -v
          python -m scripts.step36_38_preflight
          python -m scripts.step36_38_release
          python -m scripts.step37_ops_report
'''
PG_MARKER = '      - name: Step 36 disposable Postgres tenant isolation regression\n'
PG_BLOCK = '''      - name: Step 36 disposable Postgres tenant isolation regression
        run: python -m unittest discover -s tests -p test_step36_tenant_pg.py -v
'''
DOC_MARKER = '## Steps 36-38 - Tenant boundary regression and private recovery\n'
DOC_BLOCK = '''\n\n## Steps 36-38 - Tenant boundary regression and private recovery

Disposable PostgreSQL CI adds multi-owner isolation checks; localhost tools report
private agent queue health and support create-only SQLite outbox snapshot and
restore. Run `python -m scripts.step36_38_release` and see
`docs/HUONG_DAN_BUOC_36_38.md`. This is NOT PostgreSQL disaster recovery and
NOT authorization to deploy publicly. The shared runtime DB role's user-settable
`cs.actor_id` remains a public-beta security-review blocker.
'''


def _once_insert(text: str, marker: str, block: str, anchor: str) -> str:
    if marker in text:
        if block not in text:
            raise ValueError('Existing Step 36-38 section differs; review manually')
        return text
    if text.count(anchor) != 1:
        raise ValueError('Missing or ambiguous CI anchor; no changes applied')
    return text.replace(anchor, block + anchor)


def install(root: Path = ROOT) -> dict:
    workflow = root / '.github/workflows/ci.yml'
    readme = root / 'README.md'
    if not workflow.is_file() or not readme.is_file():
        raise ValueError('Run from the CyberSentinel repository root')
    old_ci, old_readme = workflow.read_text(), readme.read_text()
    updated_ci = _once_insert(old_ci, CI_MARKER, CI_BLOCK, '      - name: Dependency consistency\n')
    updated_ci = _once_insert(updated_ci, PG_MARKER, PG_BLOCK,
                              '      - name: Step 27 read-only RLS runtime metadata inspection\n')
    if DOC_MARKER not in old_readme:
        updated_readme = old_readme.rstrip('\n') + DOC_BLOCK
    elif DOC_BLOCK.strip() in old_readme:
        updated_readme = old_readme
    else:
        raise ValueError('Existing README Step 36-38 section differs; review manually')
    # Both inputs are validated before either write.
    if updated_ci != old_ci:
        workflow.write_text(updated_ci)
    if updated_readme != old_readme:
        readme.write_text(updated_readme)
    return {'status': 'pass', 'ci_updated': updated_ci != old_ci,
            'readme_updated': updated_readme != old_readme}


def main(argv: list[str] | None = None) -> int:
    import json
    p = argparse.ArgumentParser(description='Apply Step 36-38 workflow and README additions safely')
    p.parse_args(argv)
    try:
        result = install()
    except (OSError, ValueError) as exc:
        p.exit(2, f'Step 36-38 installer refused changes: {exc}\n')
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
