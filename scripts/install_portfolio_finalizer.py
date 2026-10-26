"""Strict additive portfolio release installer: modifies README and existing CI only."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_ANCHOR = '      - name: Dependency consistency\n'
CI_BLOCK = ('      - name: Final portfolio evidence and recruiter handoff\n'
            '        run: |\n'
            '          python -m unittest discover -s tests -p test_portfolio_finalizer.py -v\n'
            '          python -m scripts.portfolio_finalizer\n')
README_ANCHOR = '# CyberSentinel - AI-Assisted Security Telemetry Lab\n'
README_BLOCK = ('\n> **Final portfolio checklist:** [Portfolio 100% Acceptance]'
                '(docs/PORTFOLIO_100_ACCEPTANCE.md) covers clean-clone QA, screenshots, video,'
                ' evidence and a GitHub release. The cloud-free demo remains available via'
                ' `python -m scripts.zero_cost_portfolio demo`.\n')


def render(root: Path = ROOT) -> dict[Path, str]:
    workflow = root / '.github/workflows/ci.yml'
    readme_file = root / 'README.md'
    ci = workflow.read_text(encoding='utf-8')
    readme = readme_file.read_text(encoding='utf-8')
    patches = {}
    if CI_BLOCK not in ci:
        if ci.count(CI_ANCHOR) != 1 or 'test_zero_cost_portfolio.py -v' not in ci:
            raise RuntimeError('Unknown CI layout or previous milestone missing')
        patches[workflow] = ci.replace(CI_ANCHOR, CI_BLOCK + CI_ANCHOR, 1)
    if README_BLOCK not in readme:
        if readme.count(README_ANCHOR) != 1:
            raise RuntimeError('Unknown README layout')
        patches[readme_file] = readme.replace(README_ANCHOR, README_ANCHOR + README_BLOCK, 1)
    return patches


def install(root: Path = ROOT, check_only: bool = False) -> list[str]:
    patches = render(root)
    if not check_only:
        for path, body in patches.items():
            path.write_text(body, encoding='utf-8')
    return [str(p.relative_to(root)) for p in patches]


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument('--check-only', action='store_true')
    args = cli.parse_args()
    files = install(check_only=args.check_only)
    print(('would_update: ' if args.check_only else 'updated: ') + ', '.join(files or ['already_installed']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
