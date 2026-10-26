"""Idempotent, anchor-checked installer for the no-cloud portfolio milestone.

Only touches public showcase navigation, README discovery and existing CI jobs.
Never edits hosted_api, databases, credentials, or migration files.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NAV_ANCHOR = 'NAV = ["Overview", "Website checker", "Traffic & features", "Model evaluation", "Architecture", "Owner roadmap"]\n'
NAV_FLAG = ("OFFLINE_ONLY = os.environ.get('CYBERSENTINEL_OFFLINE_ONLY') == '1'\n"
            "if OFFLINE_ONLY:\n"
            "    NAV = [name for name in NAV if name != 'Website checker']\n")
BUTTON_ANCHOR = 'on_click=_navigate, args=("Website checker",))'
BUTTON_NEW = 'on_click=_navigate, args=("Website checker",), disabled=OFFLINE_ONLY)'
PAGE_ANCHOR = 'elif page == "Website checker":'
PAGE_NEW = 'elif page == "Website checker" and not OFFLINE_ONLY:'
CI_ANCHOR = '      - name: Dependency consistency\n'
CI_NEW = (
    '      - name: Zero-cost offline portfolio release and regression\n'
    '        run: |\n'
    '          python -m unittest discover -s tests -p test_zero_cost_portfolio.py -v\n'
    '          python -m scripts.zero_cost_portfolio audit\n'
    '          python -m scripts.zero_cost_portfolio audit --full\n'
)
README_ANCHOR = '# CyberSentinel - AI-Assisted Security Telemetry Lab\n'
README_NEW = ('\n> **Cloud-free portfolio milestone:** Launch the static SOC research demo on'
              ' localhost without Neon, Auth0 or Docker. See '
              '[Zero-Cost Portfolio Release](docs/ZERO_COST_PORTFOLIO_RELEASE.md).\n')


def render_updates(root: Path = ROOT) -> dict[Path, str]:
    """Check all three source files and compute changes before writing anything."""
    app_path = root / 'dashboard/public_app.py'
    ci_path = root / '.github/workflows/ci.yml'
    readme_path = root / 'README.md'
    app = app_path.read_text(encoding='utf-8')
    ci = ci_path.read_text(encoding='utf-8')
    readme = readme_path.read_text(encoding='utf-8')
    original = (app, ci, readme)

    markers = ('import os\n', NAV_FLAG, BUTTON_NEW, PAGE_NEW)
    installed = [m in app for m in markers]
    if all(installed):
        pass
    elif any(installed):
        raise RuntimeError('Partial public dashboard modification: review manually')
    else:
        if (app.count('import time\n') != 1 or app.count(NAV_ANCHOR) != 1
                or app.count(BUTTON_ANCHOR) != 1 or app.count(PAGE_ANCHOR) != 1):
            raise RuntimeError('Unexpected public dashboard source; aborting')
        app = app.replace('import time\n', 'import os\nimport time\n', 1)
        app = app.replace(NAV_ANCHOR, NAV_ANCHOR + NAV_FLAG, 1)
        app = app.replace(BUTTON_ANCHOR, BUTTON_NEW, 1)
        app = app.replace(PAGE_ANCHOR, PAGE_NEW, 1)

    if CI_NEW not in ci:
        if ci.count(CI_ANCHOR) != 1 or 'test_step58_63_offline.py -v' not in ci:
            raise RuntimeError('Unexpected GitHub workflow layout or missing Steps 58-63')
        ci = ci.replace(CI_ANCHOR, CI_NEW + CI_ANCHOR, 1)
    if README_NEW not in readme:
        if readme.count(README_ANCHOR) != 1:
            raise RuntimeError('Unexpected README heading')
        readme = readme.replace(README_ANCHOR, README_ANCHOR + README_NEW, 1)
    return {p: s for p, s, before in zip((app_path, ci_path, readme_path),
                                           (app, ci, readme), original) if s != before}


def install(root: Path = ROOT, *, check_only: bool = False) -> list[str]:
    changed = render_updates(root)
    if not check_only:
        for path, body in changed.items():
            path.write_text(body, encoding='utf-8')
    return [str(p.relative_to(root)) for p in changed]


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument('--check-only', action='store_true')
    args = cli.parse_args()
    changed = install(check_only=args.check_only)
    print(('would_update: ' if args.check_only else 'updated: ') +
          (', '.join(changed) if changed else 'already_installed'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
