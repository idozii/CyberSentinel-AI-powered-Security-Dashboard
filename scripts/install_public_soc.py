"""Idempotently install SOC-inspired styling into the Streamlit public entrypoint.

Does not modify the FastAPI localhost dashboard, private API, scanner or data.
Fail closed if the app has a different layout: do not overwrite user edits.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'dashboard/public_app.py'
IMPORT = 'from public_soc_theme import apply_public_theme, render_public_hero'


def patch_source(source: str) -> str:
    if IMPORT in source:
        if 'render_public_hero(st)' not in source or 'apply_public_theme(st)' not in source:
            raise ValueError('Partial SOC theme install detected; review manually')
        return source
    required = (
        'from public_data import load_public_metrics',
        'st.set_page_config(',
        'CyberSentinel / Research Explorer',
        'from site_checker import SiteCheckError, check_website',
    )
    if any(marker not in source for marker in required):
        raise ValueError('Unrecognized public app; refusing to overwrite')

    source = source.replace('from public_data import load_public_metrics\n',
                            'from public_data import load_public_metrics\n' + IMPORT + '\n', 1)
    source = source.replace('page_title="CyberSentinel | Research Showcase"',
                            'page_title="CyberSentinel | Public SOC Research"', 1)
    source = source.replace('layout="wide")',
                            'layout="wide", initial_sidebar_state="expanded")', 1)
    # Limit substitution to first CSS block and the static hero; preserve page logic.
    style_rx = re.compile(r'st\.markdown\("""\s*<style>.*?</style>\s*""",\s*unsafe_allow_html=True\)', re.S)
    source, count = style_rx.subn('apply_public_theme(st)', source, count=1)
    if count != 1:
        raise ValueError('Could not locate original public CSS block')
    hero_rx = re.compile(r'st\.markdown\("""\s*<div class="hero">.*?</div>\s*""",\s*unsafe_allow_html=True\)', re.S)
    source, count = hero_rx.subn('render_public_hero(st)', source, count=1)
    if count != 1:
        raise ValueError('Could not locate original static public hero')
    source = source.replace('st.caption("AI-assisted security telemetry research")',
                            'st.caption("PUBLIC SOC UI 2.1 / RESEARCH SHOWCASE")', 1)
    source = source.replace('OWNER MONITORING: planned, not yet available.',
                            'OWNER MONITORING: private localhost demo only; not connected here.', 1)
    source = source.replace('CyberSentinel · Educational/research prototype · Aggregate report from one local experiment · Source and documentation on GitHub',
                            'CyberSentinel · Public SOC UI v2.1 · Synthetic aggregate research only · No live customer monitoring', 1)
    return source


def install(root: Path = ROOT, *, check_only: bool = False) -> str:
    path = root / 'dashboard/public_app.py'
    if path.is_symlink() or not path.is_file():
        raise ValueError('Unsafe or missing public app path')
    theme = root / 'dashboard/public_soc_theme.py'
    if not theme.is_file() or theme.is_symlink():
        raise ValueError('Missing first-party public theme')
    original = path.read_text(encoding='utf-8')
    rewritten = patch_source(original)
    compile(rewritten, str(path), 'exec')
    if check_only:
        if original != rewritten:
            raise ValueError('SOC public theme has not been installed')
        return 'verified'
    if rewritten == original:
        return 'already-installed'
    path.write_text(rewritten, encoding='utf-8')
    return 'installed'


def main() -> int:
    parser = argparse.ArgumentParser(description='Install first-party SOC theme into public Streamlit app')
    parser.add_argument('--check', action='store_true', help='Validate that styling is already installed')
    args = parser.parse_args()
    try:
        print('public-soc-theme:', install(check_only=args.check))
    except (ValueError, OSError) as exc:
        parser.exit(2, f'Install refused: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
