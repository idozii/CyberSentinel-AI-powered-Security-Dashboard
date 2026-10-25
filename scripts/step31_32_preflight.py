"""Static preflight for isolated SOC UI and read-only beta preparation."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'hosted_api/soc_ui.py', 'hosted_api/assets/soc.css',
    'hosted_api/assets/soc.js', 'hosted_api/local_demo.py',
    'scripts/step31_32_preflight.py', 'scripts/step31_32_release.py',
    'tests/test_step31_32_soc_ui.py',
    'docs/HUONG_DAN_BUOC_31_32.md', 'docs/STEP31_32_SECURITY.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [p for p in FILES if not (root / p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    css = (root / 'hosted_api/assets/soc.css').read_text(encoding='utf-8')
    js = (root / 'hosted_api/assets/soc.js').read_text(encoding='utf-8')
    src = (root / 'hosted_api/local_demo.py').read_text(encoding='utf-8')
    soc = (root / 'hosted_api/soc_ui.py').read_text(encoding='utf-8')
    ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    checks = {
        'no_external_assets': 'https://' not in css + js and '@import' not in css,
        'responsive_layout': '@media(max-width:760px)' in css,
        'no_untrusted_inline_script': '<script>' not in soc,
        'safe_css_and_script_policy': "style-src \\'self\\'" not in src and
                                      "style-src 'self'; script-src 'self'" in src,
        'loopback_guard_remains': 'ipaddress.ip_address(peer).is_loopback' in src,
        'csrf_guard_remains': 'secrets.compare_digest' in src,
        'beta_remains_fail_closed': "@app.get('/demo/readiness')" in src and
                                   'scripts.step30_beta_gate' in src,
        'ci_regression': 'test_step31_32_soc_ui.py' in ci and
                         'scripts.step31_32_release' in ci,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'localhost SOC UI and private planning; no Internet beta deployment'}


def main() -> int:
    report = check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
