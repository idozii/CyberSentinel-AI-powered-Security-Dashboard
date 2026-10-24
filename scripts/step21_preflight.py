"""Static Step 21 safety checks; runtime baseline guard lives in quality_gate."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW_FILES = (
    'hosted_api/demo_tuning.py', 'scripts/step21_quality_gate.py',
    'scripts/step21_preflight.py', 'tests/test_step21_tuning.py',
    'docs/HUONG_DAN_BUOC_21.md', 'docs/STEP21_QUALITY_LIMITATIONS.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [name for name in NEW_FILES if not (root / name).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    tuning = (root / NEW_FILES[0]).read_text(encoding='utf-8')
    script = (root / NEW_FILES[1]).read_text(encoding='utf-8')
    portal = (root / 'hosted_api/local_demo.py').read_text(encoding='utf-8')
    ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    checks = {
        'pinned_step20_manifest': 'PINNED_MANIFEST_SHA256' in tuning,
        'frozen_holdout': 'DEVELOPMENT_NAMES' in tuning and 'VALIDATION_NAMES' in tuning,
        'uses_real_baseline': 'baseline_report = evaluate()' in tuning,
        'never_apply_thresholds': "'live_config_changed': False" in tuning and "'release_approved': False" in tuning,
        'reports_outside_git': 'target.is_relative_to(ROOT)' in script,
        'local_demo_only': "@app.get('/demo/tuning')" in portal,
        'ci_quality_gate': 'python -m scripts.step21_quality_gate' in ci,
        'ci_regression_tests': 'test_step21_tuning.py' in ci,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'limitations': 'Static source audit; not a production benchmark or security verification.'}


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
