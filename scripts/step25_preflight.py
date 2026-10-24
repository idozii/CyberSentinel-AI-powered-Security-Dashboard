"""Static acceptance checklist for the combined local portfolio MVP patch."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'hosted_api/demo_triage.py', 'hosted_api/local_demo.py',
    'cybersentinel_agent/demo_cli.py', 'scripts/step23_agent_doctor.py',
    'scripts/step24_failure_analysis.py', 'scripts/step25_demo.py',
    'scripts/step25_release.py', 'scripts/step25_preflight.py',
    'tests/test_step22_25_fasttrack.py',
    'docs/HUONG_DAN_BUOC_22_25.md', 'docs/STEP22_25_SECURITY.md',
    'docs/LOCAL_MVP_RELEASE.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [item for item in REQUIRED if not (root/item).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    portal = (root/'hosted_api/local_demo.py').read_text(encoding='utf-8')
    agent = (root/'cybersentinel_agent/demo_cli.py').read_text(encoding='utf-8')
    doctor = (root/'scripts/step23_agent_doctor.py').read_text(encoding='utf-8')
    smoke = (root/'scripts/step25_release.py').read_text(encoding='utf-8')
    workflow = (root/'.github/workflows/ci.yml').read_text(encoding='utf-8')
    cli = (root/'pyproject.toml').read_text(encoding='utf-8')
    checks = {
        'triage_details': "@app.get('/demo/alerts/{alert_id}')" in portal,
        'triage_filtered': "@app.get('/demo/alerts')" in portal,
        'csrf_unchanged': 'await authorize_form(req)' in portal,
        'local_bind_only': "host='127.0.0.1'" in (root/'scripts/step25_demo.py').read_text(),
        'isolated_token_prefix': "TOKEN_PREFIX = 'csd_'" in portal,
        'agent_exact_origin': "DEMO_URL = 'http://127.0.0.1:8019'" in agent,
        'agent_no_secrets_on_stdout': 'no key' not in agent and 'json.dumps(result' in agent,
        'doctor_no_proxy': 'request.ProxyHandler({})' in doctor,
        'key_rotation_test': 'key_rotation' in smoke,
        'existing_baseline_gate': 'quality_gate()' in smoke,
        'agent_console_script': 'cybersentinel-demo-agent' in cli,
        'ci_integrated_tests': 'test_step22_25_fasttrack.py' in workflow,
        'ci_release_smoke': 'python -m scripts.step25_release' in workflow,
    }
    return {'status':'pass' if all(checks.values()) else 'fail',
            'checks': checks,
            'limitations': 'Static and local tests only. Cloud production is outside this release.'}


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status']=='pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
