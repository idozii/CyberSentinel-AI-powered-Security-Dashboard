"""Fail-fast static checks for intentionally isolated, opt-in Step 19 demo."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEEDED = ('hosted_api/local_demo.py','scripts/step19_generate_logs.py',
          'tests/test_step19_demo.py', 'docs/HUONG_DAN_BUOC_19.md',
          'docs/STEP19_DEMO_SECURITY.md')


def check(root: Path = ROOT) -> dict:
    missing = [p for p in NEEDED if not (root / p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    source = (root / NEEDED[0]).read_text(encoding='utf-8')
    agent = (root / 'cybersentinel_agent/client.py').read_text(encoding='utf-8')
    ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    checks = {
        'requires_explicit_opt_in': "CYBERSENTINEL_LOCAL_DEMO" in source and "raise RuntimeError" in source,
        'in_memory_only': 'class DemoStore:' in source and 'sqlite3' not in source and 'psycopg' not in source,
        'isolated_demo_key_prefix': "TOKEN_PREFIX = 'csd_'" in source and 'Port 8019 accepts only local demo keys' in agent,
        'localhost_guard': "allowed_hosts=['127.0.0.1', 'localhost', 'testserver']" in source,
        'max_event_limit': 'MAX_EVENTS = 500' in source,
        'no_dns_shortcut': 'verified_at' not in source and 'ALTER ROLE' not in source,
        'ci_step19_test': 'test_step19_demo.py' in ci,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks}


def main() -> int:
    report = check()
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
