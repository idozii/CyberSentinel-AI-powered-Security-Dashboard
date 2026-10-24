"""Static review of the local-only Auth0 browser staging patch."""
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILES=(
 'hosted_api/web_auth.py','hosted_api/web.py','tests/test_step17_browser.py',
 'docs/HUONG_DAN_BUOC_17.md','docs/STEP17_BROWSER_SECURITY.md',
 'scripts/step17_preflight.py',
)

def check(root:Path=ROOT)->dict:
    absent=[f for f in FILES if not (root/f).is_file()]
    if absent:
        return {'status':'fail','missing':absent}
    web=(root/'hosted_api/web.py').read_text(encoding='utf8')
    auth=(root/'hosted_api/web_auth.py').read_text(encoding='utf8')
    ci=(root/'.github/workflows/ci.yml').read_text(encoding='utf8')
    checks={
        'no_public_binding': 'loopback_only' in web and "allowed_hosts=['127.0.0.1','localhost','testserver']" in web,
        'private_cookie': "httponly=True" in web and "samesite='lax'" in web,
        'csrf': 'check_csrf(fields, sess)' in web,
        'pkce_s256': "'code_challenge_method': 'S256'" in auth,
        'nonce_and_subject_bound': "claims.get('nonce') != pending.nonce" in auth and "claims.get('sub') != identity.subject" in auth,
        'flow_browser_binding': 'flow_cookie_hash' in auth and 'FLOW_COOKIE' in web,
        'server_side_code_exchange': "'client_secret': self.config.client_secret" in auth,
        'no_browser_token': 'access_token' not in web,
        'checks_ci': 'python -m scripts.step17_preflight' in ci,
    }
    return {'status':'pass' if all(checks.values()) else 'fail','checks':checks,
            'limitations':'Static checks only; does not verify live Auth0 callback, Neon, SSH or deployment hardening.'}

def main():
    result=check()
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='pass' else 2

if __name__=='__main__':raise SystemExit(main())
