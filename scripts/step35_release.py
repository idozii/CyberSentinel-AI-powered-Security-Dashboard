"""Offline Steps 33-35 release rehearsal (no bound network, cloud or secrets)."""
from __future__ import annotations
import json
from scripts.step25_release import release_smoke
from scripts.step31_32_release import rehearse as soc_rehearse
from scripts.step33_35_preflight import check


def release():
    base = release_smoke()
    ui = soc_rehearse()
    preflight = check()
    checks = {'local_mvp_still_passes':base['status']=='pass',
              'soc_v2_still_passes':ui['status']=='pass',
              'safe_agent_preflight':preflight['status']=='pass',
              'beta_still_blocked':ui['beta_gate']=='blocked'}
    return {'status':'pass' if all(checks.values()) else 'fail','checks':checks,
            'beta_gate':'blocked',
            'scope':'Offline integration; no public beta, no 5-minute TTL bypass'}


def main():
    result=release()
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['status']=='pass' else 2

if __name__=='__main__':
    raise SystemExit(main())
