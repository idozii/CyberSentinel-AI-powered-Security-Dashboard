"""Offline release rehearsal, with no connection to tenant databases or Neon."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from cybersentinel_agent.continuous import Outbox
from scripts.step35_release import release as step35_release
from scripts.step36_38_preflight import check
from scripts.step37_ops_report import report
from scripts.step38_outbox_recovery import backup_state, restore_state


def rehearse():
    previous = step35_release()
    preflight = check()
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp) / 'private'
        directory.mkdir(mode=0o700)
        active = directory / 'state.sqlite3'
        outbox = Outbox(active)
        outbox.bind('f' * 32, 'csd_just_a_disposable_test_token', '/tmp/step38-test-only')
        event = dict(event_id='e' * 32, occurred_at=int(time.time()), source_ref='a' * 32,
                     method='GET', path_group='login', status_code=401,
                     duration_ms=2.0, request_bytes=1, response_bytes=2)
        outbox.save_line('/tmp/step38-test-only', 1, 2, 5, event)
        before = report(state=active)
        saved = backup_state(active, directory / 'snapshot.sqlite3')
        loaded = restore_state(directory / 'snapshot.sqlite3', directory / 'restored.sqlite3', confirm=True)
        after = report(state=directory / 'restored.sqlite3')
        checks = {
            'step35_rehearsal': previous['status'] == 'pass',
            'step36_38_preflight': preflight['status'] == 'pass',
            'private_operational_health': before['status'] == 'pass' and before['outbox']['pending_events'] == 1,
            'consistent_sqlite_backup': saved['status'] == 'pass' and saved['pending_events'] == 1,
            'restore_to_new_state_only': loaded['status'] == 'pass' and after['outbox']['pending_events'] == 1,
            'beta_remains_blocked': previous['beta_gate'] == 'blocked' and after['beta_gate'] == 'blocked',
        }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'beta_gate': 'blocked', 'scope': 'Offline, private agent state only; no live PostgreSQL backup/restore.'}


def main():
    value = rehearse()
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0 if value['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
