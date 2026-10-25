"""Read-only status checks for the Step 13/33 agent SQLite outbox.

No database is created, no events are printed, and no state is modified.
Cannot recover data that the server rejects due to the 5-minute TTL.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
import stat
import time
from pathlib import Path

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.continuous import MAX_QUEUE, STALE_SECONDS


def inspect_state(path: Path, *, now: float | None = None) -> dict:
    path = Path(path).absolute()
    if path.is_symlink() or not path.exists():
        raise AgentError('State file missing or a symlink; refusing access')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o077):
        raise AgentError('State must be a private owner-only regular file (chmod 600)')
    # SQLite mode=ro: no file creation or schema migration. URI quoting is handled by as_uri.
    try:
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            num, earliest, latest = db.execute(
                'SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM queue').fetchone()
            cursor_count = db.execute('SELECT COUNT(*) FROM cursors').fetchone()[0]
            bound = db.execute("SELECT COUNT(*) FROM agent_settings WHERE name='binding'").fetchone()[0] == 1
    except sqlite3.Error as exc:
        raise AgentError('Unable to inspect an initialized agent state database') from exc
    time_now = time.time() if now is None else float(now)
    oldest_age = max(0, int(time_now - earliest)) if earliest is not None else None
    expired = earliest is not None and time_now - earliest >= STALE_SECONDS - 5
    if expired:
        status = 'needs_operator_action'
    elif num >= MAX_QUEUE:
        status = 'backpressure'
    elif num > 0:
        status = 'pending'
    else:
        status = 'empty'
    return {'status': status, 'pending_events': int(num),
            'oldest_age_seconds': oldest_age,
            'near_or_past_freshness_limit': bool(expired),
            'cursor_count': int(cursor_count), 'state_bound': bool(bound),
            'queue_capacity': MAX_QUEUE,
            'notice': '5-minute server TTL; never edit timestamps or silently discard events.'}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Read-only state and outbox diagnostics')
    parser.add_argument('--state', type=Path, required=True, help='Existing private SQLite state file')
    args = parser.parse_args(argv)
    try:
        report = inspect_state(args.state)
    except (AgentError, OSError) as exc:
        parser.exit(2, f'State inspection failed: {exc}\n')
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2 if report['status'] in ('needs_operator_action', 'backpressure') else 0


if __name__ == '__main__':
    raise SystemExit(main())
