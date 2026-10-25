"""Private SQLite outbox snapshot and restore for LOCAL disaster-recovery rehearsal.

No network, Neon credentials or cloud database access. Restore is create-only,
never writes into an existing agent state. Stop the agent before restore or use.
These snapshots are not encrypted and are NOT a production backup solution.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.state_cli import inspect_state

REQUIRED_TABLES = frozenset({'queue', 'cursors', 'agent_settings'})


def _private_source(path: Path) -> Path:
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file():
        raise AgentError('State file must be an existing regular file, not a symlink')
    if path.stat().st_mode & 0o077:
        raise AgentError('State file must be owner-only (chmod 600)')
    return path


def _destination(path: Path) -> Path:
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise AgentError('Destination already exists; never overwrite an agent state')
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise AgentError('Use an existing private destination directory')
    if parent.stat().st_mode & 0o077:
        raise AgentError('Destination directory must be private (chmod 700)')
    return path


def _verify(path: Path) -> dict:
    path = _private_source(path)
    try:
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)) as db:
            integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if integrity != 'ok' or not REQUIRED_TABLES.issubset(tables):
                raise AgentError('Outbox backup failed integrity or schema verification')
            pending = int(db.execute('SELECT count(*) FROM queue').fetchone()[0])
            binding = int(db.execute("SELECT count(*) FROM agent_settings WHERE name='binding'").fetchone()[0])
            if binding != 1:
                raise AgentError('Outbox is not bound to an agent identity')
        return {'status': 'pass', 'integrity': 'ok', 'pending_events': pending,
                'schema': 'agent-outbox', 'contains_sensitive_metadata': True}
    except sqlite3.Error as exc:
        raise AgentError('SQLite file is invalid or unreadable') from exc


def backup_state(source: Path, backup: Path) -> dict:
    source = _private_source(source)
    original = inspect_state(source)
    backup = _destination(backup)
    # O_EXCL and O_NOFOLLOW prevent overwriting and following a final symlink.
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(backup, flags, 0o600)
    os.close(fd)
    try:
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=5)) as src:
            with closing(sqlite3.connect(backup, timeout=5)) as dst:
                src.backup(dst)
        result = _verify(backup)
        if result['pending_events'] != original['pending_events']:
            # If the producer is active, SQLite gives a consistent snapshot, but
            # counts can change between pre-inspection and backup. Fail closed.
            raise AgentError('Outbox changed during backup; stop the agent and retry')
        return {'status': 'pass', 'operation': 'backup', 'pending_events': result['pending_events'],
                'warning': 'Unencrypted local snapshot. Store privately and stop agent before recovery.'}
    except BaseException:
        backup.unlink(missing_ok=True)
        raise


def restore_state(backup: Path, restored: Path, *, confirm: bool = False) -> dict:
    if not confirm:
        raise AgentError('Explicit --confirm-restore is required')
    backup = _private_source(backup)
    checked = _verify(backup)
    restored = _destination(restored)
    if backup == restored:
        raise AgentError('Restore must use a new state path')
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(restored, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out, backup.open('rb') as inp:
            shutil.copyfileobj(inp, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        verified = _verify(restored)
        if verified['pending_events'] != checked['pending_events']:
            raise AgentError('Outbox restore verification failed')
        return {'status': 'pass', 'operation': 'restore', 'pending_events': verified['pending_events'],
                'warning': 'Stop watcher first. Use original binding and log; stale events may need operator action.'}
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        restored.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Local SQLite outbox backup/restore rehearsal')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--backup', action='store_true', help='Snapshot an agent state')
    mode.add_argument('--restore', action='store_true', help='Restore to a new empty path')
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--destination', type=Path, required=True)
    p.add_argument('--confirm-restore', action='store_true')
    args = p.parse_args(argv)
    try:
        if args.backup:
            if args.confirm_restore:
                p.error('--confirm-restore applies only to --restore')
            result = backup_state(args.source, args.destination)
        else:
            result = restore_state(args.source, args.destination, confirm=args.confirm_restore)
    except (AgentError, OSError, sqlite3.Error) as exc:
        p.exit(2, f'Local outbox recovery failed: {exc}\n')
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
