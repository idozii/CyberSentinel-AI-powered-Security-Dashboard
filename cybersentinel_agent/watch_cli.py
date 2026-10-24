"""Run a bounded continuous localhost log follower; one process per state file.

The process runs in the foreground until stopped by Ctrl+C. It does not
install a background service, expose public endpoints or expand network scope.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from cybersentinel_agent.client import AgentError
from cybersentinel_agent.continuous import ContinuousAgent, Outbox

DEFAULT_STATE = Path("simulations/runtime/owner/continuous-agent.sqlite3")


@contextmanager
def single_instance(state: Path):
    lock_path = Path(str(state) + ".lock").absolute()
    if lock_path.is_symlink():
        raise AgentError("Refusing symlinked agent lock file")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path.parent.chmod(0o700)
    with lock_path.open("a+b") as handle:
        lock_path.chmod(0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AgentError("Another agent is already using this state file") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CyberSentinel continuous local NGINX log follower")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--domain-id", required=True)
    p.add_argument("--state", type=Path, default=DEFAULT_STATE)
    p.add_argument("--server", default="http://127.0.0.1:8002")
    p.add_argument("--poll-seconds", type=float, default=1.0)
    p.add_argument("--iterations", type=int, default=0, help="0 means foreground watch until Ctrl+C")
    p.add_argument("--from-start", action="store_true", help="First use only: read all existing complete lines")
    p.add_argument("--purge-expired", action="store_true", help="Explicitly discard events older than 5 minutes")
    p.add_argument("--confirm-loss", action="store_true", help="Required when --purge-expired is set")
    args = p.parse_args(argv)
    if not 0.1 <= args.poll_seconds <= 60:
        p.error("--poll-seconds must be between 0.1 and 60")
    if args.iterations < 0:
        p.error("--iterations cannot be negative")
    key = os.environ.get("CYBERSENTINEL_AGENT_KEY", "")
    if not key:
        p.error("Set CYBERSENTINEL_AGENT_KEY in the local environment")
    if args.purge_expired and not args.confirm_loss:
        p.error("--purge-expired requires --confirm-loss")
    agent = None
    try:
        with single_instance(args.state):
            agent = ContinuousAgent(args.input, args.state, args.domain_id, key,
                                    server=args.server, from_start=args.from_start)
            if args.purge_expired:
                print(json.dumps({"purged_expired": agent.store.purge_expired(confirm_loss=True)}), flush=True)
            iteration = 0
            while args.iterations == 0 or iteration < args.iterations:
                result = agent.step()
                print(json.dumps({"iteration": iteration + 1, **result}, separators=(",", ":")), flush=True)
                iteration += 1
                if args.iterations == 0 or iteration < args.iterations:
                    time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        print("Agent stopped. Outbox and file cursor remain on disk.", file=sys.stderr)
    except (AgentError, OSError) as exc:
        print(f"Continuous agent failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if agent is not None:
            agent.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
