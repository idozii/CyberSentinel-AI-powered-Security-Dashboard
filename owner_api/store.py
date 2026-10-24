"""Local-only owner identity, opaque sessions, and DNS-TXT claims.

Not a hosted identity provider. No cookies, no third-party authentication, no live ingestion.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, type=Type.ID)
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(18))
SESSION_SECONDS = 8 * 60 * 60
CHALLENGE_SECONDS = 24 * 60 * 60
MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 15 * 60
EMAIL_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.!#$%&'*+/=?^_`{|}~-]*@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$", re.ASCII)
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)
RESERVED_SUFFIXES = {"localhost", "local", "internal", "test", "invalid", "example", "home", "lan", "corp", "onion", "arpa"}


class OwnerError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if not 3 <= len(email) <= 254 or not EMAIL_PATTERN.fullmatch(email):
        raise OwnerError("Invalid email address", 422)
    if ".." in email or email.count("@") != 1 or "." not in email.rsplit("@", 1)[1]:
        raise OwnerError("Invalid email address", 422)
    return email


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().removesuffix(".")
    if len(domain) > 253 or len(domain) < 4 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in domain):
        raise OwnerError("Use an ASCII public DNS hostname, not a URL or IP address", 422)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise OwnerError("IP addresses cannot be claimed", 422)
    labels = domain.split(".")
    if len(labels) < 2 or any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise OwnerError("Invalid DNS hostname", 422)
    if labels[-1] in RESERVED_SUFFIXES or labels[-1].isdigit() or (len(labels[-1]) < 2):
        raise OwnerError("Domain must have a public DNS suffix", 422)
    if domain.startswith("xn--") or any(label.startswith("xn--") for label in labels):
        raise OwnerError("Internationalized domains are unsupported in this prototype", 422)
    return domain


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OwnerStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path.parent.chmod(0o700)
        with self._db(write=True) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at REAL NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS domains (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    domain TEXT NOT NULL, challenge_hash TEXT,
                    challenge_expires_at REAL, verified_at REAL,
                    created_at REAL NOT NULL,
                    UNIQUE(user_id, domain)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS domain_one_verified_owner
                    ON domains(domain) WHERE verified_at IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_domain_owner ON domains(user_id);
            """)
        if self.db_path.exists():
            self.db_path.chmod(0o600)

    @contextmanager
    def _db(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write and conn.in_transaction:
                conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def register(self, email: str, password: str) -> dict:
        address = normalize_email(email)
        if len(password) < 12 or len(password) > 128 or len(password.encode("utf-8")) > 512 or not password.strip():
            raise OwnerError("Password must contain 12-128 characters", 422)
        hashed = PASSWORD_HASHER.hash(password)
        uid = uuid.uuid4().hex
        with self._db(write=True) as conn:
            try:
                conn.execute("INSERT INTO users(id,email,password_hash,created_at) VALUES(?,?,?,?)",
                             (uid, address, hashed, time.time()))
            except sqlite3.IntegrityError as exc:
                raise OwnerError("Account already exists", 409) from exc
        return {"id": uid, "email": address}

    def login(self, email: str, password: str) -> dict:
        address = normalize_email(email)
        now = time.time()
        # Write transaction guarantees account-based lockout counters are atomic.
        with self._db(write=True) as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (address,)).fetchone()
            hashed = user["password_hash"] if user else DUMMY_PASSWORD_HASH
            try:
                ok = PASSWORD_HASHER.verify(hashed, password)
            except (VerificationError, VerifyMismatchError, InvalidHashError):
                ok = False
            if user is None or (user["locked_until"] > now):
                raise OwnerError("Invalid credentials or temporarily locked account", 401)
            if not ok:
                attempts = user["failed_attempts"] + 1
                locked = now + LOCK_SECONDS if attempts >= MAX_FAILED_ATTEMPTS else 0
                conn.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",
                             (0 if locked else attempts, locked, user["id"]))
                # An unsuccessful authentication must still COMMIT its counter update.
                return {"error": "Invalid credentials or temporarily locked account"}
            conn.execute("UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=?", (user["id"],))
            token = secrets.token_urlsafe(40)
            expires = now + SESSION_SECONDS
            conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                         (_sha(token), user["id"], expires, now))
            return {"access_token": token, "token_type": "bearer", "expires_at": expires}

    def current_user(self, token: str) -> dict:
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            raise OwnerError("Authentication required", 401)
        with self._db() as conn:
            r = conn.execute("SELECT users.id,users.email,sessions.expires_at FROM sessions "
                             "JOIN users ON users.id=sessions.user_id WHERE token_hash=?", (_sha(token),)).fetchone()
        if not r or r["expires_at"] <= time.time():
            raise OwnerError("Authentication required", 401)
        return {"id": r["id"], "email": r["email"]}

    def logout(self, token: str) -> None:
        with self._db(write=True) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))

    @staticmethod
    def _fresh_challenge() -> tuple[str, str, float]:
        txt = "cybersentinel-verification=" + secrets.token_urlsafe(32)
        return txt, _sha(txt), time.time() + CHALLENGE_SECONDS

    def create_domain(self, uid: str, domain: str) -> dict:
        normalized = normalize_domain(domain)
        txt, challenge_hash, expires = self._fresh_challenge()
        did = uuid.uuid4().hex
        with self._db(write=True) as conn:
            try:
                conn.execute("INSERT INTO domains(id,user_id,domain,challenge_hash,challenge_expires_at,created_at) "
                             "VALUES(?,?,?,?,?,?)", (did, uid, normalized, challenge_hash, expires, time.time()))
            except sqlite3.IntegrityError as exc:
                raise OwnerError("Domain already added to your account", 409) from exc
        return {"id": did, "domain": normalized, "verified": False,
                "txt_name": "_cybersentinel-verify." + normalized,
                "txt_value": txt, "challenge_expires_at": expires}

    def list_domains(self, uid: str) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute("SELECT id,domain,verified_at,challenge_expires_at FROM domains "
                                "WHERE user_id=? ORDER BY domain", (uid,)).fetchall()
        return [self._domain_public(row) for row in rows]

    def get_domain(self, uid: str, did: str) -> dict:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM domains WHERE id=? AND user_id=?", (did,uid)).fetchone()
        if not row:
            raise OwnerError("Domain not found", 404)
        return dict(row)

    @staticmethod
    def _domain_public(row) -> dict:
        return {"id": row["id"], "domain": row["domain"], "verified": row["verified_at"] is not None,
                "verified_at": row["verified_at"], "challenge_expires_at": row["challenge_expires_at"]}

    def rotate_challenge(self, uid: str, did: str) -> dict:
        txt, challenge_hash, expires = self._fresh_challenge()
        with self._db(write=True) as conn:
            row = conn.execute("SELECT * FROM domains WHERE id=? AND user_id=?", (did,uid)).fetchone()
            if not row:
                raise OwnerError("Domain not found", 404)
            if row["verified_at"] is not None:
                raise OwnerError("Domain is already verified", 409)
            conn.execute("UPDATE domains SET challenge_hash=?,challenge_expires_at=? WHERE id=?", (challenge_hash, expires, did))
        return {"id": did, "domain": row["domain"], "txt_name": "_cybersentinel-verify." + row["domain"],
                "txt_value": txt, "challenge_expires_at": expires}

    def verify(self, uid: str, did: str, observed_txt: list[str]) -> dict:
        row = self.get_domain(uid,did)
        if row["verified_at"] is not None:
            return self._domain_public(row)
        if row["challenge_expires_at"] is None or row["challenge_expires_at"] <= time.time():
            raise OwnerError("Challenge expired. Rotate to obtain a new value", 409)
        target_hash = row["challenge_hash"]
        matched = any(secrets.compare_digest(_sha(value), target_hash) for value in observed_txt if isinstance(value,str))
        if not matched:
            raise OwnerError("Expected DNS TXT proof was not found", 422)
        with self._db(write=True) as conn:
            # Re-read inside transaction: a rotation may have invalidated this challenge.
            fresh = conn.execute("SELECT * FROM domains WHERE id=? AND user_id=?", (did,uid)).fetchone()
            if not fresh or fresh["challenge_hash"] != target_hash or fresh["challenge_expires_at"] <= time.time():
                raise OwnerError("Challenge changed or expired", 409)
            already = conn.execute("SELECT id FROM domains WHERE domain=? AND verified_at IS NOT NULL AND id!=?",
                                   (fresh["domain"],did)).fetchone()
            if already:
                raise OwnerError("Domain is already verified by another account", 409)
            now = time.time()
            try:
                conn.execute("UPDATE domains SET verified_at=?,challenge_hash=NULL,challenge_expires_at=NULL WHERE id=?",
                             (now,did))
            except sqlite3.IntegrityError as exc:
                raise OwnerError("Domain is already verified",409) from exc
        return {"id": did, "domain": row["domain"], "verified": True,
                "verified_at": now, "challenge_expires_at": None}

    def delete_domain(self, uid: str, did: str) -> None:
        with self._db(write=True) as conn:
            result = conn.execute("DELETE FROM domains WHERE id=? AND user_id=?", (did,uid))
            if result.rowcount != 1:
                raise OwnerError("Domain not found",404)
