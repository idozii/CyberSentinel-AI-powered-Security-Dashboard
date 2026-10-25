"""CI-only additive RLS migration and rollback on a NEW disposable database.

Never connect to Neon, modify existing cs.* schema, or use this for production.
The entire database is created with a fresh random name in GitHub Actions and
is destroyed after the test. Baseline migration files are read, not edited.
"""
from __future__ import annotations

import re
import secrets
import uuid
from pathlib import Path

from scripts.step41_role_boundary import protected_ci

ROOT = Path(__file__).resolve().parents[1]
DB_RE = re.compile(r'^cs46_[a-f0-9]{12}$')
TABLES = {
    'identities': ('id', 'SELECT, INSERT, UPDATE'),
    'domains': ('owner_id', 'SELECT, INSERT, UPDATE, DELETE'),
    'agent_keys': ('owner_id', 'SELECT, INSERT, UPDATE, DELETE'),
    'telemetry_events': ('owner_id', 'SELECT, INSERT, DELETE'),
    'detection_alerts': ('owner_id', 'SELECT, INSERT, UPDATE, DELETE'),
}


class DisposableSchemaRehearsal:
    def __init__(self, admin_dsn: str):
        protected_ci(admin_dsn)
        self.admin_dsn = admin_dsn
        self.name = 'cs46_' + secrets.token_hex(6)
        self.roles = (self.name + '_a', self.name + '_b')
        self.passwords = (secrets.token_urlsafe(32), secrets.token_urlsafe(32))
        self.owners = (uuid.uuid4(), uuid.uuid4())
        self.created = False
        self.created_roles: list[str] = []
        self.reverted = False
        self.baseline_policies: set[tuple[str, str]] = set()
        self.synthetic_domain_ids: list[uuid.UUID] = []

    def _guard(self) -> None:
        protected_ci(self.admin_dsn)
        if not DB_RE.fullmatch(self.name):
            raise RuntimeError('Refusing unexpected disposable database name')
        if self.roles != (self.name + '_a', self.name + '_b'):
            raise RuntimeError('Refusing unexpected tenant login roles')

    def _admin(self):
        self._guard()
        if not self.created:
            raise RuntimeError('Disposable database not yet created')
        import psycopg
        from psycopg.conninfo import make_conninfo
        return psycopg.connect(make_conninfo(self.admin_dsn, dbname=self.name), connect_timeout=4)

    def tenant(self, index: int):
        """New connection with a genuine tenant DB LOGIN, never a SET ROLE."""
        self._guard()
        if not self.created or index not in (0, 1) or self.reverted:
            raise ValueError('Invalid tenant connection state')
        import psycopg
        from psycopg.conninfo import make_conninfo
        dsn = make_conninfo(self.admin_dsn, dbname=self.name,
                            user=self.roles[index], password=self.passwords[index])
        return psycopg.connect(dsn, connect_timeout=4)

    def _policies(self) -> set[tuple[str, str]]:
        with self._admin() as db:
            return set(db.execute("""SELECT tablename, policyname FROM pg_policies
                WHERE schemaname = 'cs' AND tablename <> 'tenant_login_map'""").fetchall())

    def prepare(self) -> None:
        """Create a fresh database; never reuse an existing database."""
        self._guard()
        if self.created:
            raise RuntimeError('Rehearsal already prepared')
        import psycopg
        from psycopg import sql
        with psycopg.connect(self.admin_dsn, autocommit=True, connect_timeout=4) as root:
            root.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(self.name)))
        self.created = True
        with psycopg.connect(self.admin_dsn, autocommit=True, connect_timeout=4) as root:
            root.execute(sql.SQL('REVOKE CONNECT ON DATABASE {} FROM PUBLIC').format(sql.Identifier(self.name)))
        with self._admin() as db:
            current = db.execute('SELECT current_database()').fetchone()[0]
            if current != self.name:
                raise RuntimeError('Disposable database mismatch')
            # Read the actual schema migrations from this repository, unchanged.
            for migration in ('001_initial.sql', '002_monitoring.sql'):
                source = (ROOT / 'hosted_api' / 'migrations' / migration).read_text(encoding='utf-8')
                db.execute(source)
        self.baseline_policies = self._policies()
        if len(self.baseline_policies) != len(TABLES):
            raise RuntimeError('Unexpected baseline RLS policies')

    def install_additive_policies(self) -> None:
        """Proof-only additional RLS policies scoped to two synthetic DB roles."""
        self._guard()
        if not self.created or not self.baseline_policies or self.created_roles:
            raise RuntimeError('Invalid migration sequence')
        from psycopg import sql
        roles = sql.SQL(', ').join(sql.Identifier(role) for role in self.roles)
        with self._admin() as db:
            for role, password, owner in zip(self.roles, self.passwords, self.owners):
                db.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} '
                                   'NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION')
                           .format(sql.Identifier(role), sql.Literal(password)))
                self.created_roles.append(role)
                # No arbitrary role membership, only CONNECT to this disposable DB.
                db.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}')
                           .format(sql.Identifier(self.name), sql.Identifier(role)))
            db.execute('CREATE TABLE cs.tenant_login_map ('
                       'login_role name PRIMARY KEY, owner_id uuid UNIQUE NOT NULL)')
            with db.cursor() as cur:
                cur.executemany('INSERT INTO cs.tenant_login_map (login_role,owner_id) VALUES (%s,%s)',
                                list(zip(self.roles, self.owners)))
            db.execute('ALTER TABLE cs.tenant_login_map ENABLE ROW LEVEL SECURITY')
            db.execute('ALTER TABLE cs.tenant_login_map FORCE ROW LEVEL SECURITY')
            db.execute(sql.SQL('CREATE POLICY cs46_map_read ON cs.tenant_login_map '
                               'FOR SELECT TO {} USING (login_role = session_user)').format(roles))
            db.execute(sql.SQL('GRANT USAGE ON SCHEMA cs TO {}').format(roles))
            db.execute(sql.SQL('GRANT SELECT ON cs.tenant_login_map TO {}').format(roles))
            lookup = sql.SQL('(SELECT owner_id FROM cs.tenant_login_map '
                             'WHERE login_role = session_user)')
            for table, (owner_column, grants) in TABLES.items():
                db.execute(sql.SQL('GRANT ' + grants + ' ON cs.{} TO {}').format(
                    sql.Identifier(table), roles))
                predicate = sql.SQL('{} = {}').format(sql.Identifier(owner_column), lookup)
                db.execute(sql.SQL('CREATE POLICY cs46_role_bound ON cs.{} '
                                   'FOR ALL TO {} USING ({}) WITH CHECK ({})').format(
                                       sql.Identifier(table), roles, predicate, predicate))
        if len(self._policies()) != len(self.baseline_policies) + len(TABLES):
            raise RuntimeError('Additive RLS policies not installed')

    def seed_synthetic(self) -> None:
        """Write one fabricated row per role into all five real cs.* tables."""
        self._guard()
        import hashlib
        with self._admin() as db:
            for idx, owner in enumerate(self.owners):
                did = uuid.uuid4()
                self.synthetic_domain_ids.append(did)
                db.execute('INSERT INTO cs.identities(id,issuer,subject) VALUES (%s,%s,%s)',
                           (owner, 'https://issuer.example.org/', 'synthetic-' + self.name + str(idx)))
                db.execute('INSERT INTO cs.domains(id,owner_id,domain) VALUES (%s,%s,%s)',
                           (did, owner, f'{self.name}-{idx}.example.org'))
                db.execute('INSERT INTO cs.agent_keys(id,owner_id,domain_id,token_hash,label) '
                           'VALUES (%s,%s,%s,%s,%s)',
                           (uuid.uuid4(), owner, did,
                            hashlib.sha256(f'{self.name}-{idx}'.encode()).hexdigest(), 'fixture'))
                db.execute('''INSERT INTO cs.telemetry_events
                    (id,owner_id,domain_id,agent_event_id,occurred_at,source_ref,method,
                     path_group,status_code,duration_ms,request_bytes,response_bytes)
                     VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                           (uuid.uuid4(), owner, did, uuid.uuid4().hex, 1700000000,
                            uuid.uuid4().hex, 'GET', 'health', 200, 1.0, 10, 20))
                db.execute('''INSERT INTO cs.detection_alerts
                    (id,owner_id,domain_id,source_ref,window_start,rule_id,severity,
                     title,explanation,observed_count,threshold_count)
                     VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                           (uuid.uuid4(), owner, did, uuid.uuid4().hex, 1700000000,
                            'request_volume_spike', 'low', 'Synthetic', 'CI fixture', 10, 5))

    def assert_tenant_scope(self) -> None:
        """Check real row visibility under the login roles, even with spoofed GUC."""
        self._guard()
        for index in (0, 1):
            with self.tenant(index) as db:
                identity = db.execute('SELECT session_user, current_user').fetchone()
                if identity != (self.roles[index], self.roles[index]):
                    raise AssertionError('Unexpected login identity')
                db.execute('SELECT set_config(%s,%s,true)',
                           ('cs.actor_id', str(self.owners[1 - index])))
                for table in TABLES:
                    from psycopg import sql
                    rows = db.execute(sql.SQL('SELECT {} FROM cs.{}').format(
                        sql.Identifier(TABLES[table][0]), sql.Identifier(table))).fetchall()
                    if rows != [(self.owners[index],)]:
                        raise AssertionError('Tenant isolation failed on ' + table)
                mapping = db.execute('SELECT owner_id FROM cs.tenant_login_map').fetchall()
                if mapping != [(self.owners[index],)]:
                    raise AssertionError('Role mapping leaked another tenant')

    def rollback(self) -> None:
        """Revert additive policies and grants; preserve baseline and test rows."""
        self._guard()
        if not self.created or not self.created_roles or self.reverted:
            raise RuntimeError('Invalid rollback sequence')
        from psycopg import sql
        roles = sql.SQL(', ').join(sql.Identifier(role) for role in self.roles)
        with self._admin() as db:
            for table in TABLES:
                db.execute(sql.SQL('DROP POLICY cs46_role_bound ON cs.{}').format(
                    sql.Identifier(table)))
            db.execute(sql.SQL('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA cs FROM {}').format(roles))
            db.execute(sql.SQL('REVOKE ALL ON SCHEMA cs FROM {}').format(roles))
            db.execute('DROP TABLE cs.tenant_login_map')
            for role in self.roles:
                db.execute(sql.SQL('REVOKE CONNECT ON DATABASE {} FROM {}').format(
                    sql.Identifier(self.name), sql.Identifier(role)))
                db.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        self.reverted = True
        if self._policies() != self.baseline_policies:
            raise AssertionError('Baseline policies changed during rollback')
        with self._admin() as db:
            for table in TABLES:
                count = db.execute(sql.SQL('SELECT count(*) FROM cs.{}').format(
                    sql.Identifier(table))).fetchone()[0]
                if count != 2:
                    raise AssertionError('Synthetic records changed during rollback: ' + table)

    def close(self) -> None:
        """Destroy only database this instance successfully created."""
        self._guard()
        if not self.created:
            return
        import psycopg
        from psycopg import sql
        with psycopg.connect(self.admin_dsn, autocommit=True, connect_timeout=4) as root:
            root.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(self.name)))
            for role in self.roles:
                if role in self.created_roles:
                    root.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
        self.created = False
