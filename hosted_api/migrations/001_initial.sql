-- Apply ONLY with the migration/admin role, not the application login role.
-- The application role cybersentinel_runtime must already exist.
-- It must be NOSUPERUSER, NOBYPASSRLS and must not own these tables.
CREATE SCHEMA IF NOT EXISTS cs;
REVOKE ALL ON SCHEMA cs FROM PUBLIC;
CREATE TABLE cs.identities (
    id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);
CREATE TABLE cs.domains (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES cs.identities(id) ON DELETE CASCADE,
    domain text NOT NULL,
    challenge_hash text,
    challenge_expires_at timestamptz,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_id, domain)
);
CREATE UNIQUE INDEX domains_one_verified_owner ON cs.domains (domain)
    WHERE verified_at IS NOT NULL;
CREATE INDEX domains_by_owner ON cs.domains (owner_id);
ALTER TABLE cs.identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE cs.identities FORCE ROW LEVEL SECURITY;
ALTER TABLE cs.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE cs.domains FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_isolation ON cs.identities
    FOR ALL TO cybersentinel_runtime
    USING (id = nullif(current_setting('cs.actor_id', true), '')::uuid)
    WITH CHECK (id = nullif(current_setting('cs.actor_id', true), '')::uuid);
CREATE POLICY domain_isolation ON cs.domains
    FOR ALL TO cybersentinel_runtime
    USING (owner_id = nullif(current_setting('cs.actor_id', true), '')::uuid)
    WITH CHECK (owner_id = nullif(current_setting('cs.actor_id', true), '')::uuid);
GRANT USAGE ON SCHEMA cs TO cybersentinel_runtime;
GRANT SELECT, INSERT, UPDATE ON cs.identities TO cybersentinel_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON cs.domains TO cybersentinel_runtime;
