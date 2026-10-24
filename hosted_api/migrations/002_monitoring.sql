-- Step 18: PostgreSQL-only private monitoring pilot.
-- Run as migration owner after 001. Never run as cybersentinel_runtime.
-- Do not alter the applied 001 migration or migrate legacy SQLite data implicitly.
ALTER TABLE cs.domains ADD CONSTRAINT domains_id_owner_unique UNIQUE (id, owner_id);

CREATE TABLE cs.agent_keys (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (domain_id, owner_id) REFERENCES cs.domains(id, owner_id) ON DELETE CASCADE
);
CREATE INDEX agent_keys_owner_domain ON cs.agent_keys(owner_id, domain_id);

CREATE TABLE cs.telemetry_events (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    agent_event_id text NOT NULL CHECK (agent_event_id ~ '^[A-Za-z0-9_-]{16,64}$'),
    occurred_at bigint NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    source_ref text NOT NULL CHECK (source_ref ~ '^[a-f0-9]{32}$'),
    method text NOT NULL CHECK (method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')),
    path_group text NOT NULL CHECK (path_group IN ('login','health','admin','api','other')),
    status_code integer NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    duration_ms double precision NOT NULL CHECK (duration_ms BETWEEN 0 AND 120000),
    request_bytes integer NOT NULL CHECK (request_bytes BETWEEN 0 AND 100000000),
    response_bytes integer NOT NULL CHECK (response_bytes BETWEEN 0 AND 100000000),
    UNIQUE (domain_id, agent_event_id),
    FOREIGN KEY (domain_id, owner_id) REFERENCES cs.domains(id, owner_id) ON DELETE CASCADE
);
CREATE INDEX telemetry_owner_domain_received ON cs.telemetry_events(owner_id, domain_id, received_at DESC);
CREATE INDEX telemetry_detection_window ON cs.telemetry_events(owner_id, domain_id, source_ref, occurred_at);

CREATE TABLE cs.detection_alerts (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    source_ref text NOT NULL CHECK (source_ref ~ '^[a-f0-9]{32}$'),
    window_start bigint NOT NULL,
    rule_id text NOT NULL CHECK (rule_id IN
      ('repeated_login_failures', 'http_404_burst', 'server_error_burst', 'request_volume_spike')),
    severity text NOT NULL CHECK (severity IN ('low','medium','high')),
    title text NOT NULL,
    explanation text NOT NULL,
    observed_count integer NOT NULL CHECK (observed_count >= 0),
    threshold_count integer NOT NULL CHECK (threshold_count > 0),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged')),
    first_detected_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    UNIQUE (domain_id, source_ref, window_start, rule_id),
    FOREIGN KEY (domain_id, owner_id) REFERENCES cs.domains(id, owner_id) ON DELETE CASCADE
);
CREATE INDEX alerts_owner_domain_window ON cs.detection_alerts(owner_id,domain_id,window_start DESC);

ALTER TABLE cs.agent_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE cs.agent_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE cs.telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE cs.telemetry_events FORCE ROW LEVEL SECURITY;
ALTER TABLE cs.detection_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cs.detection_alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_keys_tenant ON cs.agent_keys FOR ALL TO cybersentinel_runtime
 USING (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid)
 WITH CHECK (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid);
CREATE POLICY telemetry_tenant ON cs.telemetry_events FOR ALL TO cybersentinel_runtime
 USING (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid)
 WITH CHECK (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid);
CREATE POLICY alerts_tenant ON cs.detection_alerts FOR ALL TO cybersentinel_runtime
 USING (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid)
 WITH CHECK (owner_id = nullif(current_setting('cs.actor_id',true),'')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON cs.agent_keys TO cybersentinel_runtime;
GRANT SELECT, INSERT, DELETE ON cs.telemetry_events TO cybersentinel_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON cs.detection_alerts TO cybersentinel_runtime;
