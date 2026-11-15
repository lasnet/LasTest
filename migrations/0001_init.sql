-- LasTest 2.0 initial schema. All timestamps are UTC RFC 3339 strings.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('web', 'cli')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    stopped_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    client TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    source TEXT,
    source_project_id TEXT,
    archived INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name);

CREATE TABLE IF NOT EXISTS scope_revisions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    rules TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'pending_review', 'approved')),
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    UNIQUE(project_id, version)
);
CREATE INDEX IF NOT EXISTS idx_scope_project ON scope_revisions(project_id, version DESC);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    task_type TEXT NOT NULL,
    params TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled', 'interrupted')),
    scope_revision_id TEXT NOT NULL REFERENCES scope_revisions(id),
    scope_version INTEGER NOT NULL,
    idempotency_key TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    result TEXT NOT NULL DEFAULT '{}',
    counters TEXT NOT NULL DEFAULT '{}',
    current_attempt_id TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    chain_run_id TEXT,
    chain_order INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency
    ON jobs(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_queue ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS job_attempts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    heartbeat_at TEXT NOT NULL,
    lease_until TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_job ON job_attempts(job_id, started_at DESC);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(project_id, kind, canonical_value)
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    attempt_id TEXT REFERENCES job_attempts(id) ON DELETE SET NULL,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    asset TEXT NOT NULL,
    canonical_asset TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    scope_status TEXT NOT NULL CHECK (scope_status IN ('allowed', 'denied', 'observed')),
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_project_kind
    ON observations(project_id, kind, observed_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    asset TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(project_id, rule_id, asset, rule_version)
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, severity, last_seen DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    attempt_id TEXT REFERENCES job_attempts(id) ON DELETE SET NULL,
    relative_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, relative_path)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_job ON artifacts(job_id);

CREATE TABLE IF NOT EXISTS chain_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_chains_project ON chain_runs(project_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_chains_idempotency
    ON chain_runs(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS chain_stages (
    id TEXT PRIMARY KEY,
    chain_run_id TEXT NOT NULL REFERENCES chain_runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    task_type TEXT NOT NULL,
    job_id TEXT,
    input_from TEXT,
    required INTEGER NOT NULL DEFAULT 1,
    skipped_reason TEXT,
    UNIQUE(chain_run_id, position)
);

CREATE TABLE IF NOT EXISTS import_records (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_table TEXT NOT NULL,
    target_id TEXT NOT NULL,
    import_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, source_kind, source_id)
);
CREATE INDEX IF NOT EXISTS idx_import_records_target ON import_records(target_table, target_id);

CREATE TABLE IF NOT EXISTS import_runs (
    id TEXT PRIMARY KEY,
    source_root TEXT NOT NULL,
    mode TEXT NOT NULL,
    stats TEXT NOT NULL,
    report TEXT NOT NULL,
    created_at TEXT NOT NULL
);
