-- Asset Discovery: candidates, provenance, enrichment, classification,
-- installation-wide provider cache/limiter and chain stage inputs.
-- Applied migrations 0001/0002 are never edited.

CREATE TABLE IF NOT EXISTS discovery_candidates (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    -- not_checked | verified | no_addresses | dns_error | not_permitted
    dns_status TEXT NOT NULL DEFAULT 'not_checked',
    -- matched | not_matched | unknown
    ip_match TEXT NOT NULL DEFAULT 'unknown',
    addresses TEXT NOT NULL DEFAULT '[]',
    last_checked_at TEXT,
    scope_status TEXT NOT NULL DEFAULT 'observed',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, hostname)
);
CREATE INDEX IF NOT EXISTS idx_candidates_project
    ON discovery_candidates(project_id, hostname);
CREATE INDEX IF NOT EXISTS idx_candidates_filters
    ON discovery_candidates(project_id, dns_status, ip_match, last_seen DESC);

CREATE TABLE IF NOT EXISTS candidate_evidence (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES discovery_candidates(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    attempt_id TEXT REFERENCES job_attempts(id) ON DELETE SET NULL,
    attempt_key TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    source_ip TEXT,
    source_ip_key TEXT NOT NULL DEFAULT '',
    data_type TEXT NOT NULL,
    dns_status TEXT,
    addresses TEXT NOT NULL DEFAULT '[]',
    ip_match TEXT,
    reason TEXT,
    error TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(attempt_key, candidate_id, source, data_type, source_ip_key)
);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate
    ON candidate_evidence(candidate_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_job
    ON candidate_evidence(job_id, data_type);

CREATE TABLE IF NOT EXISTS asset_enrichments (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    candidate_id TEXT REFERENCES discovery_candidates(id) ON DELETE SET NULL,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    attempt_id TEXT REFERENCES job_attempts(id) ON DELETE SET NULL,
    host TEXT NOT NULL,
    format_version TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enrichments_host
    ON asset_enrichments(project_id, host, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_enrichments_job
    ON asset_enrichments(job_id);

CREATE TABLE IF NOT EXISTS asset_classifications (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    host TEXT,
    catalog_version INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    interest TEXT NOT NULL,
    groups TEXT NOT NULL DEFAULT '[]',
    categories TEXT NOT NULL DEFAULT '[]',
    technologies TEXT NOT NULL DEFAULT '[]',
    surface_hints TEXT NOT NULL DEFAULT '[]',
    reasons TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, subject_type, subject_id)
);
CREATE INDEX IF NOT EXISTS idx_classifications_host
    ON asset_classifications(project_id, host);
CREATE INDEX IF NOT EXISTS idx_classifications_updated
    ON asset_classifications(project_id, updated_at DESC);

-- Installation-wide cache. The key never contains tokens or provider URLs
-- with credentials; only the provider, api version, endpoint and a hashed
-- credential context are used for namespacing.
CREATE TABLE IF NOT EXISTS provider_cache (
    cache_key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    api_version TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    credential_context TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    body TEXT NOT NULL,
    negative INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_cache_expiry
    ON provider_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_provider_cache_provider
    ON provider_cache(provider, created_at DESC);

CREATE TABLE IF NOT EXISTS provider_reservations (
    cache_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_reservation_expiry
    ON provider_reservations(expires_at);

CREATE TABLE IF NOT EXISTS provider_state (
    provider TEXT NOT NULL,
    namespace TEXT NOT NULL,
    next_allowed_at TEXT,
    cooldown_until TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(provider, namespace)
);

ALTER TABLE chain_runs ADD COLUMN preset TEXT;
ALTER TABLE chain_stages ADD COLUMN input_refs TEXT;
