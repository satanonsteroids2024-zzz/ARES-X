-- ===================================================================
-- ARES X v8.0 TITAN ENTERPRISE — SQLite Schema
-- ===================================================================
-- This schema is ADDITIVE. It lives in a separate database file
-- (titan.db) from v6's mike_v3.db so v6 memory remains untouched.
--
-- Every table is created with IF NOT EXISTS — schema is idempotent
-- and can be re-applied on every boot without data loss.
--
-- Cross-references:
--   • TITAN Phase 1 (TRD Section 3.1, Build Prompt Section 3 Phase 1)
--   • ENTERPRISE Phase 9-11 (Build Prompt Section 4)
-- ===================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

-- -------------------------------------------------------------------
-- SCHEMA VERSION TRACKING (used by migrations.py)
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    note        TEXT
);

-- ===================================================================
-- TITAN — EVIDENCE VAULT
-- Append-only by Engineering Order 17. Triggers below enforce.
-- ===================================================================
CREATE TABLE IF NOT EXISTS evidence_vault (
    evidence_id          TEXT PRIMARY KEY,
    mission_id           TEXT,
    source_tool          TEXT NOT NULL,
    source_url           TEXT,
    collection_timestamp TIMESTAMP NOT NULL,
    ntp_timestamp        TIMESTAMP,
    raw_data             BLOB,
    raw_data_hash        TEXT NOT NULL,
    merkle_root          TEXT,
    merkle_proof         TEXT,                -- JSON
    analyst_id           TEXT,
    approval_gate_id     TEXT,
    chain_position       INTEGER,
    prev_hash            TEXT,
    encryption_scheme    TEXT DEFAULT 'aes-256-gcm',   -- 'aes-256-gcm' | 'hybrid-pq-kyber768-aes256gcm'
    archived             INTEGER DEFAULT 0,            -- soft-archive only (Order 17)
    archived_at          TIMESTAMP,
    metadata             TEXT                          -- JSON
);

CREATE INDEX IF NOT EXISTS idx_evidence_mission     ON evidence_vault(mission_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_chain_pos ON evidence_vault(chain_position);
CREATE INDEX IF NOT EXISTS idx_evidence_collected   ON evidence_vault(collection_timestamp);

-- Append-only enforcement
CREATE TRIGGER IF NOT EXISTS evidence_vault_no_update
BEFORE UPDATE ON evidence_vault
FOR EACH ROW
WHEN NEW.archived = OLD.archived AND NEW.archived_at IS OLD.archived_at
BEGIN
    SELECT RAISE(ABORT, 'evidence_vault is append-only (Order 17). Only soft-archive permitted.');
END;

CREATE TRIGGER IF NOT EXISTS evidence_vault_no_delete
BEFORE DELETE ON evidence_vault
BEGIN
    SELECT RAISE(ABORT, 'evidence_vault is append-only (Order 17). Hard-delete forbidden.');
END;

-- ===================================================================
-- TITAN — MISSION OS
-- ===================================================================
CREATE TABLE IF NOT EXISTS missions (
    mission_id          TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    goal                TEXT NOT NULL,
    status              TEXT DEFAULT 'active',     -- active | paused | complete | failed | cancelled
    priority            INTEGER DEFAULT 5,         -- 1 (highest) … 9 (lowest)
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMP,
    agent_assignments   TEXT,                       -- JSON
    objective_ids       TEXT,                       -- JSON list of objective_id
    resource_budget     TEXT,                       -- JSON {tokens, time_s, api_quota}
    parent_mission_id   TEXT,                       -- for branches
    is_response_mission INTEGER DEFAULT 0,          -- 1 if launched by threat_responder
    metadata            TEXT                        -- JSON
);

CREATE INDEX IF NOT EXISTS idx_missions_status   ON missions(status);
CREATE INDEX IF NOT EXISTS idx_missions_priority ON missions(priority);

CREATE TABLE IF NOT EXISTS mission_objectives (
    objective_id     TEXT PRIMARY KEY,
    mission_id       TEXT NOT NULL REFERENCES missions(mission_id) ON DELETE CASCADE,
    description      TEXT NOT NULL,
    completion_pct   REAL DEFAULT 0.0,             -- 0.0–1.0
    status           TEXT DEFAULT 'pending',       -- pending | active | complete | failed | skipped
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at     TIMESTAMP,
    evidence_count   INTEGER DEFAULT 0,
    dependencies     TEXT,                          -- JSON list of objective_id
    required_tools   TEXT,                          -- JSON list
    assigned_agent   TEXT
);

CREATE INDEX IF NOT EXISTS idx_objectives_mission ON mission_objectives(mission_id);

CREATE TABLE IF NOT EXISTS mission_events (
    event_id     TEXT PRIMARY KEY,
    mission_id   TEXT NOT NULL REFERENCES missions(mission_id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    agent_id     TEXT,
    payload      TEXT,                              -- JSON
    timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sequence_num INTEGER NOT NULL                   -- monotonic per mission (Order 16)
);

CREATE INDEX IF NOT EXISTS idx_mission_events_mission_seq
    ON mission_events(mission_id, sequence_num);

CREATE TABLE IF NOT EXISTS mission_branches (
    branch_id          TEXT PRIMARY KEY,
    parent_mission_id  TEXT NOT NULL REFERENCES missions(mission_id),
    forked_at_event    INTEGER NOT NULL,            -- sequence_num at branch point
    hypothesis         TEXT,
    status             TEXT DEFAULT 'active',
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===================================================================
-- TITAN — WATCHLISTS
-- ===================================================================
CREATE TABLE IF NOT EXISTS watchlists (
    watchlist_id            TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    entity_type             TEXT,                       -- person | org | domain | ip | hash | other
    query                   TEXT NOT NULL,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked            TIMESTAMP,
    check_interval_seconds  INTEGER DEFAULT 3600,
    alert_threshold         REAL    DEFAULT 0.3,
    current_risk_score      REAL    DEFAULT 0.0,
    status                  TEXT    DEFAULT 'active',   -- active | paused | archived
    metadata                TEXT                         -- JSON
);

CREATE INDEX IF NOT EXISTS idx_watchlists_status ON watchlists(status);

CREATE TABLE IF NOT EXISTS watchlist_events (
    event_id      TEXT PRIMARY KEY,
    watchlist_id  TEXT NOT NULL REFERENCES watchlists(watchlist_id) ON DELETE CASCADE,
    detected_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    change_type   TEXT,
    change_score  REAL,
    payload       TEXT,                                  -- JSON
    alerted       INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_watchlist_events_wl ON watchlist_events(watchlist_id);

-- ===================================================================
-- TITAN — APPROVAL GATES (Order 19: deterministic block)
-- ===================================================================
CREATE TABLE IF NOT EXISTS approval_gates (
    gate_id             TEXT PRIMARY KEY,
    action_type         TEXT NOT NULL,                  -- SIGINT_ACTIVE | EXTERNAL_SHARE | HUMAN_TWIN_BUILD | ACTIVE_SCAN | THREAT_RESPONSE_EXTERNAL
    action_payload      TEXT,                            -- JSON
    requested_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at         TIMESTAMP,
    approved_by         TEXT,
    approval_signature  TEXT,                            -- HMAC-SHA256
    status              TEXT DEFAULT 'pending',          -- pending | approved | denied | expired
    expires_at          TIMESTAMP,
    risk_level          TEXT DEFAULT 'medium'            -- low | medium | high | critical
);

CREATE INDEX IF NOT EXISTS idx_gates_status ON approval_gates(status);

-- ===================================================================
-- TITAN — FUSION SOURCE RELIABILITY (Phase 2)
-- ===================================================================
CREATE TABLE IF NOT EXISTS source_reliability (
    source_tool          TEXT PRIMARY KEY,
    reliability_score    REAL NOT NULL DEFAULT 0.5,     -- 0.0–1.0
    historical_accuracy  REAL DEFAULT 0.5,
    corroboration_rate   REAL DEFAULT 0.5,
    sample_count         INTEGER DEFAULT 0,
    last_updated         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes                TEXT
);

-- Seed initial reliability scores per spec
INSERT OR IGNORE INTO source_reliability (source_tool, reliability_score, notes) VALUES
    ('dark_web',          0.40, 'Initial seed per TRD §3.1'),
    ('social_media',      0.60, 'Initial seed per TRD §3.1'),
    ('official_registry', 0.90, 'Initial seed per TRD §3.1'),
    ('direct_dns',        0.95, 'Initial seed per TRD §3.1'),
    ('shodan',            0.85, 'Initial seed'),
    ('censys',            0.85, 'Initial seed'),
    ('virustotal',        0.80, 'Initial seed'),
    ('crt_sh',            0.95, 'Initial seed'),
    ('whois',             0.85, 'Initial seed'),
    ('rdap',              0.90, 'Initial seed');

-- ===================================================================
-- TITAN — FUSION RESULTS BUFFER
-- ===================================================================
CREATE TABLE IF NOT EXISTS fusion_assertions (
    assertion_id        TEXT PRIMARY KEY,
    entity_id           TEXT NOT NULL,
    attribute           TEXT NOT NULL,
    value               TEXT,
    confidence          REAL NOT NULL,                  -- 0.0–1.0
    supporting_evidence TEXT,                            -- JSON list of evidence_id
    contradicting       TEXT,                            -- JSON list of evidence_id
    fused_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    explanation         TEXT                             -- human-readable provenance
);

CREATE INDEX IF NOT EXISTS idx_fusion_entity ON fusion_assertions(entity_id);

-- ===================================================================
-- TITAN — FUSION BUFFER (Phase 2: rolling 24h evidence per entity)
-- ===================================================================
-- The buffer holds raw evidence pieces awaiting fusion. The fusion
-- engine drains entities whose buffer exceeds 3 pieces OR which are
-- older than 5 minutes (the time-based trigger).
CREATE TABLE IF NOT EXISTS fusion_buffer (
    buffer_id        TEXT PRIMARY KEY,
    entity_id        TEXT NOT NULL,
    evidence_id      TEXT,                             -- optional FK to evidence_vault
    source_tool      TEXT NOT NULL,
    attribute        TEXT NOT NULL,
    value            TEXT NOT NULL,
    domain           TEXT,                              -- OSINT | SIGINT | FININT | ...
    evidence_score   REAL DEFAULT 1.0,                  -- 0.0–1.0
    raw_text         TEXT,
    collected_at     REAL NOT NULL,                     -- unix epoch (sortable, sub-second)
    metadata         TEXT,                              -- JSON
    consumed_at      REAL                               -- NULL until fused into an assertion
);

CREATE INDEX IF NOT EXISTS idx_buffer_entity_time
    ON fusion_buffer(entity_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_buffer_unconsumed
    ON fusion_buffer(consumed_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS contradictions (
    contradiction_id  TEXT PRIMARY KEY,
    entity_id         TEXT NOT NULL,
    attribute         TEXT NOT NULL,
    evidence_a_id     TEXT NOT NULL,
    evidence_b_id     TEXT NOT NULL,
    resolution_mode   TEXT,                              -- auto | human_review | unresolved
    resolved_value    TEXT,
    resolved_at       TIMESTAMP,
    detected_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===================================================================
-- TITAN — DIGITAL TWIN METADATA (graph lives in Kuzu; metadata here)
-- ===================================================================
CREATE TABLE IF NOT EXISTS twin_registry (
    twin_id           TEXT PRIMARY KEY,
    twin_type         TEXT NOT NULL,                   -- org | infra | adversary | human | supply_chain | cyber_terrain | timeline
    entity_id         TEXT NOT NULL,
    entity_name       TEXT,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    snapshot_count    INTEGER DEFAULT 0,
    confidence_score  REAL DEFAULT 0.0,
    freshness_score   REAL DEFAULT 1.0,                -- decays via Order 14
    status            TEXT DEFAULT 'active',            -- active | stale | archived | building
    refresh_interval  INTEGER DEFAULT 21600             -- seconds (6h default)
);

CREATE INDEX IF NOT EXISTS idx_twin_type   ON twin_registry(twin_type);
CREATE INDEX IF NOT EXISTS idx_twin_status ON twin_registry(status);

-- ===================================================================
-- ENTERPRISE — SOVEREIGN AI MODEL REGISTRY (Phase 9)
-- ===================================================================
CREATE TABLE IF NOT EXISTS sovereign_models (
    model_id          TEXT PRIMARY KEY,
    name              TEXT,
    provider          TEXT,
    version           TEXT,
    quantization      TEXT,
    task_affinities   TEXT,
    perf_metrics      TEXT,
    status            TEXT DEFAULT 'active',
    tokens_processed  INTEGER DEFAULT 0,
    avg_latency_ms    REAL DEFAULT 0.0,
    error_rate        REAL DEFAULT 0.0,
    registered_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at      TIMESTAMP,
    is_local          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sovereign_inference_log (
    log_id        TEXT PRIMARY KEY,
    model_used    TEXT NOT NULL,
    task_type     TEXT,
    tokens_in     INTEGER,
    tokens_out    INTEGER,
    latency_ms    INTEGER,
    success       INTEGER DEFAULT 1,
    error_msg     TEXT,
    called_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    feature_id    TEXT                                  -- which ARES feature triggered this
);

CREATE INDEX IF NOT EXISTS idx_inf_log_called   ON sovereign_inference_log(called_at);
CREATE INDEX IF NOT EXISTS idx_inf_log_feature  ON sovereign_inference_log(feature_id);

CREATE TABLE IF NOT EXISTS compute_budget (
    budget_id        TEXT PRIMARY KEY,
    day              DATE NOT NULL,
    feature_id       TEXT,
    tokens_consumed  INTEGER DEFAULT 0,
    quota            INTEGER,                           -- NULL = unlimited
    UNIQUE(day, feature_id)
);

-- ===================================================================
-- ENTERPRISE — RAG / FEDERATED SEARCH (Phase 10)
-- Vector storage lives in LanceDB; this is metadata + sessions only
-- ===================================================================
CREATE TABLE IF NOT EXISTS rag_documents (
    doc_id           TEXT PRIMARY KEY,
    source_path      TEXT,
    source_url       TEXT,
    content_hash     TEXT NOT NULL,                    -- dedup key
    title            TEXT,
    doc_type         TEXT,                              -- pdf | docx | html | md | mission_finding | osint_result
    ingested_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    chunk_count      INTEGER DEFAULT 0,
    auto_ingested    INTEGER DEFAULT 0,                -- 1 if from knowledge_base.py auto-pop
    metadata         TEXT                               -- JSON
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rag_hash ON rag_documents(content_hash);

CREATE TABLE IF NOT EXISTS search_sessions (
    session_id        TEXT PRIMARY KEY,
    query             TEXT NOT NULL,
    systems_queried   TEXT,                             -- JSON list
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_run_at       TIMESTAMP,
    schedule_cron     TEXT,                             -- NULL = one-shot
    alert_on_delta    INTEGER DEFAULT 0,
    result_snapshot   TEXT                              -- JSON of last result IDs for delta detection
);

-- ===================================================================
-- ENTERPRISE — POST-QUANTUM SECURITY (Phase 11)
-- ===================================================================
CREATE TABLE IF NOT EXISTS audit_log_v2 (
    log_id           TEXT PRIMARY KEY,
    sequence_num     INTEGER NOT NULL UNIQUE,           -- monotonic
    actor            TEXT NOT NULL,                     -- user | system | agent_id
    action           TEXT NOT NULL,
    resource         TEXT,
    payload          TEXT,                              -- JSON
    -- timestamp is the canonical hash-input string (f"{unix_ts:.6f}")
    -- It is stored as TEXT (not TIMESTAMP) so SQLite type affinity does
    -- not coerce it to a numeric and lose precision when re-read.
    timestamp        TEXT NOT NULL,
    prev_sha3_hash   TEXT,                              -- SHA3-256 of previous record
    this_sha3_hash   TEXT NOT NULL                      -- SHA3-256 of this record
);

CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log_v2(sequence_num);

-- Audit log is inviolable (Order 27)
CREATE TRIGGER IF NOT EXISTS audit_log_v2_no_update
BEFORE UPDATE ON audit_log_v2
BEGIN
    SELECT RAISE(ABORT, 'audit_log_v2 is inviolable (Order 27).');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_v2_no_delete
BEFORE DELETE ON audit_log_v2
BEGIN
    SELECT RAISE(ABORT, 'audit_log_v2 is inviolable (Order 27).');
END;

CREATE TABLE IF NOT EXISTS key_rotation_log (
    rotation_id    TEXT PRIMARY KEY,
    key_type       TEXT NOT NULL,                       -- pq_kyber | pq_dilithium | aes_master | mtls_ca
    rotated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_fingerprint TEXT,
    new_fingerprint TEXT,
    rotated_by     TEXT,
    success        INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS hsm_attestation (
    attestation_id TEXT PRIMARY KEY,
    hsm_type       TEXT,                                 -- tpm2 | fido2 | software_fallback
    attested_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pcr_values     TEXT,                                 -- JSON for TPM
    cert_chain     TEXT,
    valid          INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS compliance_checks (
    check_id        TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,                       -- nist_800_53 | soc2 | fedramp_moderate | nist_csf
    control_id      TEXT NOT NULL,                       -- e.g. "AC-2", "CC6.1"
    status          TEXT NOT NULL,                       -- pass | fail | not_applicable | manual_review
    evidence_refs   TEXT,                                 -- JSON list of evidence_vault.evidence_id
    checked_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    next_check_at   TIMESTAMP,
    finding         TEXT
);

CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_checks(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_status    ON compliance_checks(status);

CREATE TABLE IF NOT EXISTS retention_policies (
    policy_id           TEXT PRIMARY KEY,
    data_type           TEXT NOT NULL UNIQUE,           -- sigint | osint | evidence | mission_events | fusion | rag_docs
    retention_days      INTEGER NOT NULL,                -- -1 = indefinite
    archive_action      TEXT DEFAULT 'cold_archive',     -- cold_archive | proof_delete | none
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO retention_policies (policy_id, data_type, retention_days, archive_action) VALUES
    ('pol_sigint',    'sigint',          30, 'cold_archive'),
    ('pol_osint',     'osint',          365, 'cold_archive'),
    ('pol_evidence',  'evidence',        -1, 'none'),
    ('pol_mission',   'mission_events',  -1, 'cold_archive'),
    ('pol_fusion',    'fusion',         365, 'cold_archive'),
    ('pol_rag',       'rag_docs',        -1, 'none');

-- ===================================================================
-- Phase 8: SOVEREIGN AI — add missing columns to existing table
-- ===================================================================
-- sovereign_models already exists from Phase 1 schema but lacks some columns.
-- ALTER TABLE is idempotent via the migration runner (duplicate column errors ignored).
ALTER TABLE sovereign_models ADD COLUMN name TEXT;
ALTER TABLE sovereign_models ADD COLUMN tokens_processed INTEGER DEFAULT 0;
ALTER TABLE sovereign_models ADD COLUMN avg_latency_ms REAL DEFAULT 0.0;
ALTER TABLE sovereign_models ADD COLUMN error_rate REAL DEFAULT 0.0;
-- key_rotation_log may exist without these columns
ALTER TABLE key_rotation_log ADD COLUMN old_key_id TEXT;
ALTER TABLE key_rotation_log ADD COLUMN new_key_id TEXT;
ALTER TABLE key_rotation_log ADD COLUMN status TEXT;

-- ===================================================================
-- Phase 9: DIGITAL TWINS extended
-- ===================================================================
CREATE TABLE IF NOT EXISTS twin_registry (
    twin_id           TEXT PRIMARY KEY,
    twin_type         TEXT NOT NULL,
    entity_id         TEXT,
    entity_name       TEXT,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    snapshot_count    INTEGER DEFAULT 0,
    confidence_score  REAL DEFAULT 0.0,
    freshness_score   REAL DEFAULT 1.0,
    status            TEXT DEFAULT 'building'
);

CREATE INDEX IF NOT EXISTS idx_twin_name_type ON twin_registry(entity_name, twin_type);

-- ===================================================================
-- Phase 10: RAG + FEDERATED SEARCH
-- ===================================================================
CREATE TABLE IF NOT EXISTS rag_documents (
    doc_id        TEXT PRIMARY KEY,
    source_path   TEXT,
    content_hash  TEXT UNIQUE,
    title         TEXT,
    doc_type      TEXT,
    ingested_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata      TEXT
);

CREATE TABLE IF NOT EXISTS search_sessions (
    session_id         TEXT PRIMARY KEY,
    query              TEXT NOT NULL,
    last_results       TEXT,    -- JSON summary
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    schedule_interval_s INTEGER,
    last_run_at        TIMESTAMP
);

-- ===================================================================
-- Phase 11: POST-QUANTUM SECURITY
-- ===================================================================
CREATE TABLE IF NOT EXISTS compliance_checks (
    check_id      TEXT PRIMARY KEY,
    control_id    TEXT,
    control_name  TEXT,
    framework     TEXT,
    status        TEXT,    -- pass | fail | not_applicable | manual_review
    checked_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details       TEXT
);

CREATE TABLE IF NOT EXISTS key_rotation_log (
    rotation_id  TEXT PRIMARY KEY,
    old_key_id   TEXT,
    new_key_id   TEXT,
    rotated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status       TEXT
);

CREATE TABLE IF NOT EXISTS hsm_keys (
    key_id      TEXT PRIMARY KEY,
    backend     TEXT,    -- tpm | fido2 | software
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS retention_log (
    log_id           TEXT PRIMARY KEY,
    sweep_at         TIMESTAMP,
    proof_hash       TEXT,
    archived_counts  TEXT    -- JSON
);

-- ===================================================================
-- Phase 12: THREAT RESPONSE + MISSION EXTENSIONS
-- ===================================================================
CREATE TABLE IF NOT EXISTS mission_objectives (
    objective_id  TEXT PRIMARY KEY,
    mission_id    TEXT REFERENCES missions(mission_id),
    description   TEXT NOT NULL,
    completion_pct REAL DEFAULT 0.0,
    status        TEXT DEFAULT 'pending',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at  TIMESTAMP,
    evidence_count INTEGER DEFAULT 0,
    dependencies  TEXT    -- JSON list of objective_ids
);

-- Extend approval_gates with extra columns (safe to add)
ALTER TABLE approval_gates ADD COLUMN risk_level TEXT DEFAULT 'medium';
ALTER TABLE approval_gates ADD COLUMN expires_at TIMESTAMP;

-- Source reliability table (Phase 2 - may already exist, safe)
CREATE TABLE IF NOT EXISTS source_reliability (
    source_tool          TEXT PRIMARY KEY,
    reliability_score    REAL DEFAULT 0.7,
    historical_accuracy  REAL DEFAULT 0.5,
    corroboration_rate   REAL DEFAULT 0.5,
    sample_count         INTEGER DEFAULT 0,
    last_updated         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes                TEXT
);

-- Seed initial source reliability scores per Build Prompt §3 Phase 2.1
INSERT OR IGNORE INTO source_reliability (source_tool, reliability_score, notes) VALUES
    ('direct_dns',       0.95, 'direct DNS resolution'),
    ('whois',            0.90, 'WHOIS registry'),
    ('sec_edgar',        0.92, 'SEC EDGAR official filings'),
    ('opencorporates',   0.88, 'OpenCorporates registry'),
    ('shodan',           0.80, 'Shodan internet scan'),
    ('censys',           0.82, 'Censys internet scan'),
    ('crt_sh',           0.85, 'crt.sh certificate transparency'),
    ('linkedin',         0.65, 'LinkedIn social'),
    ('twitter',          0.55, 'Twitter social'),
    ('dark_web',         0.40, 'dark web sources'),
    ('social_media',     0.60, 'generic social media');

-- ===================================================================
-- Phase 4+: CAMPAIGNS (long-running multi-mission investigations)
-- ===================================================================
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    goal            TEXT,
    status          TEXT DEFAULT 'active',
    mission_ids     TEXT DEFAULT '[]',   -- JSON list
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checkpoint TIMESTAMP,
    metadata        TEXT
);

-- ===================================================================
-- simulation_results store
-- ===================================================================
CREATE TABLE IF NOT EXISTS simulation_results (
    sim_id      TEXT PRIMARY KEY,
    sim_type    TEXT,      -- wargame | propagation | what_if | economic | scenario
    entity_id   TEXT,
    mission_id  TEXT,
    result_data TEXT,      -- JSON
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
