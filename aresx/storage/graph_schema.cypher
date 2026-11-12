// ===================================================================
// ARES X v8.0 TITAN ENTERPRISE — Kuzu Graph Schema
// ===================================================================
// All graph schema for digital twins, fused entity graph, and TTP graph.
// Applied by aresx/storage/graph.py on first connection.
//
// Cross-references:
//   • TITAN Phase 1 (Build Prompt §3 Phase 1)
//   • Digital Twin extension (Build Prompt §3 Phase 3)
//   • Adversary Twin TTP graph (Build Prompt §3 Phase 3 / TRD §3.5)
// ===================================================================

// -------- Base entity nodes --------
CREATE NODE TABLE IF NOT EXISTS Entity (
    entity_id       STRING,
    entity_type     STRING,                  // person | org | domain | ip | asn | cidr | hash | email | etc.
    canonical_name  STRING,
    first_seen      TIMESTAMP,
    last_updated    TIMESTAMP,
    risk_score      DOUBLE DEFAULT 0.0,
    confidence      DOUBLE DEFAULT 0.0,
    metadata        STRING,                  // JSON
    PRIMARY KEY (entity_id)
);

CREATE NODE TABLE IF NOT EXISTS Domain (
    domain_id       STRING,
    fqdn            STRING,
    registrar       STRING,
    registered_at   TIMESTAMP,
    expires_at      TIMESTAMP,
    PRIMARY KEY (domain_id)
);

CREATE NODE TABLE IF NOT EXISTS IPAddress (
    ip_id           STRING,
    address         STRING,
    version         INT8,                    // 4 or 6
    PRIMARY KEY (ip_id)
);

CREATE NODE TABLE IF NOT EXISTS ASN (
    asn_id          STRING,
    asn_number      INT64,
    organization    STRING,
    country         STRING,
    PRIMARY KEY (asn_id)
);

CREATE NODE TABLE IF NOT EXISTS Person (
    person_id       STRING,
    full_name       STRING,
    aliases         STRING,                  // JSON list
    PRIMARY KEY (person_id)
);

CREATE NODE TABLE IF NOT EXISTS Organization (
    org_id          STRING,
    legal_name      STRING,
    industry        STRING,
    headquarters    STRING,
    employee_count  INT64,
    PRIMARY KEY (org_id)
);

// -------- Digital Twin nodes --------
CREATE NODE TABLE IF NOT EXISTS Twin (
    twin_id         STRING,
    twin_type       STRING,                  // org | infra | adversary | human | supply_chain | cyber_terrain | timeline
    entity_id       STRING,
    created_at      TIMESTAMP,
    last_updated    TIMESTAMP,
    snapshot_count  INT64 DEFAULT 0,
    confidence_score DOUBLE DEFAULT 0.0,
    status          STRING,                  // active | stale | archived | building
    PRIMARY KEY (twin_id)
);

CREATE NODE TABLE IF NOT EXISTS TwinSnapshot (
    snapshot_id     STRING,
    twin_id         STRING,
    captured_at     TIMESTAMP,
    graph_state     BLOB,                    // gzip-serialized subgraph
    metadata        STRING,                  // JSON
    PRIMARY KEY (snapshot_id)
);

// -------- Threat Intelligence (Adversary Twin) --------
CREATE NODE TABLE IF NOT EXISTS ThreatActor (
    actor_id        STRING,
    name            STRING,
    aliases         STRING,                  // JSON list
    motivation      STRING,                  // financial | espionage | hacktivism | etc.
    sophistication  STRING,
    first_seen      TIMESTAMP,
    PRIMARY KEY (actor_id)
);

CREATE NODE TABLE IF NOT EXISTS Technique (
    technique_id    STRING,                  // MITRE ATT&CK ID e.g. T1078
    name            STRING,
    tactic          STRING,                  // initial-access | execution | persistence | etc.
    description     STRING,
    PRIMARY KEY (technique_id)
);

CREATE NODE TABLE IF NOT EXISTS Sector (
    sector_id       STRING,
    name            STRING,
    PRIMARY KEY (sector_id)
);

// -------- Evidence node (links graph to vault) --------
CREATE NODE TABLE IF NOT EXISTS Evidence (
    evidence_id     STRING,                  // matches evidence_vault.evidence_id
    source_tool     STRING,
    collected_at    TIMESTAMP,
    confidence      DOUBLE,
    PRIMARY KEY (evidence_id)
);

// -------- Relationships --------
CREATE REL TABLE IF NOT EXISTS RESOLVES_TO   (FROM Domain TO IPAddress, observed_at TIMESTAMP);
CREATE REL TABLE IF NOT EXISTS BELONGS_TO    (FROM IPAddress TO ASN, observed_at TIMESTAMP);
CREATE REL TABLE IF NOT EXISTS OWNED_BY      (FROM Domain TO Organization, registered_at TIMESTAMP);
CREATE REL TABLE IF NOT EXISTS EMPLOYS       (FROM Organization TO Person, role STRING, since DATE);
CREATE REL TABLE IF NOT EXISTS AFFILIATED    (FROM Person TO Organization, role STRING);
CREATE REL TABLE IF NOT EXISTS CONNECTED_TO  (FROM Entity TO Entity, relation_type STRING, confidence DOUBLE);

CREATE REL TABLE IF NOT EXISTS ENTITY_HAS_TWIN     (FROM Entity TO Twin);
CREATE REL TABLE IF NOT EXISTS TWIN_HAS_SNAPSHOT   (FROM Twin TO TwinSnapshot);
CREATE REL TABLE IF NOT EXISTS TWIN_EVOLVED_FROM   (FROM TwinSnapshot TO TwinSnapshot);

CREATE REL TABLE IF NOT EXISTS USED_BY      (FROM Technique TO ThreatActor, first_observed TIMESTAMP);
CREATE REL TABLE IF NOT EXISTS TARGETS      (FROM ThreatActor TO Sector, observed_at TIMESTAMP);
CREATE REL TABLE IF NOT EXISTS USES_INFRA   (FROM ThreatActor TO Entity, infra_type STRING);

CREATE REL TABLE IF NOT EXISTS SUPPORTED_BY (FROM Entity TO Evidence, attribute STRING);
CREATE REL TABLE IF NOT EXISTS CONTRADICTS  (FROM Evidence TO Evidence, attribute STRING);
