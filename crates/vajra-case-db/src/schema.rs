//! Relational database schema and migration definitions (§22).

/// Current schema version
pub const SCHEMA_VERSION: i32 = 1;

/// SQL DDL for initial database schema (§22).
pub const INITIAL_SCHEMA_SQL: &str = r#"
-- Case management metadata table (§22)
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('Active', 'Closed'))
);

-- Evidence items table (§22)
CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    item_type TEXT NOT NULL,              -- PhysicalDevice, ForensicImage
    device_serial TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    model TEXT NOT NULL,
    capacity_bytes INTEGER NOT NULL,
    interface TEXT NOT NULL,               -- SATA, NVMe, USB, SD
    filesystem TEXT,
    device_fingerprint_hash TEXT NOT NULL,
    source_location TEXT,
    physical_condition TEXT,
    write_block_status TEXT,
    current_custody_owner TEXT,
    current_location TEXT
);

-- Forensic images table (§22)
CREATE TABLE IF NOT EXISTS forensic_images (
    image_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_items(evidence_id),
    image_format TEXT NOT NULL,            -- RAW, E01, AFF4
    file_path TEXT NOT NULL,
    acquisition_hash TEXT NOT NULL,
    verification_hash TEXT,
    bad_sector_map_json TEXT,
    acquired_at TEXT NOT NULL,
    operator TEXT NOT NULL
);

-- Operations tracking table (§22)
CREATE TABLE IF NOT EXISTS operations (
    op_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    evidence_id TEXT REFERENCES evidence_items(evidence_id),
    op_type TEXT NOT NULL,                 -- Acquire, Recover, Sanitize, Verify, Analyze
    parameters_json TEXT,
    tool_version TEXT NOT NULL,
    build_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL
);

-- Recovered artifacts table (§22)
CREATE TABLE IF NOT EXISTS recovered_artifacts (
    artifact_id TEXT PRIMARY KEY,
    op_id TEXT NOT NULL REFERENCES operations(op_id),
    original_path TEXT,
    recovered_path TEXT NOT NULL,
    file_type TEXT NOT NULL,
    recovery_tier INTEGER NOT NULL,        -- 1=metadata, 2=signature, 3=fragmented
    confidence_score REAL NOT NULL,
    confidence_breakdown_json TEXT,
    provenance_json TEXT
);

-- Sanitization events table (§22)
CREATE TABLE IF NOT EXISTS sanitization_events (
    san_id TEXT PRIMARY KEY,
    op_id TEXT NOT NULL REFERENCES operations(op_id),
    method TEXT NOT NULL,
    standard_reference TEXT NOT NULL,
    verification_layers_json TEXT NOT NULL,
    assurance_level TEXT NOT NULL           -- HIGH, MEDIUM, LOW, FAILED
);

-- Chain of custody events table (§21, §22)
CREATE TABLE IF NOT EXISTS custody_events (
    event_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_items(evidence_id),
    event_type TEXT NOT NULL,
    from_party TEXT,
    to_party TEXT,
    timestamp_utc TEXT NOT NULL,
    location TEXT,
    purpose TEXT,
    evidence_condition TEXT,
    signature_ref TEXT
);

-- Tamper-evident sequential audit log table (§22, §39)
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    entry_json TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL
);

-- Generated reports table (§22, §41)
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    report_type TEXT NOT NULL,             -- ForensicExamination, SanitizationCertificate, Acquisition, Recovery, DeviceHealth, ChainOfCustody
    file_path_pdf TEXT,
    file_path_json TEXT,
    signature TEXT,
    certificate_chain TEXT,
    trusted_timestamp TEXT
);

-- Version tracking table for migrations
CREATE TABLE IF NOT EXISTS _schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Trigger: Enforces that cases in 'Closed' status cannot be reopened (§22)
CREATE TRIGGER IF NOT EXISTS prevent_case_reopening
BEFORE UPDATE OF status ON cases
FOR EACH ROW
WHEN OLD.status = 'Closed' AND NEW.status != 'Closed'
BEGIN
    SELECT RAISE(ABORT, 'Illegal status transition: Case is closed/tombstoned and cannot be reopened.');
END;

-- Trigger: Enforces that case records are permanent and cannot be deleted (§22)
CREATE TRIGGER IF NOT EXISTS prevent_case_deletion
BEFORE DELETE ON cases
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Illegal operation: Forensic cases cannot be deleted. Closed cases are preserved permanently.');
END;
"#;
