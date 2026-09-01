//! # vajra-case-db
//!
//! Encrypted SQLite/SQLCipher persistence and relational data access layer for
//! the Vajra Digital Forensics Platform (§17, §22).
//!
//! Enforces:
//! - Full §22 relational schema (cases, evidence, operations, artifacts, audit log, custody)
//! - Binary evidence separation (metadata and hashes only; raw bytes live as regular files)
//! - Permanent case tombstoning (`Active -> Closed` irreversible lifecycle)

pub mod db;
pub mod error;
pub mod key;
pub mod models;
pub mod schema;

pub use db::CaseDb;
pub use error::DbError;
pub use key::DatabaseKey;
pub use models::{
    AuditLogRecord, CaseRecord, CaseStatus, CustodyEventRecord, EvidenceItemRecord,
    ForensicImageRecord, OperationRecord, RecoveredArtifactRecord, ReportRecord,
    SanitizationEventRecord,
};
