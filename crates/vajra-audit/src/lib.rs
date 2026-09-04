//! # vajra-audit
//!
//! Tamper-evident sequential audit logging, X.509/PKI signing, external
//! anchoring verification, and unified forensic report generation (§39, §40, §41).
//!
//! Proves:
//! - An unbroken, hash-chained record of every state-changing software operation (§39)
//! - Cryptographic non-repudiation of operator attestations via Ed25519 / X.509 (§40)
//! - History-rewrite tamper detection via signed offline external checkpoints (§40)
//! - Unified cryptographic report packaging (`.vjr`) for all six §41 report types (§41)

pub mod anchor;
pub mod chain;
pub mod entry;
pub mod error;
pub mod pki;
pub mod report;

pub use anchor::{export_anchor, verify_anchor, AnchorCheckpoint, AnchorVerificationReport};
pub use chain::{AuditChain, ChainReport};
pub use entry::{AuditEntry, GENESIS_PREV_HASH};
pub use error::AuditError;
pub use pki::{verify_signature, OperatorKeyPair};
pub use report::{
    fetch_timestamp_opportunistic, AcquisitionReportPayload, ChainOfCustodyPayload,
    DeviceHealthPayload, EvidenceManifestItem, ForensicExamPayload, RecoveredArtifactItem,
    RecoveryReportPayload, ReportEnvelope, ReportGenerator, ReportType, SanitizationCertData,
    SanitizationCertPayload, SmartAttributeItem, TimestampTokenRecord,
};
