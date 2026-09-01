//! Error definitions for audit logging and attestation (§39, §40).

use thiserror::Error;
use vajra_case_db::DbError;

/// Canonical error type for audit log verification, PKI, and anchoring operations (§39, §40).
#[derive(Debug, Error)]
pub enum AuditError {
    /// Chain broken: previous hash pointer does not match expected predecessor (§39)
    #[error("Audit chain broken at seq={seq}: expected prev_hash '{expected_prev}', found '{found_prev}'")]
    ChainBrokenAtSeq {
        seq: u64,
        expected_prev: String,
        found_prev: String,
    },

    /// Content tampering: entry payload does not hash to recorded entry_hash (§39)
    #[error("Audit entry content tampered at seq={seq}: computed hash '{computed}', recorded hash '{recorded}'")]
    HashMismatchAtSeq {
        seq: u64,
        computed: String,
        recorded: String,
    },

    /// Missing sequence numbers in sequential chain
    #[error("Audit sequence gap: expected sequence {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },

    /// Critical integrity violation: live chain head diverges from signed external anchor (§40)
    #[error(
        "CRITICAL INTEGRITY FAILURE: External anchor mismatch at seq={seq}. Live chain hash '{live_hash}' does not match signed anchor checkpoint hash '{anchor_hash}'. Potential history rewrite detected!"
    )]
    AnchorMismatch {
        seq: u64,
        live_hash: String,
        anchor_hash: String,
    },

    /// Digital signature verification failure
    #[error("Digital signature verification failed: {0}")]
    InvalidSignature(String),

    /// X.509 / PKI error
    #[error("PKI or certificate error: {0}")]
    PkiError(String),

    /// Database persistence error
    #[error("Database error in audit subsystem: {0}")]
    Db(#[from] DbError),

    /// Serialization error
    #[error("Serialization error in audit record: {0}")]
    Serialization(#[from] serde_json::Error),

    /// File I/O error during anchor export/import
    #[error("File I/O error in audit subsystem: {0}")]
    Io(#[from] std::io::Error),
}
