//! # vajra-verify
//!
//! Independent forensic report, digital signature, and audit chain verification tool (§42).

pub mod models;
pub mod verifier;

pub use models::{VjrAuditEntry, VjrEnvelope, VjrEvidenceItem, VjrTimestampRecord};
pub use verifier::{
    compute_independent_entry_hash, extract_ed25519_pubkey_from_pem, verify_report_envelope,
    verify_report_file, CheckStatus, VerificationReport, VerifyError,
};
