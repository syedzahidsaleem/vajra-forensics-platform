//! Independent Data Structures for .vjr Report Parsing (§42).
//!
//! Defined independently within `vajra-verify` to ensure zero dependency
//! on `vajra-audit`'s internal data structures and verification pipelines (§42).

use serde::{Deserialize, Serialize};

/// Canonical representation of an audit entry inside an independent .vjr file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VjrAuditEntry {
    pub seq: u64,
    pub timestamp_utc: String,
    pub operator_id: String,
    pub case_id: String,
    pub operation: String,
    pub target_descriptor: String,
    pub result: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Referenced evidence item in the report manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VjrEvidenceItem {
    pub evidence_id: String,
    pub file_name: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
}

/// Trusted timestamp record in the report envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VjrTimestampRecord {
    pub is_rfc3161: bool,
    pub tsa_url: Option<String>,
    pub timestamp_utc: String,
    pub token_der_base64: Option<String>,
    pub status_label: String,
}

/// The independent Report Envelope model parsed by `vajra-verify` (§42).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VjrEnvelope {
    pub report_id: String,
    pub case_id: String,
    pub report_type: String,
    pub title: String,
    pub created_at_utc: String,
    pub operator_id: String,
    pub tool_version: String,
    pub build_id: String,
    pub content_json: String,
    pub content_markdown: String,
    pub content_sha256: String,
    pub audit_chain_segment: Vec<VjrAuditEntry>,
    pub signature_hex: String,
    pub signing_cert_pem: String,
    pub certificate_chain_pem: Option<String>,
    pub trusted_timestamp: VjrTimestampRecord,
    pub evidence_manifest: Vec<VjrEvidenceItem>,
}
