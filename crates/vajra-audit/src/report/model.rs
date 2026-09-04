//! Unified Report Models & Envelope Architecture (§41, §42, §40).
//!
//! Provides canonical data models for all six §41 forensic report types,
//! encapsulated in a cryptographically signed `.vjr` Report Envelope.

use crate::entry::AuditEntry;
use serde::{Deserialize, Serialize};

/// The six canonical forensic report types defined in §41.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportType {
    /// Full case narrative: acquisition details, recovery methodology, recovered artifacts with provenance, examiner notes.
    ForensicExamination,
    /// Secure data sanitization certificate per §38 with 5-layer verification results and assurance rating.
    SanitizationCertificate,
    /// Forensic imaging report with device fingerprint, image hashes, bad-sector map, and re-read verification.
    AcquisitionReport,
    /// Deep file carving report with per-artifact provenance (§31), aggregate statistics, confidence breakdown, and ML explainability.
    RecoveryReport,
    /// SMART / NVMe health diagnostics snapshot and decision engine recommendation (§23).
    DeviceHealthReport,
    /// Chronological chain-of-custody tracking log for evidence items (§21).
    ChainOfCustodyReport,
}

impl ReportType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForensicExamination => "ForensicExamination",
            Self::SanitizationCertificate => "SanitizationCertificate",
            Self::AcquisitionReport => "AcquisitionReport",
            Self::RecoveryReport => "RecoveryReport",
            Self::DeviceHealthReport => "DeviceHealthReport",
            Self::ChainOfCustodyReport => "ChainOfCustodyReport",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ForensicExamination => "Forensic Examination Report",
            Self::SanitizationCertificate => "Sanitization Certificate",
            Self::AcquisitionReport => "Forensic Acquisition Report",
            Self::RecoveryReport => "File Recovery & Carving Report",
            Self::DeviceHealthReport => "Device Health Diagnostics Report",
            Self::ChainOfCustodyReport => "Chain of Custody Report",
        }
    }
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ReportType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['-', '_', ' '], "").as_str() {
            "forensicexamination" | "forensic" | "exam" => Ok(Self::ForensicExamination),
            "sanitizationcertificate" | "sanitization" | "certificate" | "erase" => Ok(Self::SanitizationCertificate),
            "acquisitionreport" | "acquisition" | "acquire" | "image" => Ok(Self::AcquisitionReport),
            "recoveryreport" | "recovery" | "carve" => Ok(Self::RecoveryReport),
            "devicehealthreport" | "devicehealth" | "health" | "smart" => Ok(Self::DeviceHealthReport),
            "chainofcustodyreport" | "chainofcustody" | "custody" => Ok(Self::ChainOfCustodyReport),
            other => Err(format!("Unknown report type: '{}'", other)),
        }
    }
}

/// Referenced evidence item in the report manifest (§42).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifestItem {
    pub evidence_id: String,
    pub file_name: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
}

/// Trusted timestamp attestation record (§40).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampTokenRecord {
    pub is_rfc3161: bool,
    pub tsa_url: Option<String>,
    pub timestamp_utc: String,
    pub token_der_base64: Option<String>,
    pub status_label: String,
}

/// The unified cryptographic container format (`.vjr`) for all generated reports (§41, §42).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEnvelope {
    /// Unique report identifier (UUID v4)
    pub report_id: String,
    /// Associated forensic case ID (§22)
    pub case_id: String,
    /// Canonical report type
    pub report_type: ReportType,
    /// Human-readable title
    pub title: String,
    /// Generation timestamp (ISO 8601 UTC)
    pub created_at_utc: String,
    /// Operator / Investigator ID
    pub operator_id: String,
    /// Tool build version
    pub tool_version: String,
    /// Build commit identifier
    pub build_id: String,
    /// Machine-readable specific JSON payload
    pub content_json: String,
    /// Human-readable structured markdown / text rendering
    pub content_markdown: String,
    /// SHA-256 hex digest of `content_json`
    pub content_sha256: String,
    /// Sequential audit-chain segment corresponding to this case / report (§39)
    pub audit_chain_segment: Vec<AuditEntry>,
    /// Hex-encoded Ed25519 digital signature of `content_sha256`
    pub signature_hex: String,
    /// PEM-encoded X.509 certificate of the signing operator (§40)
    pub signing_cert_pem: String,
    /// Optional PEM-encoded certificate chain
    pub certificate_chain_pem: Option<String>,
    /// Trusted timestamp attestation (RFC 3161 or labeled local fallback)
    pub trusted_timestamp: TimestampTokenRecord,
    /// Referenced external evidence files and their SHA-256 hashes for verifier check
    pub evidence_manifest: Vec<EvidenceManifestItem>,
}

impl ReportEnvelope {
    /// Serializes the envelope to pretty-printed JSON (`.vjr`).
    pub fn to_vjr_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a report envelope from a `.vjr` JSON string.
    pub fn from_vjr_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// =============================================================================
// Specific Report Payloads (§41)
// =============================================================================

/// 1. Forensic Examination Report Payload (§41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicExamPayload {
    pub case_id: String,
    pub case_name: String,
    pub investigator_id: String,
    pub created_at: String,
    pub case_status: String,
    pub evidence_items: Vec<vajra_case_db::EvidenceItemRecord>,
    pub operations: Vec<vajra_case_db::OperationRecord>,
    pub recovered_artifacts: Vec<vajra_case_db::RecoveredArtifactRecord>,
    pub custody_summary: Vec<vajra_case_db::CustodyEventRecord>,
    pub examiner_notes: String,
}

/// Sanitization Certificate structured data (§38, §41).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationCertData {
    pub certificate_id: String,
    pub device_serial: String,
    pub manufacturer: String,
    pub model: String,
    pub media_type: String,
    pub capacity_bytes: u64,
    pub sanitization_method: String,
    pub standard_reference: String,
    pub timestamp_completed: String,
    pub operator_id: String,
    pub layer1_controller_confirmation: String,
    pub layer2_readback_samples: String,
    pub layer3_full_read: String,
    pub layer4_entropy_analysis: String,
    pub layer5_recovery_carve: String,
    pub overall_assurance: String,
    pub assurance_justification: Option<String>,
}

/// 2. Sanitization Certificate Report Payload (§38, §41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationCertPayload {
    pub certificate: SanitizationCertData,
}

/// 3. Acquisition Report Payload (§41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionReportPayload {
    pub case_id: String,
    pub evidence_id: String,
    pub device_serial: String,
    pub manufacturer: String,
    pub model: String,
    pub capacity_bytes: u64,
    pub device_fingerprint_hash: String,
    pub image_format: String,
    pub image_file_path: String,
    pub acquisition_hash_sha256: String,
    pub verification_hash_sha256: Option<String>,
    pub re_read_verified: bool,
    pub total_sectors: u64,
    pub bad_sector_count: u64,
    pub bad_sector_ranges: Vec<(u64, u64)>,
    pub started_at: String,
    pub completed_at: String,
    pub operator: String,
}

/// Recovered artifact item representation for recovery report (§31).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredArtifactItem {
    pub id: u64,
    pub filename_guess: Option<String>,
    pub file_type: String,
    pub recovery_tier: u32,
    pub recovered_bytes: u64,
    pub content_hash: String,
    pub confidence_score: f64,
    pub structural_score: f64,
    pub metadata_score: f64,
    pub entropy_score: f64,
    pub explainability: Option<String>,
    pub limitations: Option<String>,
}

/// 4. Recovery Report Payload (§31, §41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReportPayload {
    pub case_id: String,
    pub target_source: String,
    pub partition_offset_lba: u64,
    pub tiers_executed: Vec<String>,
    pub total_recovered_artifacts: usize,
    pub tier1_count: usize,
    pub tier2_count: usize,
    pub tier3_count: usize,
    pub type_counts: std::collections::HashMap<String, usize>,
    pub artifacts: Vec<RecoveredArtifactItem>,
}

/// SMART attribute item for health report (§23).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAttributeItem {
    pub id: u8,
    pub name: String,
    pub raw_value: u64,
    pub normalized_value: u8,
    pub worst_value: u8,
    pub threshold: u8,
    pub status: String,
}

/// 5. Device Health Report Payload (§23, §41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHealthPayload {
    pub case_id: String,
    pub device_path: String,
    pub serial: String,
    pub model: String,
    pub vendor: String,
    pub interface: String,
    pub media_type: String,
    pub capacity_bytes: u64,
    pub device_fingerprint_hash: String,
    pub health_status: String, // "Healthy", "Warning", "Critical", "Unknown"
    pub temperature_celsius: Option<u32>,
    pub power_on_hours: Option<u64>,
    pub power_cycles: Option<u64>,
    pub critical_warning_flags: Vec<String>,
    pub raw_attributes: Vec<SmartAttributeItem>,
    pub decision_engine_recommendation: String,
}

/// 6. Chain-of-Custody Report Payload (§21, §41)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyPayload {
    pub case_id: String,
    pub evidence_id: String,
    pub device_serial: String,
    pub manufacturer: String,
    pub model: String,
    pub current_owner: String,
    pub current_location: String,
    pub physical_condition: String,
    pub total_events: usize,
    pub events: Vec<vajra_case_db::CustodyEventRecord>,
}
