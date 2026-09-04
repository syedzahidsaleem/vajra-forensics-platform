//! Entity models for the Evidence Vault relational database (§22).

use serde::{Deserialize, Serialize};

/// Status of a forensic case (§22).
///
/// Under §22's tombstoning lifecycle, cases only ever transition `Active -> Closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaseStatus {
    /// Active investigation — operations and evidence may be appended.
    Active,
    /// Permanently closed / tombstoned — immutable historic record.
    Closed,
}

impl CaseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Closed => "Closed",
        }
    }
}

impl std::fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for CaseStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Active" => Ok(Self::Active),
            "Closed" => Ok(Self::Closed),
            other => Err(format!("Invalid case status '{}'", other)),
        }
    }
}

/// Case record in the Evidence Vault (§22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub case_name: String,
    pub investigator_id: String,
    pub created_at: String,
    pub status: CaseStatus,
}

/// Evidence item record (§22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItemRecord {
    pub evidence_id: String,
    pub case_id: String,
    pub item_type: String, // "PhysicalDevice", "ForensicImage"
    pub device_serial: String,
    pub manufacturer: String,
    pub model: String,
    pub capacity_bytes: u64,
    pub interface: String,
    pub filesystem: Option<String>,
    pub device_fingerprint_hash: String,
    pub source_location: Option<String>,
    pub physical_condition: Option<String>,
    pub write_block_status: Option<String>,
    pub current_custody_owner: Option<String>,
    pub current_location: Option<String>,
}

/// Forensic image metadata record (§17, §22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicImageRecord {
    pub image_id: String,
    pub evidence_id: String,
    pub image_format: String, // "RAW", "E01", "AFF4"
    pub file_path: String,
    pub acquisition_hash: String,
    pub verification_hash: Option<String>,
    pub bad_sector_map_json: Option<String>,
    pub acquired_at: String,
    pub operator: String,
}

/// Operation tracking record (§22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub op_id: String,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub op_type: String,
    pub parameters_json: Option<String>,
    pub tool_version: String,
    pub build_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: String,
}

/// Recovered artifact metadata record (§17, §22).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveredArtifactRecord {
    pub artifact_id: String,
    pub op_id: String,
    pub original_path: Option<String>,
    pub recovered_path: String,
    pub file_type: String,
    pub recovery_tier: u32,
    pub confidence_score: f64,
    pub confidence_breakdown_json: Option<String>,
    pub provenance_json: Option<String>,
}

/// Sanitization event record (§22, §35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizationEventRecord {
    pub san_id: String,
    pub op_id: String,
    pub method: String,
    pub standard_reference: String,
    pub verification_layers_json: String,
    pub assurance_level: String, // "HIGH", "MEDIUM", "LOW", "FAILED"
}

/// Custody event record in the database (§21, §22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyEventRecord {
    pub event_id: String,
    pub evidence_id: String,
    pub event_type: String,
    pub from_party: Option<String>,
    pub to_party: Option<String>,
    pub timestamp_utc: String,
    pub location: Option<String>,
    pub purpose: Option<String>,
    pub evidence_condition: Option<String>,
    pub signature_ref: Option<String>,
}

/// Audit log record in the database (§22, §39).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub seq: u64,
    pub entry_json: String,
    pub entry_hash: String,
    pub prev_hash: String,
}

/// Generated report record (§22, §41).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRecord {
    pub report_id: String,
    pub case_id: String,
    pub report_type: String,
    pub file_path_pdf: Option<String>,
    pub file_path_json: Option<String>,
    pub signature: Option<String>,
    pub certificate_chain: Option<String>,
    pub trusted_timestamp: Option<String>,
}
