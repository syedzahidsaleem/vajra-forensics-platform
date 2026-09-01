//! Operation types and results per §22 and §39.

use serde::{Deserialize, Serialize};

/// High-level categories of operations recorded in the Evidence Vault and Audit Log (§22, §39).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationType {
    /// Physical or logical acquisition of evidence (§19)
    Acquire,
    /// Data recovery and carving (§26–§32)
    Recover,
    /// Cryptographic or physical data sanitization (§33–§38)
    Sanitize,
    /// Hash verification or integrity validation (§40, §42)
    Verify,
    /// Filesystem or artifact analysis (§29–§32)
    Analyze,
    /// Storage device enumeration or hardware health query (§23)
    DeviceInspection,
    /// Case management or custody logging event (§21, §22)
    CaseManagement,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquire => write!(f, "Acquire"),
            Self::Recover => write!(f, "Recover"),
            Self::Sanitize => write!(f, "Sanitize"),
            Self::Verify => write!(f, "Verify"),
            Self::Analyze => write!(f, "Analyze"),
            Self::DeviceInspection => write!(f, "DeviceInspection"),
            Self::CaseManagement => write!(f, "CaseManagement"),
        }
    }
}

/// Result of an operation recorded in the audit log (§39).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationResult {
    /// Operation completed successfully with zero non-recoverable errors.
    Success,
    /// Operation completed with non-fatal warnings or partial results.
    Partial { details: String },
    /// Operation failed with an error description.
    Failed { reason: String },
    /// Operation aborted by user intervention or safety refusal.
    Aborted { reason: String },
}

impl std::fmt::Display for OperationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::Partial { details } => write!(f, "PARTIAL: {}", details),
            Self::Failed { reason } => write!(f, "FAILED: {}", reason),
            Self::Aborted { reason } => write!(f, "ABORTED: {}", reason),
        }
    }
}
