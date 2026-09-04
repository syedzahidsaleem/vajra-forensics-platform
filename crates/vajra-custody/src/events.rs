//! Chain of Custody event data structures and types (§21).

use serde::{Deserialize, Serialize};

/// Enumeration of physical and forensic custody lifecycle events (§21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CustodyEventType {
    /// Initial evidence seizure in the field
    Seized,
    /// Intake / receipt at evidence facility or forensic lab
    Received,
    /// Movement between physical storage locations (e.g. Evidence Locker 4)
    StorageChange,
    /// Transfer of physical custody from one person/examiner to another
    Transferred,
    /// Physical write-blocker connection logged with hardware identity
    WriteBlockerAttached,
    /// Forensic imaging, carving, or analysis session started
    AnalysisStarted,
    /// Forensic analysis or examination session concluded
    AnalysisCompleted,
    /// Forensic working copy or derived image created for analysis
    WorkingCopyCreated,
    /// Evidence returned to owner / submitting agency
    Returned,
    /// Evidence permanently disposed of or destroyed per court order
    Disposed,
}

impl CustodyEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Seized => "Seized",
            Self::Received => "Received",
            Self::StorageChange => "StorageChange",
            Self::Transferred => "Transferred",
            Self::WriteBlockerAttached => "WriteBlockerAttached",
            Self::AnalysisStarted => "AnalysisStarted",
            Self::AnalysisCompleted => "AnalysisCompleted",
            Self::WorkingCopyCreated => "WorkingCopyCreated",
            Self::Returned => "Returned",
            Self::Disposed => "Disposed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Returned | Self::Disposed)
    }
}

impl std::fmt::Display for CustodyEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for CustodyEventType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Seized" => Ok(Self::Seized),
            "Received" => Ok(Self::Received),
            "StorageChange" => Ok(Self::StorageChange),
            "Transferred" => Ok(Self::Transferred),
            "WriteBlockerAttached" => Ok(Self::WriteBlockerAttached),
            "AnalysisStarted" => Ok(Self::AnalysisStarted),
            "AnalysisCompleted" => Ok(Self::AnalysisCompleted),
            "WorkingCopyCreated" => Ok(Self::WorkingCopyCreated),
            "Returned" => Ok(Self::Returned),
            "Disposed" => Ok(Self::Disposed),
            other => Err(format!("Unknown custody event type '{}'", other)),
        }
    }
}

/// Chain of Custody event record (§21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyEvent {
    /// Unique event identifier (UUID v4)
    pub event_id: String,
    /// Reference to the evidence item
    pub evidence_id: String,
    /// Type of custody event
    pub event_type: CustodyEventType,
    /// Party releasing custody (optional)
    pub from_party: Option<String>,
    /// Party accepting custody (optional)
    pub to_party: Option<String>,
    /// UTC timestamp of the custody event
    pub timestamp_utc: String,
    /// Physical location (e.g. "Evidence Locker 4", "Forensic Lab Bay 2")
    pub location: Option<String>,
    /// Purpose of transfer or handling (e.g. "Forensic acquisition", "Court exhibit")
    pub purpose: Option<String>,
    /// Physical condition notes (e.g. "Sealed tamper bag intact")
    pub evidence_condition: Option<String>,
    /// Optional cryptographic signature reference for digital attestation
    pub signature_ref: Option<String>,
}
