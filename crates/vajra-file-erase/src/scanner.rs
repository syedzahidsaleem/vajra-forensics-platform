//! Residual Artifact Scanner (§7.2, §36).
//!
//! Implements the mandatory five-state result model for post-erasure forensic inspection,
//! ensuring that file erasures are never collapsed into a bare "Success" boolean.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Five-State Residual Artifact Scan Result (§7.2, §36).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidualScanResult {
    /// Zero residual data, metadata traces, or journal references found across all inspected locations.
    Sanitized,
    /// Residual traces detected in specific locations (e.g. journal entries, directory slack, un-zeroed extents).
    ResidualTracesDetected(Vec<String>),
    /// Unable to inspect specific structures (e.g. active shadow copies, encrypted journal, unsupported structures).
    UnableToVerify(String),
    /// Target location or structure not applicable for this filesystem format.
    NotApplicable(String),
    /// Data blocks overwritten, but metadata or journal references partially remain.
    PartiallySanitized(String),
}

impl fmt::Display for ResidualScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResidualScanResult::Sanitized => write!(f, "Sanitized (0 residual traces found)"),
            ResidualScanResult::ResidualTracesDetected(traces) => {
                write!(f, "Residual traces detected in: {}", traces.join(", "))
            }
            ResidualScanResult::UnableToVerify(reason) => write!(f, "Unable to verify: {}", reason),
            ResidualScanResult::NotApplicable(reason) => write!(f, "Not applicable: {}", reason),
            ResidualScanResult::PartiallySanitized(reason) => write!(f, "Partially sanitized: {}", reason),
        }
    }
}

/// Residual Artifact Scanner (§36).
pub struct ResidualArtifactScanner;

impl ResidualArtifactScanner {
    /// Evaluates data extents, metadata records, and filesystem journals for residual traces.
    pub fn scan(
        data_overwritten: bool,
        metadata_zeroed: bool,
        journal_scrubbed: bool,
        detected_traces: Vec<String>,
        verification_error: Option<String>,
    ) -> ResidualScanResult {
        if let Some(err) = verification_error {
            return ResidualScanResult::UnableToVerify(err);
        }

        if !detected_traces.is_empty() {
            return ResidualScanResult::ResidualTracesDetected(detected_traces);
        }

        if data_overwritten && metadata_zeroed && journal_scrubbed {
            ResidualScanResult::Sanitized
        } else if data_overwritten && (!metadata_zeroed || !journal_scrubbed) {
            ResidualScanResult::PartiallySanitized(
                "Data extents overwritten, but metadata or journal entries remain un-scrubbed."
                    .to_string(),
            )
        } else {
            ResidualScanResult::ResidualTracesDetected(vec!["Data extents unverified".to_string()])
        }
    }
}
