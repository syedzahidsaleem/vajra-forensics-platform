//! Checkpointing and resumability structures (§19, NFR-1).

use crate::bad_sector::BadSectorMap;
use crate::profile::AcquisitionProfile;
use serde::{Deserialize, Serialize};

/// Checkpoint payload serialized into `operations.parameters_json` to enable interrupted
/// acquisitions to resume exactly where they left off without restarting from LBA 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionCheckpoint {
    pub op_id: String,
    pub case_id: String,
    pub evidence_id: String,
    /// SHA-256 fingerprint of the original source device, validated on resume (§23).
    pub source_fingerprint: String,
    pub output_path: String,
    pub profile: AcquisitionProfile,
    /// First LBA of the acquisition profile range.
    pub start_lba: u64,
    /// Next LBA to acquire.
    pub current_lba: u64,
    /// Last LBA in the acquisition profile range.
    pub end_lba: u64,
    pub total_blocks: u64,
    pub bytes_written: u64,
    pub bad_sector_map: BadSectorMap,
    pub started_at: String,
    pub last_updated_at: String,
}

impl AcquisitionCheckpoint {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}
