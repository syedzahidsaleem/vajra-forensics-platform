//! Acquisition profiles (§19).

use serde::{Deserialize, Serialize};

/// Acquisition profile specifying the target range and nature of acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionProfile {
    /// Physical block-by-block copy of the entire storage source from LBA 0 to total_blocks - 1.
    Physical,

    /// Partial acquisition covering a specified contiguous LBA range `[start_lba, end_lba]`.
    Partial { start_lba: u64, end_lba: u64 },

    /// Logical acquisition targeting specific logical structures (e.g. partition or filesystem range).
    /// Note: Full filesystem-aware logical extraction is expanded in Conversation 04.
    Logical {
        target_description: String,
        start_lba: u64,
        end_lba: u64,
    },
}

impl AcquisitionProfile {
    /// Returns the LBA boundaries (start_lba, end_lba) for a given total capacity.
    pub fn lba_bounds(&self, source_total_blocks: u64) -> (u64, u64) {
        match self {
            Self::Physical => (0, source_total_blocks.saturating_sub(1)),
            Self::Partial { start_lba, end_lba } => {
                let end = (*end_lba).min(source_total_blocks.saturating_sub(1));
                (*start_lba, end)
            }
            Self::Logical {
                start_lba,
                end_lba,
                ..
            } => {
                let end = (*end_lba).min(source_total_blocks.saturating_sub(1));
                (*start_lba, end)
            }
        }
    }
}
