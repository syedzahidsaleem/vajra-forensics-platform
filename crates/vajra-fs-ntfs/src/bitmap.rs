//! NTFS $Bitmap cluster allocation verification (§25).
//!
//! Evaluates whether data clusters of deleted MFT records remain unallocated (free)
//! to inform calibrated `MetadataConfidence` (Confirmed vs. Partial).

use crate::boot::NtfsBoot;
use vajra_core::MetadataConfidence;

/// Parsed `$Bitmap` cluster allocation bit vector.
#[derive(Debug, Clone)]
pub struct NtfsBitmap {
    pub bitmap_bytes: Vec<u8>,
}

impl NtfsBitmap {
    /// Loads `$Bitmap` data from MFT record 6 or directly from cluster runs.
    pub fn new(bitmap_bytes: Vec<u8>) -> Self {
        Self { bitmap_bytes }
    }

    /// Checks if cluster `lcn` is currently marked as free/unallocated (bit == 0).
    pub fn is_cluster_free(&self, lcn: u64) -> bool {
        let byte_idx = (lcn / 8) as usize;
        let bit_idx = (lcn % 8) as usize;

        if byte_idx < self.bitmap_bytes.len() {
            (self.bitmap_bytes[byte_idx] & (1 << bit_idx)) == 0
        } else {
            false
        }
    }

    /// Evaluates cluster allocation status for a set of physical extents.
    pub fn evaluate_extents_confidence(&self, extents: &[(u64, u64)], boot: &NtfsBoot) -> MetadataConfidence {
        if extents.is_empty() {
            return MetadataConfidence::Low;
        }

        let sectors_per_clus = boot.sectors_per_cluster as u64;
        let mut all_free = true;
        let mut any_free = false;

        for &(start_lba, block_count) in extents {
            let start_lcn = (start_lba.saturating_sub(boot.partition_start_lba)) / sectors_per_clus;
            let cluster_count = (block_count + sectors_per_clus - 1) / sectors_per_clus;

            for c in 0..cluster_count {
                let lcn = start_lcn + c;
                if self.is_cluster_free(lcn) {
                    any_free = true;
                } else {
                    all_free = false;
                }
            }
        }

        if all_free {
            MetadataConfidence::Confirmed
        } else if any_free {
            MetadataConfidence::Partial
        } else {
            MetadataConfidence::Low
        }
    }
}
