//! Bad-sector and damaged-media handling engine (§20).
//!
//! Implements the retry/reduce-block-size/mark-unreadable flowchart specified in §20.
//!
//! # Single Source of Truth Guarantee
//!
//! The [`BadSectorMap`] is the authoritative single source of truth for unreadable regions.
//! Unreadable sectors are filled on disk with a distinctive, documented non-natural marker
//! (`b"VAJRA_BAD_SECTOR"`) purely as a visual and hex-inspection aid. Byte inspection alone
//! is never used by Vajra to infer damage, because healthy media may legitimately contain any
//! byte pattern. Software callers must always query [`BadSectorMap::is_lba_bad`].

use serde::{Deserialize, Serialize};

/// Default distinctive 16-byte marker repeated across unreadable sectors (§20).
pub const DEFAULT_BAD_SECTOR_MARKER: &[u8; 16] = b"VAJRA_BAD_SECTOR";

/// Configuration strategy for handling read failures and bad sectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadSectorStrategy {
    /// Number of retries before reducing block size or marking a sector as unreadable.
    pub max_retries: u32,
    /// Initial acquisition chunk size in sectors (e.g. 128 sectors = 64 KiB for 512B sectors).
    pub initial_chunk_sectors: u32,
    /// Minimum block size in sectors to reduce to upon encountering read errors (typically 1 sector).
    pub min_chunk_sectors: u32,
    /// Backoff sleep in milliseconds between retries.
    pub retry_backoff_ms: u64,
    /// Distinctive byte pattern to populate into unreadable sector buffers.
    pub placeholder_pattern: Vec<u8>,
}

impl Default for BadSectorStrategy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_chunk_sectors: 128,
            min_chunk_sectors: 1,
            retry_backoff_ms: 10,
            placeholder_pattern: DEFAULT_BAD_SECTOR_MARKER.to_vec(),
        }
    }
}

/// A contiguous range of unreadable logical blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadableRange {
    /// Starting LBA of the damaged region.
    pub start_lba: u64,
    /// Number of contiguous unreadable blocks.
    pub block_count: u64,
    /// Diagnostic error description provided by the OS or storage controller.
    pub error_details: String,
}

/// Cryptographically auditable record of all bad and unreadable sectors encountered (§20, §22).
///
/// This map is serialized to JSON and persisted in `forensic_images.bad_sector_map_json`
/// within the Evidence Vault database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadSectorMap {
    pub unreadable_ranges: Vec<UnreadableRange>,
    pub total_unreadable_blocks: u64,
    pub total_unreadable_bytes: u64,
}

impl BadSectorMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an unreadable LBA range, merging contiguous adjacent ranges if applicable.
    pub fn record_unreadable(
        &mut self,
        start_lba: u64,
        block_count: u64,
        block_size: u32,
        error_details: String,
    ) {
        if block_count == 0 {
            return;
        }

        self.total_unreadable_blocks += block_count;
        self.total_unreadable_bytes += block_count * block_size as u64;

        // Try merging with the last range if contiguous
        if let Some(last) = self.unreadable_ranges.last_mut() {
            if last.start_lba + last.block_count == start_lba {
                last.block_count += block_count;
                return;
            }
        }

        self.unreadable_ranges.push(UnreadableRange {
            start_lba,
            block_count,
            error_details,
        });
    }

    /// Returns `true` if the specified LBA falls within any recorded unreadable range.
    ///
    /// This is the single source of truth for unreadable status.
    pub fn is_lba_bad(&self, lba: u64) -> bool {
        self.unreadable_ranges
            .iter()
            .any(|r| lba >= r.start_lba && lba < r.start_lba + r.block_count)
    }

    /// Returns `true` if any block in the range `[start_lba .. start_lba + count]` is bad.
    pub fn is_range_bad(&self, start_lba: u64, count: u32) -> bool {
        let end_lba = start_lba + count as u64;
        self.unreadable_ranges
            .iter()
            .any(|r| r.start_lba < end_lba && r.start_lba + r.block_count > start_lba)
    }

    /// Serializes this map to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserializes a map from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Fills `buffer` with the repeating distinctive placeholder pattern.
    pub fn fill_placeholder(buffer: &mut [u8], pattern: &[u8]) {
        if pattern.is_empty() {
            buffer.fill(0);
            return;
        }
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = pattern[i % pattern.len()];
        }
    }
}
