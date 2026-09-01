//! Tier 1: Filesystem-Aware Metadata Recovery (§25).
//!
//! Thin orchestration layer calling into `vajra-fs-ntfs`, `vajra-fs-ext4`, and `vajra-fs-fat`.
//! Converts `RecoverableFileEntry` records into `RecoveredArtifact` and produces
//! an `AllocatedBlockMap` tracking resolved LBAs.

use crate::confidence::ConfidenceBreakdown;
use crate::entropy::{EntropyAnalyzer, HeuristicEntropyAnalyzer};
use crate::error::CarveError;
use crate::types::{RecoveredArtifact, RecoveryTier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use vajra_core::{
    detect_filesystem, DataLocation, FilesystemType, MetadataConfidence, ReadOnlyBlockSource,
    RecoverableFileEntry,
};

/// Set of LBA sectors confirmed by Tier-1 metadata.
#[derive(Debug, Default, Clone)]
pub struct AllocatedBlockMap {
    pub allocated_lbas: HashSet<u64>,
}

impl AllocatedBlockMap {
    pub fn new() -> Self {
        Self {
            allocated_lbas: HashSet::new(),
        }
    }

    /// Marks a range of LBAs as resolved/allocated.
    pub fn mark_range(&mut self, start_lba: u64, count: u64) {
        for lba in start_lba..start_lba + count {
            self.allocated_lbas.insert(lba);
        }
    }

    /// Checks if a specific LBA is already resolved.
    pub fn contains(&self, lba: u64) -> bool {
        self.allocated_lbas.contains(&lba)
    }

    /// Checks if any LBA in a range is already resolved.
    pub fn overlaps(&self, start_lba: u64, count: u64) -> bool {
        for lba in start_lba..start_lba + count {
            if self.allocated_lbas.contains(&lba) {
                return true;
            }
        }
        false
    }
}

/// Executes Tier-1 metadata recovery across the storage source.
pub fn recover_tier1(
    source: &mut dyn ReadOnlyBlockSource,
    partition_offset: u64,
) -> Result<(Vec<RecoveredArtifact>, AllocatedBlockMap), CarveError> {
    let fs_type = detect_filesystem(source, partition_offset).unwrap_or(FilesystemType::Unknown);
    let mut artifacts = Vec::new();
    let mut allocated_map = AllocatedBlockMap::new();
    let entropy_analyzer = HeuristicEntropyAnalyzer::default();

    let entries: Vec<RecoverableFileEntry> = match fs_type {
        FilesystemType::Ntfs => {
            vajra_fs_ntfs::enumerate_entries(source, partition_offset)
                .map_err(|e| CarveError::Filesystem(format!("NTFS error: {}", e)))?
        }
        FilesystemType::Ext4 => {
            vajra_fs_ext4::enumerate_entries(source, partition_offset)
                .map_err(|e| CarveError::Filesystem(format!("ext4 error: {}", e)))?
        }
        FilesystemType::Fat32 | FilesystemType::Fat16 | FilesystemType::Fat12 => {
            vajra_fs_fat::enumerate_entries(source, partition_offset)
                .map_err(|e| CarveError::Filesystem(format!("FAT error: {}", e)))?
        }
        _ => Vec::new(),
    };

    let mut id_counter = 1000u64;

    for entry in entries {
        let (payload, source_locations) = match &entry.data_location {
            DataLocation::Resident(bytes) => (bytes.clone(), Vec::new()),
            DataLocation::Contiguous { start_lba, block_count } => {
                let bytes = source
                    .read_blocks(*start_lba, *block_count as u32)
                    .unwrap_or_default();
                let actual_bytes = if let Some(size) = entry.size_bytes {
                    bytes[..((size as usize).min(bytes.len()))].to_vec()
                } else {
                    bytes
                };
                (actual_bytes, vec![(*start_lba, *block_count)])
            }
            DataLocation::Fragmented(exts) => {
                let mut all_bytes = Vec::new();
                for &(s, c) in exts {
                    if let Ok(b) = source.read_blocks(s, c as u32) {
                        all_bytes.extend(b);
                    }
                }
                let actual_bytes = if let Some(size) = entry.size_bytes {
                    all_bytes[..((size as usize).min(all_bytes.len()))].to_vec()
                } else {
                    all_bytes
                };
                (actual_bytes, exts.clone())
            }
            DataLocation::Unresolved => (Vec::new(), Vec::new()),
        };

        // Determine file type from extension
        let file_type = entry
            .filename
            .as_ref()
            .and_then(|name| name.split('.').last())
            .unwrap_or("unknown")
            .to_lowercase();

        // Calculate SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let content_hash = hex::encode(hasher.finalize());

        // Confidence signals
        let meta_sig = ConfidenceBreakdown::evaluate_metadata_confidence(Some(entry.metadata_confidence));
        let entropy_sig = entropy_analyzer.evaluate_consistency(&payload, &file_type);

        let confidence_breakdown = ConfidenceBreakdown {
            header_footer_integrity: 1.0,
            structural_validity: 1.0,
            metadata_cross_reference: meta_sig,
            entropy_consistency: entropy_sig,
            entropy_explainability: None,
            fragmentation_confidence: 1.0,
            overwrite_probability: if entry.metadata_confidence == MetadataConfidence::Confirmed {
                1.0
            } else {
                0.6
            },
        };

        let confidence_score = confidence_breakdown.composite_score();

        // Only Confirmed or Partial confidence blocks Tier 2/3 carving on those LBAs (§25)
        if entry.metadata_confidence == MetadataConfidence::Confirmed
            || entry.metadata_confidence == MetadataConfidence::Partial
        {
            for &(s, c) in &source_locations {
                allocated_map.mark_range(s, c);
            }
        }

        let limitations = if payload.is_empty() && entry.size_bytes.unwrap_or(0) > 0 {
            Some("Payload unavailable or overwritten".to_string())
        } else {
            None
        };

        id_counter += 1;
        artifacts.push(RecoveredArtifact {
            id: id_counter,
            recovery_method: RecoveryTier::Tier1Metadata,
            source_locations,
            original_path: entry.original_path.clone(),
            filename_guess: entry.filename.clone(),
            file_type,
            confidence_score,
            confidence_breakdown,
            fragmentation_detail: None,
            recovered_bytes: payload.len() as u64,
            expected_total_bytes: entry.size_bytes,
            content_hash,
            recovery_limitations: limitations,
            payload,
        });
    }

    Ok((artifacts, allocated_map))
}
