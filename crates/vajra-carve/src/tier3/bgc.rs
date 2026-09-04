//! Bifragment Gap Carving (BGC) Engine (§27).
//!
//! Implements Simson Garfinkel's seminal Bifragment Gap Carving algorithm (DFRWS 2007)
//! with the empirical gap-size search-order optimization:
//! Gap sizes are evaluated in order `[8, 16, 32, 4, 64, 24, 40, 128, 256, 512, 1024, 2048]`
//! sectors (reflecting real filesystem allocation-cluster distributions) rather than
//! a naive linear 1,2,3,4... sweep.

use crate::confidence::ConfidenceBreakdown;
use crate::entropy::{EntropyAnalyzer, HeuristicEntropyAnalyzer};
use crate::tier1::AllocatedBlockMap;
use crate::tier2::validator::{StructuralValidator, ValidationResult};
use crate::types::{FragmentationDetail, RecoveredArtifact, RecoveryTier};
use sha2::{Digest, Sha256};
use vajra_core::ReadOnlyBlockSource;

/// Empirical gap-size search-order table from Garfinkel (2007) Section 3 fragmentation survey.
pub const EMPIRICAL_GAP_SEARCH_ORDER: &[u64] = &[8, 16, 32, 4, 64, 24, 40, 128, 256, 512, 1024, 2048];

/// Default maximum search radius in sectors (e.g. 2048 sectors = 1MB).
pub const DEFAULT_MAX_SEARCH_RADIUS: u64 = 2048;

/// Executes Bifragment Gap Carving for a candidate starting at `start_lba`.
pub fn bifragment_gap_carve(
    source: &mut dyn ReadOnlyBlockSource,
    start_lba: u64,
    file_type: &str,
    validator: &dyn StructuralValidator,
    expected_sectors: u64,
    max_search_radius: u64,
    allocated_map: &AllocatedBlockMap,
) -> Option<RecoveredArtifact> {
    bifragment_gap_carve_with_analyzer(
        source,
        start_lba,
        file_type,
        validator,
        expected_sectors,
        max_search_radius,
        allocated_map,
        None,
    )
}

/// Executes Bifragment Gap Carving with an optional custom entropy analyzer (§27, §33).
pub fn bifragment_gap_carve_with_analyzer(
    source: &mut dyn ReadOnlyBlockSource,
    start_lba: u64,
    file_type: &str,
    validator: &dyn StructuralValidator,
    expected_sectors: u64,
    max_search_radius: u64,
    allocated_map: &AllocatedBlockMap,
    custom_analyzer: Option<&dyn EntropyAnalyzer>,
) -> Option<RecoveredArtifact> {
    let total_blocks = source.total_blocks();
    let _block_size = source.block_size() as u64;
    let default_analyzer = HeuristicEntropyAnalyzer::default();
    let entropy_analyzer = custom_analyzer.unwrap_or(&default_analyzer);

    if start_lba + expected_sectors >= total_blocks {
        return None;
    }

    // Build the gap size search sequence: empirical order first, then remaining gaps up to max_radius
    let mut gap_sizes = Vec::new();
    for &gap in EMPIRICAL_GAP_SEARCH_ORDER {
        if gap <= max_search_radius && gap + start_lba + expected_sectors < total_blocks {
            gap_sizes.push(gap);
        }
    }
    for gap in 1..=max_search_radius {
        if !gap_sizes.contains(&gap) && gap + start_lba + expected_sectors < total_blocks {
            gap_sizes.push(gap);
        }
    }

    // BGC search loop (O(n²) complexity for candidate object, Garfinkel 2007)
    let flags = validator.flags();

    // Test possible split points for fragment 1
    for frag1_sectors in 1..expected_sectors {
        if allocated_map.overlaps(start_lba, frag1_sectors) {
            continue;
        }

        // Read fragment 1 once per split point
        let frag1_bytes = match source.read_blocks(start_lba, frag1_sectors as u32) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Early prefix rejection: if fragment 1 itself is corrupted and format is prefix-sensitive, skip
        if flags.err_is_prefix {
            let prefix_val = validator.validate(&frag1_bytes);
            if prefix_val.is_err() {
                continue;
            }
        }

        for &gap_size in &gap_sizes {
            let frag2_sectors = expected_sectors - frag1_sectors;
            let frag2_start_lba = start_lba + frag1_sectors + gap_size;

            if frag2_start_lba + frag2_sectors > total_blocks {
                continue;
            }

            // If fragment 2 collides with confirmed Tier-1 files, skip
            if allocated_map.overlaps(frag2_start_lba, frag2_sectors) {
                continue;
            }

            // Read fragment 2
            let frag2_bytes = match source.read_blocks(frag2_start_lba, frag2_sectors as u32) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Concatenate fragments
            let mut candidate = Vec::with_capacity(frag1_bytes.len() + frag2_bytes.len());
            candidate.extend_from_slice(&frag1_bytes);
            candidate.extend_from_slice(&frag2_bytes);

            // Validate concatenated payload
            let validation = validator.validate(&candidate);

            if let ValidationResult::Ok { object_length } = validation {
                let actual_len = object_length.unwrap_or(candidate.len() as u64) as usize;
                let payload = if actual_len <= candidate.len() {
                    candidate[..actual_len].to_vec()
                } else {
                    candidate
                };

                // Compute SHA-256
                let mut hasher = Sha256::new();
                hasher.update(&payload);
                let content_hash = hex::encode(hasher.finalize());

                let entropy_sig = entropy_analyzer.evaluate_consistency(&payload, file_type);

                // Fragmentation confidence penalty based on gap distance
                let frag_penalty = (gap_size as f32 / max_search_radius as f32).min(1.0) * 0.5;

                let confidence_breakdown = ConfidenceBreakdown {
                    header_footer_integrity: 1.0,
                    structural_validity: 1.0,
                    metadata_cross_reference: 0.0,
                    entropy_consistency: entropy_sig,
                    entropy_explainability: None,
                    fragmentation_confidence: (1.0 - frag_penalty).clamp(0.1, 1.0),
                    overwrite_probability: 1.0,
                };

                let confidence_score = confidence_breakdown.composite_score();

                let frag_detail = FragmentationDetail {
                    gap_size_sectors: gap_size,
                    fragment_1: (start_lba, frag1_sectors),
                    fragment_2: (frag2_start_lba, frag2_sectors),
                };

                let limitations = format!(
                    "Reconstructed from 2 fragments across {}-sector unallocated gap (LBA {}..{} and LBA {}..{})",
                    gap_size,
                    start_lba,
                    start_lba + frag1_sectors,
                    frag2_start_lba,
                    frag2_start_lba + frag2_sectors
                );

                return Some(RecoveredArtifact {
                    id: 3000 + start_lba,
                    recovery_method: RecoveryTier::Tier3Fragmented,
                    source_locations: vec![
                        (start_lba, frag1_sectors),
                        (frag2_start_lba, frag2_sectors),
                    ],
                    original_path: None,
                    filename_guess: Some(format!("reconstructed_file_{}.{}", start_lba, file_type)),
                    file_type: file_type.to_string(),
                    confidence_score,
                    confidence_breakdown,
                    fragmentation_detail: Some(frag_detail),
                    recovered_bytes: payload.len() as u64,
                    expected_total_bytes: Some(payload.len() as u64),
                    content_hash,
                    recovery_limitations: Some(limitations),
                    payload,
                });
            }
        }
    }

    None
}
