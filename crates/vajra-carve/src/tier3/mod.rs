//! Tier 3: Fragment Detection & Bifragment Gap Carving (BGC) (§27).

pub mod bgc;

pub use bgc::{bifragment_gap_carve, DEFAULT_MAX_SEARCH_RADIUS, EMPIRICAL_GAP_SEARCH_ORDER};

use crate::entropy::EntropyAnalyzer;
use crate::error::CarveError;
use crate::tier1::AllocatedBlockMap;
use crate::tier2::{SignatureDb, ValidatorRegistry};
use crate::types::RecoveredArtifact;
use vajra_core::ReadOnlyBlockSource;

/// Executes Tier-3 Bifragment Gap Carving across unallocated and fragmented candidates (§27).
pub fn carve_tier3(
    source: &mut dyn ReadOnlyBlockSource,
    sig_db: &SignatureDb,
    registry: &ValidatorRegistry,
    allocated_map: &mut AllocatedBlockMap,
    target_types: Option<&[String]>,
    max_search_radius: Option<u64>,
) -> Result<Vec<RecoveredArtifact>, CarveError> {
    carve_tier3_with_analyzer(
        source,
        sig_db,
        registry,
        allocated_map,
        target_types,
        max_search_radius,
        None,
    )
}

/// Executes Tier-3 Bifragment Gap Carving with an optional custom entropy analyzer (§27, §33).
pub fn carve_tier3_with_analyzer(
    source: &mut dyn ReadOnlyBlockSource,
    sig_db: &SignatureDb,
    registry: &ValidatorRegistry,
    allocated_map: &mut AllocatedBlockMap,
    target_types: Option<&[String]>,
    max_search_radius: Option<u64>,
    custom_analyzer: Option<&dyn EntropyAnalyzer>,
) -> Result<Vec<RecoveredArtifact>, CarveError> {
    let total_blocks = source.total_blocks();
    let radius = max_search_radius.unwrap_or(DEFAULT_MAX_SEARCH_RADIUS);
    let mut artifacts = Vec::new();

    let mut current_lba = 0u64;

    while current_lba < total_blocks {
        if allocated_map.contains(current_lba) {
            current_lba += 1;
            continue;
        }

        let sector_bytes = match source.read_blocks(current_lba, 1) {
            Ok(b) => b,
            Err(_) => {
                current_lba += 1;
                continue;
            }
        };

        for sig in &sig_db.signatures {
            if let Some(types) = target_types {
                if !types.iter().any(|t| t.eq_ignore_ascii_case(&sig.file_type)) {
                    continue;
                }
            }

            if sector_bytes.starts_with(&sig.header) {
                let validator = match registry.get(&sig.validator_id) {
                    Some(v) => v,
                    None => continue,
                };

                // Try bounded BGC search (search candidate sizes up to 16 sectors by default)
                for expected_sectors in 2..=16 {
                    if let Some(artifact) = bgc::bifragment_gap_carve_with_analyzer(
                        source,
                        current_lba,
                        &sig.file_type,
                        validator.as_ref(),
                        expected_sectors,
                        radius,
                        allocated_map,
                        custom_analyzer,
                    ) {
                        for &(s, c) in &artifact.source_locations {
                            allocated_map.mark_range(s, c);
                        }
                        artifacts.push(artifact);
                        break;
                    }
                }
            }
        }

        current_lba += 1;
    }

    Ok(artifacts)
}
