//! Tier 2: Signature-Based Carving with Garfinkel Structural Validation (§26.1, §26.2).

pub mod jpeg;
pub mod ole2;
pub mod pdf;
pub mod png;
pub mod signature_db;
pub mod sqlite;
pub mod validator;
pub mod zip;

pub use jpeg::JpegValidator;
pub use ole2::Ole2Validator;
pub use pdf::PdfValidator;
pub use png::PngValidator;
pub use signature_db::{FileSignature, SignatureDb};
pub use sqlite::SqliteValidator;
pub use validator::{StructuralValidator, ValidationResult, ValidatorFlags};
pub use zip::ZipValidator;

use crate::confidence::ConfidenceBreakdown;
use crate::entropy::{EntropyAnalyzer, HeuristicEntropyAnalyzer};
use crate::error::CarveError;
use crate::tier1::AllocatedBlockMap;
use crate::types::{RecoveredArtifact, RecoveryTier};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vajra_core::ReadOnlyBlockSource;

/// Registry of compiled structural validators (§26.2).
pub struct ValidatorRegistry {
    pub validators: Vec<(String, Arc<dyn StructuralValidator>)>,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self {
            validators: vec![
                ("jpeg".to_string(), Arc::new(JpegValidator)),
                ("png".to_string(), Arc::new(PngValidator)),
                ("pdf".to_string(), Arc::new(PdfValidator)),
                ("zip".to_string(), Arc::new(ZipValidator)),
                ("sqlite".to_string(), Arc::new(SqliteValidator)),
                ("ole2".to_string(), Arc::new(Ole2Validator)),
            ],
        }
    }
}

impl ValidatorRegistry {
    pub fn get(&self, id: &str) -> Option<Arc<dyn StructuralValidator>> {
        self.validators
            .iter()
            .find(|(name, _)| name == id)
            .map(|(_, v)| Arc::clone(v))
    }
}

/// Executes Tier-2 signature-based carving with Garfinkel structural validation (§26.1, §26.2).
pub fn carve_tier2(
    source: &mut dyn ReadOnlyBlockSource,
    sig_db: &SignatureDb,
    registry: &ValidatorRegistry,
    allocated_map: &mut AllocatedBlockMap,
    target_types: Option<&[String]>,
) -> Result<Vec<RecoveredArtifact>, CarveError> {
    carve_tier2_with_analyzer(source, sig_db, registry, allocated_map, target_types, None)
}

/// Executes Tier-2 signature-based carving with an optional custom entropy analyzer (§26, §33).
pub fn carve_tier2_with_analyzer(
    source: &mut dyn ReadOnlyBlockSource,
    sig_db: &SignatureDb,
    registry: &ValidatorRegistry,
    allocated_map: &mut AllocatedBlockMap,
    target_types: Option<&[String]>,
    custom_analyzer: Option<&dyn EntropyAnalyzer>,
) -> Result<Vec<RecoveredArtifact>, CarveError> {
    let total_blocks = source.total_blocks();
    let block_size = source.block_size() as u64;
    let mut artifacts = Vec::new();
    let default_analyzer = HeuristicEntropyAnalyzer::default();
    let entropy_analyzer = custom_analyzer.unwrap_or(&default_analyzer);
    let mut id_counter = 2000u64;

    let mut current_lba = 0u64;

    while current_lba < total_blocks {
        // Skip sectors already claimed by Tier-1 Confirmed/Partial recovery (§25 precedence)
        if allocated_map.contains(current_lba) {
            current_lba += 1;
            continue;
        }

        // Read 1 sector to check for signature headers
        let sector_bytes = match source.read_blocks(current_lba, 1) {
            Ok(b) => b,
            Err(_) => {
                current_lba += 1;
                continue;
            }
        };

        // Check against active signatures
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

                let flags = validator.flags();

                // Fast zero-block rejection (§26.2)
                if flags.no_zblocks && sector_bytes.iter().all(|&b| b == 0) {
                    continue;
                }

                // Determine read window
                let max_sectors = ((sig.max_size_bytes + block_size - 1) / block_size).min(total_blocks - current_lba);
                let read_sectors = max_sectors.min(2048) as u32; // Read up to 1MB chunks for fast validation

                let candidate_bytes = match source.read_blocks(current_lba, read_sectors) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let validation = validator.validate(&candidate_bytes);

                if let ValidationResult::Ok { object_length } = validation {
                    let actual_len = object_length.unwrap_or(candidate_bytes.len() as u64) as usize;
                    let payload = if actual_len <= candidate_bytes.len() {
                        candidate_bytes[..actual_len].to_vec()
                    } else {
                        // Read full length if beyond initial 1MB window
                        let full_sectors = ((actual_len as u64 + block_size - 1) / block_size) as u32;
                        source.read_blocks(current_lba, full_sectors).unwrap_or_default()[..actual_len.min(candidate_bytes.len())].to_vec()
                    };

                    let sectors_consumed = ((payload.len() as u64 + block_size - 1) / block_size).max(1);

                    // Compute SHA-256
                    let mut hasher = Sha256::new();
                    hasher.update(&payload);
                    let content_hash = hex::encode(hasher.finalize());

                    let entropy_sig = entropy_analyzer.evaluate_consistency(&payload, &sig.file_type);

                    let confidence_breakdown = ConfidenceBreakdown {
                        header_footer_integrity: 1.0,
                        structural_validity: 1.0,
                        metadata_cross_reference: 0.0, // Pure carved artifact
                        entropy_consistency: entropy_sig,
                        entropy_explainability: None,
                        fragmentation_confidence: 1.0,
                        overwrite_probability: 1.0,
                    };

                    let confidence_score = confidence_breakdown.composite_score();

                    id_counter += 1;
                    let artifact = RecoveredArtifact {
                        id: id_counter,
                        recovery_method: RecoveryTier::Tier2Signature,
                        source_locations: vec![(current_lba, sectors_consumed)],
                        original_path: None,
                        filename_guess: Some(format!("carved_file_{:04}.{}", id_counter, sig.file_type)),
                        file_type: sig.file_type.clone(),
                        confidence_score,
                        confidence_breakdown,
                        fragmentation_detail: None,
                        recovered_bytes: payload.len() as u64,
                        expected_total_bytes: Some(payload.len() as u64),
                        content_hash,
                        recovery_limitations: None,
                        payload,
                    };

                    // Mark sectors as resolved
                    allocated_map.mark_range(current_lba, sectors_consumed);
                    artifacts.push(artifact);

                    current_lba += sectors_consumed.saturating_sub(1);
                    break;
                }
            }
        }

        current_lba += 1;
    }

    Ok(artifacts)
}
