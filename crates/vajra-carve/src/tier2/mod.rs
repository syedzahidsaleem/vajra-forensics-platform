//! Tier 2: Signature-Based Carving with Garfinkel Structural Validation (§26.1, §26.2).

pub mod jpeg;
pub mod mp4;
pub mod ole2;
pub mod pdf;
pub mod png;
pub mod signature_db;
pub mod sqlite;
pub mod validator;
pub mod zip;

pub use jpeg::JpegValidator;
pub use mp4::Mp4Validator;
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
                ("mp4".to_string(), Arc::new(Mp4Validator)),
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

            if sig.matches_header(&sector_bytes) {
                let validator = match registry.get(&sig.validator_id) {
                    Some(v) => v,
                    None => continue,
                };

                let flags = validator.flags();

                // Fast zero-block rejection (§26.2)
                if flags.no_zblocks && sector_bytes.iter().all(|&b| b == 0) {
                    continue;
                }

                // Determine read window: initially read up to 1MB chunks (2048 sectors) for fast check
                let max_sectors = ((sig.max_size_bytes + block_size - 1) / block_size).min(total_blocks - current_lba);
                let read_sectors = max_sectors.min(2048) as u32;

                let mut candidate_bytes = match source.read_blocks(current_lba, read_sectors) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let mut validation = validator.validate(&candidate_bytes);

                // Priority 2 Fix 1: Window expansion when early read suggests a larger object
                if validation.is_eof() && (read_sectors as u64) < max_sectors {
                    // Try expanding window up to 8 MiB (16384 sectors) or max_sectors to resolve large files
                    let expanded_sectors = max_sectors.min(16384) as u32;
                    if expanded_sectors > read_sectors {
                        if let Ok(exp_bytes) = source.read_blocks(current_lba, expanded_sectors) {
                            let exp_validation = validator.validate(&exp_bytes);
                            if exp_validation.is_ok() || exp_validation.is_eof() {
                                candidate_bytes = exp_bytes;
                                validation = exp_validation;
                            }
                        }
                    }
                }

                if let ValidationResult::Ok { object_length } = validation {
                    let actual_len = object_length.unwrap_or(candidate_bytes.len() as u64) as usize;
                    let payload = if actual_len <= candidate_bytes.len() {
                        candidate_bytes[..actual_len].to_vec()
                    } else {
                        // Read full length if beyond initial window, properly bounded by total available sectors
                        let full_sectors = ((actual_len as u64 + block_size - 1) / block_size).min(total_blocks - current_lba) as u32;
                        let full_bytes = source.read_blocks(current_lba, full_sectors).unwrap_or_default();
                        full_bytes[..actual_len.min(full_bytes.len())].to_vec()
                    };

                    let sectors_consumed = ((payload.len() as u64 + block_size - 1) / block_size).max(1);

                    // Compute SHA-256
                    let mut hasher = Sha256::new();
                    hasher.update(&payload);
                    let content_hash = hex::encode(hasher.finalize());

                    let entropy_sig = entropy_analyzer.evaluate_consistency(&payload, &sig.file_type);

                    // Priority 1: Genuine per-candidate Header/Footer and Structural confidence scoring
                    let (hfi_score, _hfi_reason) = evaluate_header_footer_integrity(&payload, sig, false);
                    let (struct_score, _struct_reason) = evaluate_structural_validity(&validation, &payload, sig);

                    let confidence_breakdown = ConfidenceBreakdown {
                        header_footer_integrity: hfi_score,
                        structural_validity: struct_score,
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
                } else if let ValidationResult::Eof { partial_length } = validation {
                    // Priority 2 Fix 2: Surface V_EOF candidates as real partial recoveries with explicit limitations
                    let min_useful_len: u64 = match sig.file_type.as_str() {
                        "png" => 33,    // Magic (8) + IHDR (25)
                        "jpeg" => 16,   // SOI (2) + SOF/DQT marker header
                        "pdf" => 32,    // %PDF- + catalog object
                        "sqlite" => 100,// 100-byte database header
                        "mp4" => 24,    // ftyp box + brand
                        "zip" => 30,    // Local file header (30 bytes min)
                        "ole2" => 512,  // 512-byte header sector
                        _ => 16,
                    };

                    if partial_length >= min_useful_len {
                        let payload_len = (partial_length as usize).min(candidate_bytes.len());
                        let payload = candidate_bytes[..payload_len].to_vec();
                        let sectors_consumed = ((payload.len() as u64 + block_size - 1) / block_size).max(1);

                        let mut hasher = Sha256::new();
                        hasher.update(&payload);
                        let content_hash = hex::encode(hasher.finalize());

                        let entropy_sig = entropy_analyzer.evaluate_consistency(&payload, &sig.file_type);

                        // Priority 1: Genuine per-candidate Header/Footer and Structural scoring for EOF candidate
                        let (hfi_score, hfi_reason) = evaluate_header_footer_integrity(&payload, sig, true);
                        let (struct_score, struct_reason) = evaluate_structural_validity(&validation, &payload, sig);

                        let confidence_breakdown = ConfidenceBreakdown {
                            header_footer_integrity: hfi_score,
                            structural_validity: struct_score,
                            metadata_cross_reference: 0.0,
                            entropy_consistency: entropy_sig,
                            entropy_explainability: None,
                            fragmentation_confidence: 0.80, // Reduced confidence due to missing tail/fragment
                            overwrite_probability: 1.0,
                        };

                        let confidence_score = confidence_breakdown.composite_score();

                        id_counter += 1;
                        let artifact = RecoveredArtifact {
                            id: id_counter,
                            recovery_method: RecoveryTier::Tier2Signature,
                            source_locations: vec![(current_lba, sectors_consumed)],
                            original_path: None,
                            filename_guess: Some(format!("carved_partial_{:04}.{}", id_counter, sig.file_type)),
                            file_type: sig.file_type.clone(),
                            confidence_score,
                            confidence_breakdown,
                            fragmentation_detail: None,
                            recovered_bytes: payload.len() as u64,
                            expected_total_bytes: None,
                            content_hash,
                            recovery_limitations: Some(format!(
                                "Truncated candidate (V_EOF): {}; {}",
                                hfi_reason, struct_reason
                            )),
                            payload,
                        };

                        artifacts.push(artifact);
                        // NOTE: We do NOT mark allocated_map for Eof candidates so Tier 3 BGC
                        // can still attempt bifragment gap carving if a second fragment exists!
                        break;
                    }
                }
            }
        }

        current_lba += 1;
    }

    Ok(artifacts)
}

/// Evaluates genuine per-candidate header and footer integrity (§26.1, §29).
///
/// Returns `(score, explanation)` for forensic explainability.
pub fn evaluate_header_footer_integrity(
    payload: &[u8],
    sig: &FileSignature,
    is_eof: bool,
) -> (f32, String) {
    if let Some(ref footer) = sig.footer {
        if is_eof {
            (
                0.50,
                format!(
                    "Valid {} header matched; footer missing due to stream truncation (V_EOF)",
                    sig.file_type.to_uppercase()
                ),
            )
        } else if payload.ends_with(footer) {
            (
                1.00,
                format!(
                    "Exact header and terminator match at boundary for {}",
                    sig.file_type.to_uppercase()
                ),
            )
        } else if let Some(pos) = payload.windows(footer.len()).rposition(|w| w == footer.as_slice()) {
            let trailing_slack = payload.len() - (pos + footer.len());
            let score = (1.00 - (trailing_slack as f32 / 512.0) * 0.15).clamp(0.80, 0.99);
            (
                score,
                format!(
                    "Header matched; footer present at offset {} ({} bytes trailing sector slack)",
                    pos, trailing_slack
                ),
            )
        } else {
            (
                0.60,
                format!(
                    "Valid header matched; expected footer sequence not located in payload"
                ),
            )
        }
    } else {
        // Footerless format (SQLite, MP4, OLE2): evaluate format-specific header integrity & geometry
        match sig.file_type.as_str() {
            "sqlite" => {
                if payload.len() >= 100 {
                    let raw_page_size = u16::from_be_bytes([payload[16], payload[17]]);
                    let page_size = if raw_page_size == 1 { 65536u32 } else { raw_page_size as u32 };
                    if (512..=65536).contains(&page_size) && (page_size & (page_size - 1)) == 0 {
                        (1.00, format!("SQLite 16-byte magic and valid page size ({} bytes) verified; footerless format by specification", page_size))
                    } else {
                        (0.70, "SQLite magic matched but page size field is non-standard".to_string())
                    }
                } else {
                    (0.50, "SQLite candidate truncated within 100-byte database header".to_string())
                }
            }
            "mp4" => {
                if payload.len() >= 12 && &payload[4..8] == b"ftyp" {
                    let brand = String::from_utf8_lossy(&payload[8..12]);
                    (1.00, format!("ISO-BMFF ftyp atom confirmed at offset 4 (brand: '{}'); footerless format by specification", brand))
                } else {
                    (0.60, "MP4 ftyp atom detected with incomplete brand specification".to_string())
                }
            }
            "ole2" => {
                if payload.len() >= 512 {
                    let sector_shift = u16::from_le_bytes([payload[30], payload[31]]);
                    if sector_shift == 9 || sector_shift == 12 {
                        (1.00, format!("OLE2 header magic and sector shift (2^{} = {} bytes) verified; footerless format by specification", sector_shift, 1 << sector_shift))
                    } else {
                        (0.75, "OLE2 magic verified with non-standard sector shift".to_string())
                    }
                } else {
                    (0.50, "OLE2 candidate truncated within 512-byte header block".to_string())
                }
            }
            _ => (1.00, format!("Valid magic header match for footerless format {}", sig.file_type)),
        }
    }
}

/// Evaluates genuine structural validity score based on Garfinkel validation state (§26.2, §29).
///
/// Returns `(score, explanation)`.
pub fn evaluate_structural_validity(
    validation: &ValidationResult,
    payload: &[u8],
    sig: &FileSignature,
) -> (f32, String) {
    match validation {
        ValidationResult::Ok { object_length } => {
            let desc = match object_length {
                Some(len) => format!("Fully parsed and structurally validated (V_OK, length: {} bytes)", len),
                None => "Fully parsed and structurally validated (V_OK, unbounded length)".to_string(),
            };
            (1.00, desc)
        }
        ValidationResult::Eof { partial_length } => {
            let total = payload.len().max(1) as f32;
            let ratio = (*partial_length as f32 / total).clamp(0.0, 1.0);
            let score = match sig.file_type.as_str() {
                "png" => 0.65, // IHDR chunk verified, stream truncated before IEND
                "jpeg" => 0.60, // SOI and marker tables verified, scan data truncated before EOI
                "pdf" => 0.60,  // Header and objects parsed, missing %%EOF trailer
                "sqlite" => 0.70, // Page 1 b-tree header verified, truncated before declared file size
                "mp4" => 0.55,  // Valid ftyp and partial box, truncated media stream
                "zip" => 0.55,  // Valid local file header, central directory truncated
                _ => (0.50 + 0.20 * ratio).clamp(0.50, 0.70),
            };
            (
                score,
                format!(
                    "V_EOF: structurally sound prefix ({} bytes verified of {} bytes read), but object truncated before end",
                    partial_length, payload.len()
                ),
            )
        }
        ValidationResult::Err(reason) => (0.00, format!("Structural parsing failed (V_ERR: {})", reason)),
    }
}
