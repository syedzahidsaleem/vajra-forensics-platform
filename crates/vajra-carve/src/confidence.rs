//! Recovery Confidence Scoring (§29).
//!
//! Implements the 6-signal weighted composite confidence formula per §29.
//! All weights are clearly defined as named constants for future empirical calibration (§30).

use serde::{Deserialize, Serialize};
use vajra_core::MetadataConfidence;

// --- NAMED TUNABLE WEIGHT CONSTANTS (§29) ---
// Note: These are initial baseline weights pending empirical calibration against labeled corpora (§30).
pub const WEIGHT_HEADER_FOOTER: f32 = 0.20;
pub const WEIGHT_STRUCTURAL: f32 = 0.25;
pub const WEIGHT_METADATA: f32 = 0.20;
pub const WEIGHT_ENTROPY: f32 = 0.15;
pub const WEIGHT_FRAGMENTATION: f32 = 0.15;
pub const WEIGHT_OVERWRITE: f32 = 0.05;

/// Component signal breakdown of recovery confidence (§29).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    /// Exact signature match + valid terminator presence (0.0–1.0). Weight: 0.20.
    pub header_footer_integrity: f32,

    /// Result of format-specific structural validation (0.0–1.0, e.g. V_OK=1.0, V_EOF=0.5, V_ERR=0.0). Weight: 0.25.
    pub structural_validity: f32,

    /// Corroboration from surviving filesystem metadata (§25, §29) (0.0–1.0). Weight: 0.20.
    /// Mapping:
    /// - Confirmed: 1.0 (100% metadata intact + unallocated data blocks confirmed)
    /// - Partial: 0.6 (Metadata intact, some blocks uncertain)
    /// - Reconstructed: 0.4 (Directory slack or journal replay)
    /// - Low: 0.1 (Corrupted metadata)
    /// - None (Pure carved candidate without metadata): 0.0
    pub metadata_cross_reference: f32,

    /// Shannon entropy consistency compared against expected file-type profile (0.0–1.0). Weight: 0.15.
    pub entropy_consistency: f32,

    /// Optional inspectable basis for ML-derived entropy consistency (§33, §31).
    pub entropy_explainability: Option<String>,

    /// Fragmentation reconstruction quality (0.0–1.0). Weight: 0.15.
    /// - Contiguous / Unfragmented: 1.0
    /// - Bifragment Gap Carved: 1.0 - ((gap_size / max_radius) * 0.5)
    pub fragmentation_confidence: f32,

    /// Non-overwrite integrity score (0.0–1.0). Weight: 0.05.
    /// - 1.0: Blocks confirmed unallocated and free of overwriting data.
    /// - 0.5: Ambiguous or unreferenced block status.
    /// - 0.0: Region confirmed reallocated / overwritten by newer filesystem writes.
    pub overwrite_probability: f32,
}

impl Default for ConfidenceBreakdown {
    fn default() -> Self {
        Self {
            header_footer_integrity: 0.0,
            structural_validity: 0.0,
            metadata_cross_reference: 0.0,
            entropy_consistency: 0.5,
            entropy_explainability: None,
            fragmentation_confidence: 1.0,
            overwrite_probability: 1.0,
        }
    }
}


impl ConfidenceBreakdown {
    /// Computes composite confidence score using the §29 weighted formula.
    pub fn composite_score(&self) -> f32 {
        let score = (WEIGHT_HEADER_FOOTER * self.header_footer_integrity)
            + (WEIGHT_STRUCTURAL * self.structural_validity)
            + (WEIGHT_METADATA * self.metadata_cross_reference)
            + (WEIGHT_ENTROPY * self.entropy_consistency)
            + (WEIGHT_FRAGMENTATION * self.fragmentation_confidence)
            + (WEIGHT_OVERWRITE * self.overwrite_probability);

        score.clamp(0.0, 1.0)
    }

    /// Evaluates metadata cross-reference signal from optional `MetadataConfidence`.
    pub fn evaluate_metadata_confidence(meta_conf: Option<MetadataConfidence>) -> f32 {
        match meta_conf {
            Some(MetadataConfidence::Confirmed) => 1.0,
            Some(MetadataConfidence::Partial) => 0.6,
            Some(MetadataConfidence::Reconstructed) => 0.4,
            Some(MetadataConfidence::Low) => 0.1,
            None => 0.0,
        }
    }
}
