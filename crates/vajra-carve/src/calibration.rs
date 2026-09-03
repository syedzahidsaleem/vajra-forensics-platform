//! Empirical Confidence Score Calibration Engine (§30).
//!
//! Provides labeled benchmark corpus evaluation, Precision/Recall/F1 and Brier calibration loss calculation,
//! and empirical grid-search optimization for confidence score weights (§29, §30, §45).

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::confidence::{
    ConfidenceBreakdown, WEIGHT_ENTROPY, WEIGHT_FRAGMENTATION, WEIGHT_HEADER_FOOTER,
    WEIGHT_METADATA, WEIGHT_OVERWRITE, WEIGHT_STRUCTURAL,
};

/// A labeled ground-truth candidate sample for empirical calibration (§30, §45).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabeledGroundTruthSample {
    /// Sample identifier or filename.
    pub sample_id: String,
    /// Classified file format (e.g. "jpeg", "png", "pdf", "zip", "sqlite").
    pub file_type: String,
    /// Known ground-truth status: `true` if this candidate represents a fully valid, recoverable file.
    pub is_truly_valid: bool,
    /// Component confidence breakdown signals for this candidate.
    pub breakdown: ConfidenceBreakdown,
}

/// Evaluated performance and calibration metrics for a weight profile (§30).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationMetrics {
    /// Total samples evaluated.
    pub total_samples: usize,
    /// True Positives (high confidence >= 0.7 and truly valid).
    pub true_positives: usize,
    /// False Positives (high confidence >= 0.7 but truly invalid/corrupted).
    pub false_positives: usize,
    /// True Negatives (low confidence < 0.7 and truly invalid).
    pub true_negatives: usize,
    /// False Negatives (low confidence < 0.7 but truly valid).
    pub false_negatives: usize,
    /// Precision = TP / (TP + FP).
    pub precision: f32,
    /// Recall = TP / (TP + FN).
    pub recall: f32,
    /// F1-Score = 2 * (Precision * Recall) / (Precision + Recall).
    pub f1_score: f32,
    /// Mean Squared Error (MSE) between composite score and binary true label.
    pub mse_loss: f32,
    /// Brier Calibration Score: $\frac{1}{N} \sum_{i=1}^N (score_i - label_i)^2$.
    pub brier_score: f32,
}

/// Dynamic weight profile for the 6-signal composite confidence model (§29, §30).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunableWeightProfile {
    pub weight_header_footer: f32,
    pub weight_structural: f32,
    pub weight_metadata: f32,
    pub weight_entropy: f32,
    pub weight_fragmentation: f32,
    pub weight_overwrite: f32,
}

impl Default for TunableWeightProfile {
    fn default() -> Self {
        Self {
            weight_header_footer: WEIGHT_HEADER_FOOTER,
            weight_structural: WEIGHT_STRUCTURAL,
            weight_metadata: WEIGHT_METADATA,
            weight_entropy: WEIGHT_ENTROPY,
            weight_fragmentation: WEIGHT_FRAGMENTATION,
            weight_overwrite: WEIGHT_OVERWRITE,
        }
    }
}

impl TunableWeightProfile {
    /// Computes composite score for a breakdown under this specific weight profile.
    pub fn compute_score(&self, breakdown: &ConfidenceBreakdown) -> f32 {
        let raw = (self.weight_header_footer * breakdown.header_footer_integrity)
            + (self.weight_structural * breakdown.structural_validity)
            + (self.weight_metadata * breakdown.metadata_cross_reference)
            + (self.weight_entropy * breakdown.entropy_consistency)
            + (self.weight_fragmentation * breakdown.fragmentation_confidence)
            + (self.weight_overwrite * breakdown.overwrite_probability);
        raw.clamp(0.0, 1.0)
    }

    /// Normalizes weights so that their sum strictly equals 1.0.
    pub fn normalize(&mut self) {
        let sum = self.weight_header_footer
            + self.weight_structural
            + self.weight_metadata
            + self.weight_entropy
            + self.weight_fragmentation
            + self.weight_overwrite;
        if sum > 0.0 {
            self.weight_header_footer /= sum;
            self.weight_structural /= sum;
            self.weight_metadata /= sum;
            self.weight_entropy /= sum;
            self.weight_fragmentation /= sum;
            self.weight_overwrite /= sum;
        }
    }
}

/// Calibration Engine performing empirical weight optimization (§30).
pub struct EmpiricalCalibrator {
    dataset: Vec<LabeledGroundTruthSample>,
}

impl EmpiricalCalibrator {
    /// Creates a new calibrator instance with a labeled dataset.
    pub fn new(dataset: Vec<LabeledGroundTruthSample>) -> Self {
        Self { dataset }
    }

    /// Evaluates a specific weight profile against the labeled ground-truth dataset.
    pub fn evaluate(&self, weights: &TunableWeightProfile) -> CalibrationMetrics {
        let mut tp = 0;
        let mut fp = 0;
        let mut tn = 0;
        let mut fn_count = 0;
        let mut sum_squared_err = 0.0f32;

        let threshold = 0.70f32;

        for sample in &self.dataset {
            let score = weights.compute_score(&sample.breakdown);
            let target_label = if sample.is_truly_valid { 1.0f32 } else { 0.0f32 };
            let err = score - target_label;
            sum_squared_err += err * err;

            let predicted_valid = score >= threshold;

            match (predicted_valid, sample.is_truly_valid) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, false) => tn += 1,
                (false, true) => fn_count += 1,
            }
        }

        let total = self.dataset.len();
        let precision = if tp + fp > 0 {
            tp as f32 / (tp + fp) as f32
        } else {
            0.0
        };
        let recall = if tp + fn_count > 0 {
            tp as f32 / (tp + fn_count) as f32
        } else {
            0.0
        };
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        };
        let brier_score = if total > 0 {
            sum_squared_err / total as f32
        } else {
            0.0
        };

        CalibrationMetrics {
            total_samples: total,
            true_positives: tp,
            false_positives: fp,
            true_negatives: tn,
            false_negatives: fn_count,
            precision,
            recall,
            f1_score,
            mse_loss: brier_score,
            brier_score,
        }
    }

    /// Runs grid-search optimization to discover the optimal weight profile maximizing F1-score (§30).
    pub fn optimize(&self) -> (TunableWeightProfile, CalibrationMetrics) {
        let mut best_profile = TunableWeightProfile::default();
        let mut best_metrics = self.evaluate(&best_profile);

        // Coarse grid search over weight perturbations
        let steps = [0.10, 0.15, 0.20, 0.25, 0.30];

        for &w_hf in &steps {
            for &w_struct in &steps {
                for &w_meta in &steps {
                    for &w_ent in &[0.05, 0.10, 0.15] {
                        let mut candidate = TunableWeightProfile {
                            weight_header_footer: w_hf,
                            weight_structural: w_struct,
                            weight_metadata: w_meta,
                            weight_entropy: w_ent,
                            weight_fragmentation: 0.15,
                            weight_overwrite: 0.05,
                        };
                        candidate.normalize();
                        let metrics = self.evaluate(&candidate);

                        if metrics.f1_score > best_metrics.f1_score
                            || (metrics.f1_score == best_metrics.f1_score
                                && metrics.brier_score < best_metrics.brier_score)
                        {
                            best_profile = candidate;
                            best_metrics = metrics;
                        }
                    }
                }
            }
        }

        (best_profile, best_metrics)
    }

    /// Exports calibrated weights profile to a JSON file.
    pub fn export_json<P: AsRef<Path>>(
        profile: &TunableWeightProfile,
        metrics: &CalibrationMetrics,
        path: P,
    ) -> Result<(), std::io::Error> {
        #[derive(Serialize)]
        struct ExportWrapper<'a> {
            calibrated_weights: &'a TunableWeightProfile,
            benchmark_metrics: &'a CalibrationMetrics,
        }

        let wrapper = ExportWrapper {
            calibrated_weights: profile,
            benchmark_metrics: metrics,
        };

        let json = serde_json::to_string_pretty(&wrapper)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empirical_calibration_and_metrics_calculation() {
        let samples = vec![
            // Truly valid sample with strong signals -> TP
            LabeledGroundTruthSample {
                sample_id: "s1_jpeg_valid".to_string(),
                file_type: "jpeg".to_string(),
                is_truly_valid: true,
                breakdown: ConfidenceBreakdown {
                    header_footer_integrity: 1.0,
                    structural_validity: 1.0,
                    metadata_cross_reference: 1.0,
                    entropy_consistency: 1.0,
                    entropy_explainability: None,
                    fragmentation_confidence: 1.0,
                    overwrite_probability: 1.0,
                },
            },
            // Truly corrupt sample with zero signals -> TN
            LabeledGroundTruthSample {
                sample_id: "s2_corrupt".to_string(),
                file_type: "jpeg".to_string(),
                is_truly_valid: false,
                breakdown: ConfidenceBreakdown {
                    header_footer_integrity: 0.0,
                    structural_validity: 0.0,
                    metadata_cross_reference: 0.0,
                    entropy_consistency: 0.2,
                    entropy_explainability: None,
                    fragmentation_confidence: 0.5,
                    overwrite_probability: 0.5,
                },
            },
        ];

        let calibrator = EmpiricalCalibrator::new(samples);
        let default_profile = TunableWeightProfile::default();
        let metrics = calibrator.evaluate(&default_profile);

        assert_eq!(metrics.total_samples, 2);
        assert_eq!(metrics.true_positives, 1);
        assert_eq!(metrics.true_negatives, 1);
        assert_eq!(metrics.precision, 1.0);
        assert_eq!(metrics.recall, 1.0);
        assert_eq!(metrics.f1_score, 1.0);

        let (best_profile, best_metrics) = calibrator.optimize();
        assert!(best_metrics.f1_score >= 0.99);
        assert!((best_profile.weight_header_footer + best_profile.weight_structural + best_profile.weight_metadata + best_profile.weight_entropy + best_profile.weight_fragmentation + best_profile.weight_overwrite - 1.0).abs() < 1e-4);
    }
}
