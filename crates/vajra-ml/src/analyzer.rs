//! ML-Backed Entropy and Format Profile Analyzer (§29, §33).
//!
//! Implements Conversation 05's `EntropyAnalyzer` trait using the trained GBDT classifier,
//! providing an empirical, explainable replacement for the baseline heuristic.

use crate::classifier::{ClassificationResult, FileTypeClassifier};
use crate::features::extract_features;
use std::sync::Arc;
use vajra_carve::entropy::EntropyAnalyzer;

/// ML-backed Entropy and File Profile Analyzer (§29, §33).
#[derive(Clone)]
pub struct MlEntropyAnalyzer {
    classifier: Arc<FileTypeClassifier>,
}

impl Default for MlEntropyAnalyzer {
    fn default() -> Self {
        Self {
            classifier: Arc::new(FileTypeClassifier::default()),
        }
    }
}

impl MlEntropyAnalyzer {
    /// Creates an analyzer with the default embedded classifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an analyzer with a custom pre-loaded classifier.
    pub fn with_classifier(classifier: FileTypeClassifier) -> Self {
        Self {
            classifier: Arc::new(classifier),
        }
    }

    /// Computes full classification and explainability basis for candidate data.
    pub fn explain_candidate(&self, data: &[u8]) -> ClassificationResult {
        let features = extract_features(data);
        self.classifier.classify(&features)
    }

    /// Computes format-specific consistency score and explainable report.
    pub fn explain_consistency(&self, data: &[u8], file_type: &str) -> (f32, ClassificationResult) {
        let report = self.explain_candidate(data);
        let target_lower = file_type.to_lowercase();

        // Normalize format aliases
        let canonical_target = match target_lower.as_str() {
            "jpg" | "jpeg" => "jpeg",
            "png" => "png",
            "pdf" => "pdf",
            "zip" | "docx" | "xlsx" | "pptx" => "zip",
            "sqlite" | "db" => "sqlite",
            _ => &target_lower,
        };

        let target_prob = report
            .class_probabilities
            .iter()
            .find(|(cls, _)| cls == canonical_target)
            .map(|(_, p)| *p)
            .unwrap_or(0.0);

        // Baseline Shannon entropy consistency prior
        let heuristic_baseline = vajra_carve::entropy::HeuristicEntropyAnalyzer.evaluate_consistency(data, file_type);

        // Compute composite consistency score:
        // When ML confidence is strong, it dominates; on ambiguous/very short inputs, baseline entropy anchors the score.
        let consistency = if target_prob >= 0.60 {
            0.80 + (target_prob - 0.60) * 0.50
        } else if report.predicted_class == canonical_target {
            0.60 + (target_prob * 0.40)
        } else if report.predicted_class == "unknown" {
            // Unclear content: rely on baseline heuristic entropy
            0.50 * heuristic_baseline + 0.50 * target_prob
        } else {
            // Confident mismatch: penalized
            (0.30 * heuristic_baseline + 0.20 * target_prob).min(0.40)
        };

        (consistency.clamp(0.1, 1.0), report)
    }
}

impl EntropyAnalyzer for MlEntropyAnalyzer {
    fn evaluate_consistency(&self, data: &[u8], file_type: &str) -> f32 {
        let (score, _) = self.explain_consistency(data, file_type);
        score
    }
}
