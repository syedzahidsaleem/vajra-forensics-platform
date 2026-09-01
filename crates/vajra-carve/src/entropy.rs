//! Shannon Entropy Analysis & Profile Consistency (§29, §33).
//!
//! Evaluates the entropy profile of candidate data against expected characteristics
//! for each file format. Structured via `EntropyAnalyzer` trait to allow seamless
//! drop-in of ML-based classifiers (LightGBM/ONNX) in Conversation 07 (§33).

/// Calculates Shannon entropy in bits per byte (range: 0.0 to 8.0).
pub fn calculate_shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Interface for entropy analysis and format profile scoring.
pub trait EntropyAnalyzer: Send + Sync {
    /// Computes an entropy consistency score (0.0–1.0) for candidate data against a target format.
    fn evaluate_consistency(&self, data: &[u8], file_type: &str) -> f32;
}

/// Baseline heuristic entropy profile evaluator (§29).
#[derive(Debug, Default, Clone)]
pub struct HeuristicEntropyAnalyzer;

impl EntropyAnalyzer for HeuristicEntropyAnalyzer {
    fn evaluate_consistency(&self, data: &[u8], file_type: &str) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let entropy = calculate_shannon_entropy(data);

        match file_type.to_lowercase().as_str() {
            // Compressed formats: expect very high entropy (> 7.0)
            "jpeg" | "jpg" | "png" | "zip" | "docx" | "xlsx" | "pptx" => {
                if entropy >= 7.2 {
                    1.0
                } else if entropy >= 6.0 {
                    0.7
                } else if entropy >= 4.5 {
                    0.4
                } else {
                    0.1
                }
            }
            // Mixed text/stream formats: expect moderate to high entropy (4.5 to 7.8)
            "pdf" => {
                if (4.5..=7.9).contains(&entropy) {
                    1.0
                } else if entropy > 3.0 {
                    0.7
                } else {
                    0.2
                }
            }
            // Database b-tree pages: expect moderate entropy (3.0 to 6.5)
            "sqlite" | "db" => {
                if (3.0..=6.8).contains(&entropy) {
                    1.0
                } else if entropy > 2.0 {
                    0.7
                } else {
                    0.3
                }
            }
            // Default generic profile
            _ => {
                if entropy > 3.0 {
                    0.8
                } else {
                    0.4
                }
            }
        }
    }
}
