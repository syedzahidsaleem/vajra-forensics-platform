//! Feature Extraction Pipeline for File-Type Classification (§33).
//!
//! Computes the 280-dimensional feature vector:
//! 1. `[0..256]`: Byte frequency histogram (256 dimensions, normalized 0.0..1.0).
//! 2. `[256..272]`: Chunked Shannon entropy profile (16 uniform chunks across data, 0.0..8.0).
//! 3. `[272..278]`: 2-gram transition statistical summary (6 dimensions):
//!    - Sparsity (fraction of 65,536 bigrams with 0 count)
//!    - Top-10 concentration (sum of top 10 bigrams / total bigrams)
//!    - Transition entropy (Shannon entropy over bigram distribution)
//!    - Mean probability over active transitions
//!    - Variance of bigram distribution
//!    - Distinct bigram ratio (distinct / 65,536)
//! 4. `[278]`: Longest printable ASCII run (normalized log ratio).
//! 5. `[279]`: Chi-square statistic against uniform distribution (normalized log10).

use serde::{Deserialize, Serialize};

/// Number of extracted features per sample (§33).
pub const NUM_FEATURES: usize = 280;

/// Names of all 280 extracted features for forensic explainability.
pub fn get_feature_names() -> Vec<String> {
    let mut names = Vec::with_capacity(NUM_FEATURES);
    for i in 0..256 {
        names.push(format!("byte_freq_{:02x}", i));
    }
    for i in 0..16 {
        names.push(format!("entropy_chunk_{}", i));
    }
    names.push("bigram_sparsity".to_string());
    names.push("bigram_top10_concentration".to_string());
    names.push("bigram_transition_entropy".to_string());
    names.push("bigram_mean_prob".to_string());
    names.push("bigram_variance".to_string());
    names.push("bigram_distinct_ratio".to_string());
    names.push("longest_ascii_run_ratio".to_string());
    names.push("chi_square_uniformity".to_string());
    names
}

/// Extracted 280-dimensional feature vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedFeatures {
    pub vector: Vec<f32>,
}

/// Calculates Shannon entropy in bits per byte (range: 0.0 to 8.0).
pub fn calculate_shannon_entropy(chunk: &[u8]) -> f32 {
    if chunk.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in chunk {
        counts[b as usize] += 1;
    }

    let len = chunk.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy as f32
}

/// Extracts the 280-dimensional feature vector from raw candidate bytes (§33).
pub fn extract_features(data: &[u8]) -> ExtractedFeatures {
    let mut vector = vec![0.0f32; NUM_FEATURES];
    let n_bytes = data.len();

    if n_bytes == 0 {
        return ExtractedFeatures { vector };
    }

    // 1. Byte Frequency Histogram (256-dim)
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n_float = n_bytes as f64;
    for i in 0..256 {
        vector[i] = (counts[i] as f64 / n_float) as f32;
    }

    // 2. Chunked Shannon Entropy Profile (16-dim)
    let num_chunks = 16;
    let chunk_size = (n_bytes / num_chunks).max(1);
    for i in 0..num_chunks {
        let start = i * chunk_size;
        let end = if i == num_chunks - 1 {
            n_bytes
        } else {
            ((i + 1) * chunk_size).min(n_bytes)
        };

        if start < n_bytes {
            let chunk = &data[start..end];
            vector[256 + i] = calculate_shannon_entropy(chunk);
        } else {
            vector[256 + i] = 0.0;
        }
    }

    // 3. 2-Gram Transition Features (6-dim)
    if n_bytes > 1 {
        let mut bigram_counts = vec![0u32; 65536];
        for pair in data.windows(2) {
            let idx = ((pair[0] as usize) << 8) | (pair[1] as usize);
            bigram_counts[idx] += 1;
        }

        let n_bigrams = (n_bytes - 1) as f64;
        let mut active_counts = Vec::new();
        for &c in &bigram_counts {
            if c > 0 {
                active_counts.push(c);
            }
        }

        let num_distinct = active_counts.len();

        // 272: Sparsity (fraction of 65,536 with 0 count)
        vector[272] = ((65536 - num_distinct) as f64 / 65536.0) as f32;

        // 273: Top-10 Concentration
        active_counts.sort_unstable();
        let top10_sum: u64 = active_counts.iter().rev().take(10).map(|&c| c as u64).sum();
        vector[273] = (top10_sum as f64 / n_bigrams) as f32;

        // 274: Transition Entropy (f64 accumulator)
        let mut trans_entropy = 0.0f64;
        let mut probs = Vec::with_capacity(num_distinct);
        for &c in &active_counts {
            let p = c as f64 / n_bigrams;
            probs.push(p);
            trans_entropy -= p * p.log2();
        }
        vector[274] = trans_entropy as f32;

        // 275: Mean probability over active
        vector[275] = if num_distinct > 0 {
            (1.0 / num_distinct as f64) as f32
        } else {
            0.0
        };

        // 276: Variance of probabilities
        if !probs.is_empty() {
            let mean: f64 = probs.iter().sum::<f64>() / probs.len() as f64;
            let var: f64 = probs.iter().map(|&p| (p - mean) * (p - mean)).sum::<f64>() / probs.len() as f64;
            vector[276] = var as f32;
        }

        // 277: Distinct ratio
        vector[277] = (num_distinct as f64 / 65536.0) as f32;
    } else {
        vector[272] = 1.0;
    }

    // 4. Longest Printable ASCII Run (1-dim)
    let mut max_run = 0usize;
    let mut current_run = 0usize;
    for &b in data {
        if (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 0;
        }
    }

    let log_run = ((max_run as f64) + 1.0).log2();
    let log_total = ((n_bytes as f64) + 1.0).log2();
    vector[278] = if log_total > 0.0 {
        (log_run / log_total) as f32
    } else {
        0.0
    };

    // 5. Chi-Square Uniformity Statistic (1-dim)
    let expected = n_bytes as f64 / 256.0;
    if expected > 0.0 {
        let mut chi2 = 0.0f64;
        for &c in &counts {
            let diff = c as f64 - expected;
            chi2 += (diff * diff) / expected;
        }
        let norm_chi2 = (chi2 + 1.0).log10() / 10.0;
        vector[279] = (norm_chi2.clamp(0.0, 1.0)) as f32;
    } else {
        vector[279] = 0.0;
    }

    ExtractedFeatures { vector }
}

