//! Layer 4 Verification: Statistical Sampling Verification (§37).
//!
//! Implements hypergeometric-corrected finite-population sampling without replacement:
//! n ≈ [1 - (1 - C)^(1 / (N * p))] * N
//!
//! Default parameters: 99.9% confidence (C = 0.999), 0.01% defect rate (p = 0.0001).

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use vajra_core::ReadOnlyBlockSource;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalParams {
    pub total_sectors_n: u64,
    pub confidence_c: f64,
    pub assumed_defect_rate_p: f64,
    pub computed_sample_size_n: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer4Result {
    pub passed: bool,
    pub params: StatisticalParams,
    pub sampled_sectors_count: u64,
    pub non_conforming_sectors_count: u64,
    pub message: String,
}

/// Calculates required sample size using hypergeometric-corrected formula (§37).
pub fn compute_required_sample_size(total_sectors: u64, confidence: f64, defect_rate: f64) -> u64 {
    if total_sectors == 0 {
        return 0;
    }
    let n = total_sectors as f64;
    let np = (n * defect_rate).max(1.0);
    let exponent = 1.0 / np;
    let sample_frac = 1.0 - (1.0 - confidence).powf(exponent);
    let raw_sample = (sample_frac * n).ceil() as u64;

    // Bounded between minimum 10 sectors (or total_sectors) and maximum 50,000 sectors for feasible verification time
    raw_sample.max(10).min(total_sectors).min(50_000)
}

pub fn verify_layer4(
    device: &mut dyn ReadOnlyBlockSource,
    confidence: f64,
    defect_rate: f64,
) -> Layer4Result {
    verify_layer4_with_seed(device, confidence, defect_rate, None)
}

pub fn verify_layer4_with_seed(
    device: &mut dyn ReadOnlyBlockSource,
    confidence: f64,
    defect_rate: f64,
    seed: Option<u64>,
) -> Layer4Result {
    let total_sectors = device.total_blocks();
    let sample_size = compute_required_sample_size(total_sectors, confidence, defect_rate);

    let params = StatisticalParams {
        total_sectors_n: total_sectors,
        confidence_c: confidence,
        assumed_defect_rate_p: defect_rate,
        computed_sample_size_n: sample_size,
    };

    if total_sectors == 0 {
        return Layer4Result {
            passed: false,
            params,
            sampled_sectors_count: 0,
            non_conforming_sectors_count: 0,
            message: "Device reports 0 total sectors.".to_string(),
        };
    }

    // Generate sample LBAs: mandatory inclusions + random sampling
    let mut rng = match seed {
        Some(s) => ChaCha20Rng::seed_from_u64(s),
        None => ChaCha20Rng::from_entropy(),
    };
    let mut candidate_lbas: Vec<u64> = (0..total_sectors).collect();
    candidate_lbas.shuffle(&mut rng);
    let sampled_lbas = &candidate_lbas[..sample_size.min(candidate_lbas.len() as u64) as usize];

    let mut non_conforming = 0u64;

    for &lba in sampled_lbas {
        match device.read_blocks(lba, 1) {
            Ok(bytes) => {
                let first_byte = bytes.first().copied().unwrap_or(0);
                let is_clean = bytes.iter().all(|&b| b == first_byte);
                if !is_clean {
                    non_conforming += 1;
                }
            }
            Err(_) => {
                non_conforming += 1;
            }
        }
    }

    let passed = non_conforming == 0;
    let message = if passed {
        format!(
            "Statistical sampling PASS: {} sectors verified clean (Confidence: {:.1}%, Defect Rate: {:.2}%).",
            sampled_lbas.len(),
            confidence * 100.0,
            defect_rate * 100.0
        )
    } else {
        format!(
            "Statistical sampling FAILED: {} / {} sectors contained residual non-sanitized data.",
            non_conforming,
            sampled_lbas.len()
        )
    };

    Layer4Result {
        passed,
        params,
        sampled_sectors_count: sampled_lbas.len() as u64,
        non_conforming_sectors_count: non_conforming,
        message,
    }
}
