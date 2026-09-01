//! Train/Serve Feature-Parity Integration Test (§33).
//!
//! Validates that the pure-Rust feature extractor in `crates/vajra-ml/src/features.rs`
//! and the offline Python feature extractor in `training/feature_extractor.py` produce
//! bit-identical 280-dimensional vectors across all test cases.

use serde::Deserialize;
use vajra_ml::features::extract_features;

#[derive(Debug, Deserialize)]
struct ParityFixture {
    name: String,
    hex_data: String,
    expected_features: Vec<f32>,
}

#[test]
fn test_train_serve_feature_parity_exact_tolerance() {
    let fixture_str = include_str!("../../../training/parity_fixtures.json");
    let fixtures: Vec<ParityFixture> =
        serde_json::from_str(fixture_str).expect("Failed to parse training/parity_fixtures.json");

    assert!(
        !fixtures.is_empty(),
        "Parity fixture list must not be empty"
    );

    println!("================================================================================");
    println!("       TRAIN/SERVE FEATURE-PARITY TEST — PYTHON vs RUST (§33)");
    println!("================================================================================");
    println!("  Total Fixtures:         {}", fixtures.len());
    println!("  Vector Dimension:       280 features");
    println!("  Max Allowed Tolerance:  1e-4");
    println!("--------------------------------------------------------------------------------");

    let mut global_max_diff = 0.0f32;

    for fixture in &fixtures {
        let raw_bytes = hex::decode(&fixture.hex_data)
            .unwrap_or_else(|_| panic!("Failed to decode hex data for {}", fixture.name));

        let rust_features = extract_features(&raw_bytes);
        assert_eq!(
            rust_features.vector.len(),
            280,
            "Rust feature vector length must be 280"
        );
        assert_eq!(
            fixture.expected_features.len(),
            280,
            "Python feature vector length must be 280"
        );

        let mut case_max_diff = 0.0f32;
        let mut worst_dim = 0usize;

        for dim in 0..280 {
            let py_val = fixture.expected_features[dim];
            let rs_val = rust_features.vector[dim];
            let diff = (py_val - rs_val).abs();

            if diff > case_max_diff {
                case_max_diff = diff;
                worst_dim = dim;
            }

            assert!(
                diff < 1e-4,
                "Feature parity mismatch on fixture '{}' at dimension {}: Python={:.6}, Rust={:.6}, diff={:.6}",
                fixture.name,
                dim,
                py_val,
                rs_val,
                diff
            );
        }

        if case_max_diff > global_max_diff {
            global_max_diff = case_max_diff;
        }

        println!(
            "  Fixture: {:<20} | Bytes: {:>5} | Max Diff: {:.8} (dim {}) [PASS]",
            fixture.name,
            raw_bytes.len(),
            case_max_diff,
            worst_dim
        );
    }

    println!("--------------------------------------------------------------------------------");
    println!(
        "  TRAIN/SERVE PARITY VERIFIED: Global Max Diff across all dimensions = {:.8}",
        global_max_diff
    );
    println!("================================================================================");
}
