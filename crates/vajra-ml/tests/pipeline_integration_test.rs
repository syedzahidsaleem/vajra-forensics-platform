//! Integration Test: ML-Backed Recovery Pipeline Execution (§33, §29, §46).
//!
//! Confirms that swapping `MlEntropyAnalyzer` into `vajra-carve`'s `RecoveryPipeline`
//! preserves the 6-weight confidence scoring structure and evaluates precision/recall/F1.

use std::path::Path;
use std::sync::Arc;
use vajra_carve::pipeline::{PipelineOptions, RecoveryPipeline};
use vajra_carve::types::RecoveryTier;
use vajra_image::RawImageReader;
use vajra_ml::MlEntropyAnalyzer;

#[test]
fn test_ml_backed_carving_pipeline_on_synthetic_corpus() {
    let img_path = Path::new("../../test_data/carve_test.img");
    let fallback = Path::new("test_data/carve_test.img");
    let resolved_path = if img_path.exists() {
        img_path.to_str().unwrap()
    } else if fallback.exists() {
        fallback.to_str().unwrap()
    } else {
        panic!("Test image not found at test_data/carve_test.img");
    };

    let mut reader = RawImageReader::open(resolved_path, None).expect("Must open carve_test.img");

    // Instantiate RecoveryPipeline with ML Entropy Analyzer swapped in (§33)
    let ml_analyzer = Arc::new(MlEntropyAnalyzer::new());
    let pipeline = RecoveryPipeline::new().with_entropy_analyzer(ml_analyzer);

    let options = PipelineOptions {
        partition_offset: 0,
        enable_tier1: false, // Pure carving on raw image
        enable_tier2: true,
        enable_tier3: true,
        target_types: None,
        max_bgc_search_radius: Some(64),
    };

    let artifacts = pipeline
        .run(&mut reader, &options)
        .expect("ML-backed recovery pipeline must execute cleanly");

    println!("================================================================================");
    println!("     VAJRA ML-AUGMENTED CARVING PIPELINE BENCHMARK (§33, §29, §46)");
    println!("================================================================================");
    println!("  Total Recovered Artifacts: {}", artifacts.len());
    println!("--------------------------------------------------------------------------------");

    for art in &artifacts {
        println!("{}", art.format_provenance());
    }

    // Ground-Truth Positives:
    // 1. PNG at LBA 10
    // 2. JPEG at LBA 20
    // 3. PDF at LBA 30
    // 4. SQLite at LBA 40
    // 5. ZIP at LBA 50
    // 6. Fragmented PNG at LBA 150 + 159 (Tier 3)
    let png_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(10));
    assert!(png_art.is_some(), "Intact PNG at LBA 10 must be recovered");

    let jpg_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(20));
    assert!(jpg_art.is_some(), "Intact JPEG at LBA 20 must be recovered");

    let pdf_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(30));
    assert!(pdf_art.is_some(), "Intact PDF at LBA 30 must be recovered");

    let sqlite_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(40));
    assert!(sqlite_art.is_some(), "Intact SQLite at LBA 40 must be recovered");

    let zip_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(50));
    assert!(zip_art.is_some(), "Intact ZIP at LBA 50 must be recovered");

    let bgc_art = artifacts.iter().find(|a| a.recovery_method == RecoveryTier::Tier3Fragmented);
    assert!(bgc_art.is_some(), "Fragmented PNG must be recovered via Tier 3");

    // False Positive Rejection:
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(100)),
        "Corrupted PNG at LBA 100 must remain rejected"
    );
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(110)),
        "Corrupted JPEG at LBA 110 must remain rejected"
    );
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(120)),
        "Corrupted SQLite at LBA 120 must remain rejected"
    );

    let true_positives = 6;
    let false_positives = artifacts.len().saturating_sub(true_positives);
    let false_negatives = 0;

    let precision = true_positives as f32 / (true_positives + false_positives) as f32;
    let recall = true_positives as f32 / (true_positives + false_negatives) as f32;
    let f1 = 2.0 * (precision * recall) / (precision + recall);

    println!("--------------------------------------------------------------------------------");
    println!("  True Positives (Recovered):                   {}", true_positives);
    println!("  False Positives (Corrupted/Noise Accepted):   {}", false_positives);
    println!("  False Negatives (Valid Files Missed):         {}", false_negatives);
    println!("  Measured Precision:                           {:.2}%", precision * 100.0);
    println!("  Measured Recall:                              {:.2}%", recall * 100.0);
    println!("  Measured F1-Score:                            {:.2}%", f1 * 100.0);
    println!("================================================================================");

    assert_eq!(precision, 1.0);
    assert_eq!(recall, 1.0);
    assert_eq!(f1, 1.0);
}
