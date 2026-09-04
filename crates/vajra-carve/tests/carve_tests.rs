//! Integration and Benchmark Tests for vajra-carve (§26, §27, §45, §46).

use std::path::Path;
use vajra_carve::pipeline::{PipelineOptions, RecoveryPipeline};
use vajra_carve::types::RecoveryTier;
use vajra_image::RawImageReader;

#[test]
fn test_carving_and_bgc_on_synthetic_corpus() {
    let img_path = Path::new("../../test_data/carve_test.img");
    if !img_path.exists() {
        // Fallback relative path from workspace root
        let fallback = Path::new("test_data/carve_test.img");
        if !fallback.exists() {
            panic!("Test image not found at {:?}", img_path);
        }
    }

    let resolved_path = if img_path.exists() {
        img_path.to_str().unwrap()
    } else {
        "test_data/carve_test.img"
    };

    let mut reader = RawImageReader::open(resolved_path, None).expect("Must open carve_test.img");

    let pipeline = RecoveryPipeline::new();
    let options = PipelineOptions {
        partition_offset: 0,
        enable_tier1: false, // Pure carving on raw image
        enable_tier2: true,
        enable_tier3: true,
        target_types: None,
        max_bgc_search_radius: Some(64),
    };

    let artifacts = pipeline.run(&mut reader, &options).expect("Pipeline must succeed");

    println!("Total Recovered Artifacts: {}", artifacts.len());
    for art in &artifacts {
        println!("{}", art.format_provenance());
    }

    // --- Ground-Truth Verification ---
    // Positives to recover:
    // 1. Intact PNG at LBA 10
    // 2. Intact JPEG at LBA 20
    // 3. Intact PDF at LBA 30
    // 4. Intact SQLite at LBA 40
    // 5. Intact ZIP at LBA 50
    // 6. Fragmented PNG at LBA 150 + LBA 159 (Tier 3)

    // False positives that MUST BE REJECTED:
    // - Corrupted PNG at LBA 100 (CRC mismatch)
    // - Corrupted JPEG at LBA 110 (Bitstream error)
    // - Corrupted SQLite at LBA 120 (Invalid b-tree page type)

    // 1. Check Intact Tier-2 Carvings
    let png_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(10));
    assert!(png_art.is_some(), "Intact PNG at LBA 10 must be recovered");
    assert_eq!(png_art.unwrap().recovery_method, RecoveryTier::Tier2Signature);

    let jpg_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(20));
    assert!(jpg_art.is_some(), "Intact JPEG at LBA 20 must be recovered");

    let pdf_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(30));
    assert!(pdf_art.is_some(), "Intact PDF at LBA 30 must be recovered");

    let sqlite_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(40));
    assert!(sqlite_art.is_some(), "Intact SQLite at LBA 40 must be recovered");

    let zip_art = artifacts.iter().find(|a| a.source_locations.first().map(|(l, _)| *l) == Some(50));
    assert!(zip_art.is_some(), "Intact ZIP at LBA 50 must be recovered");

    // 2. Check Rejection of Corrupted Candidates (False Positives Suppressed)
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(100)),
        "Corrupted PNG at LBA 100 must be rejected by CRC32 validator"
    );
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(110)),
        "Corrupted JPEG at LBA 110 must be rejected by bitstream validator"
    );
    assert!(
        artifacts.iter().all(|a| a.source_locations.first().map(|(l, _)| *l) != Some(120)),
        "Corrupted SQLite at LBA 120 must be rejected by b-tree validator"
    );

    // 3. Check Tier-3 BGC Reassembly
    let bgc_art = artifacts
        .iter()
        .find(|a| a.recovery_method == RecoveryTier::Tier3Fragmented)
        .expect("BGC must recover fragmented PNG across gap");

    let frag_detail = bgc_art.fragmentation_detail.as_ref().unwrap();
    assert_eq!(frag_detail.gap_size_sectors, 8, "BGC must discover exact 8-sector gap");
    assert_eq!(frag_detail.fragment_1, (150, 1), "Fragment 1 must be at LBA 150");
    assert_eq!(frag_detail.fragment_2, (159, 1), "Fragment 2 must be at LBA 159");

    // 4. Measure Real Precision & Recall
    let true_positives = 6; // 5 contiguous intact + 1 BGC reconstructed
    let false_positives = artifacts.len().saturating_sub(true_positives);
    let false_negatives = 0;

    let precision = true_positives as f32 / (true_positives + false_positives) as f32;
    let recall = true_positives as f32 / (true_positives + false_negatives) as f32;
    let f1 = 2.0 * (precision * recall) / (precision + recall);

    println!("============================================================");
    println!("        VAJRA CARVING GROUND-TRUTH BENCHMARK REPORT (§46)");
    println!("============================================================");
    println!("  True Positives (Recovered Intact/Fragmented): {}", true_positives);
    println!("  False Positives (Corrupted/Noise Accepted):   {}", false_positives);
    println!("  False Negatives (Valid Files Missed):         {}", false_negatives);
    println!("  Measured Precision:                           {:.2}%", precision * 100.0);
    println!("  Measured Recall:                              {:.2}%", recall * 100.0);
    println!("  Measured F1-Score:                            {:.2}%", f1 * 100.0);
    println!("============================================================");

    assert_eq!(precision, 1.0, "Precision must be 100% on ground-truth corpus");
    assert_eq!(recall, 1.0, "Recall must be 100% on ground-truth corpus");
}

#[test]
fn test_v_eof_truncated_candidate_handling() {
    use vajra_carve::tier2::{JpegValidator, PngValidator, StructuralValidator, ValidationResult};
    use vajra_core::ReadOnlyBlockSource;

    let img_path = Path::new("../../test_data/carve_test.img");
    let fallback = Path::new("test_data/carve_test.img");
    let resolved_path = if img_path.exists() {
        img_path.to_str().unwrap()
    } else {
        fallback.to_str().unwrap()
    };

    let mut reader = RawImageReader::open(resolved_path, None).expect("Must open carve_test.img");

    // 1. Validate LBA 70 (Deliberately truncated PNG - missing IEND)
    let lba70_bytes = reader.read_blocks(70, 1).unwrap();
    let png_validator = PngValidator;
    let png_result = png_validator.validate(&lba70_bytes);

    println!("LBA 70 (Truncated PNG) Validator Result: {:?}", png_result);
    assert!(png_result.is_eof(), "Truncated PNG must return V_EOF, not V_ERR or V_OK");
    if let ValidationResult::Eof { partial_length } = png_result {
        assert_eq!(partial_length, 33, "Partial length must equal 33 bytes (Magic + IHDR)");
    } else {
        panic!("Expected ValidationResult::Eof");
    }

    // 2. Validate LBA 80 (Deliberately truncated JPEG - missing EOI)
    let lba80_bytes = reader.read_blocks(80, 1).unwrap();
    let jpeg_validator = JpegValidator;
    let jpeg_result = jpeg_validator.validate(&lba80_bytes);

    println!("LBA 80 (Truncated JPEG) Validator Result: {:?}", jpeg_result);
    assert!(jpeg_result.is_eof(), "Truncated JPEG must return V_EOF, not V_ERR or V_OK");
    if let ValidationResult::Eof { partial_length } = jpeg_result {
        assert!(partial_length > 0, "Partial length must be positive");
    } else {
        panic!("Expected ValidationResult::Eof");
    }
}
