//! Integration Tests for Selective File Erasure & Residual Scanner (§36).

use std::io::Write;
use tempfile::NamedTempFile;
use vajra_core::media_type::MediaType;
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_erase::mock::MockWritableDevice;
use vajra_file_erase::file_eraser::{erase_data_extents_destructive, execute_file_erasure_pipeline_destructive};
use vajra_file_erase::local_eraser::erase_local_file_destructive;
use vajra_file_erase::scanner::{ResidualArtifactScanner, ResidualScanResult};

#[test]
fn test_free_after_overwrite_ordering_and_crash_safety() {
    let mut mock_dev = MockWritableDevice::new(100, 512, MediaType::Hdd);

    // Pre-populate sensitive data at LBA 20..22 (2 blocks)
    let sensitive_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    mock_dev.populate_data(20, &sensitive_payload);

    let extents = [(20u64, 2u64)];

    // Simulate crash after Step 2 (Data extent overwrite)
    let bytes_overwritten = erase_data_extents_destructive(&mut mock_dev, &extents, 1).unwrap();
    assert_eq!(bytes_overwritten, 1024);

    // Verify data at LBA 20 is already completely overwritten with 0x00
    let read_back = mock_dev.read_blocks(20, 2).unwrap();
    assert!(
        read_back.iter().all(|&b| b == 0x00),
        "CRASH SAFETY (§36): In the event of a crash before allocation bitmap update, data is already cleanly overwritten!"
    );

    // Now execute full pipeline
    let report = execute_file_erasure_pipeline_destructive(
        &mut mock_dev,
        "FILE_001",
        Some("/var/secrets/passwords.txt"),
        &extents,
        Some(10), // Metadata at LBA 10
        1,
    )
    .expect("Pipeline must succeed");

    assert!(report.metadata_zeroed);
    assert!(report.free_after_overwrite_verified);
    assert_eq!(report.residual_scan, ResidualScanResult::Sanitized);
}

#[test]
fn test_residual_artifact_scanner_five_states() {
    // 1. Sanitized
    let r1 = ResidualArtifactScanner::scan(true, true, true, Vec::new(), None);
    assert_eq!(r1, ResidualScanResult::Sanitized);

    // 2. ResidualTracesDetected
    let r2 = ResidualArtifactScanner::scan(
        true,
        true,
        false,
        vec!["$LogFile entry 1042".to_string()],
        None,
    );
    assert!(matches!(r2, ResidualScanResult::ResidualTracesDetected(_)));

    // 3. UnableToVerify
    let r3 = ResidualArtifactScanner::scan(
        true,
        true,
        true,
        Vec::new(),
        Some("VSS Shadow Copy locked by kernel".to_string()),
    );
    assert!(matches!(r3, ResidualScanResult::UnableToVerify(_)));

    // 4. PartiallySanitized
    let r4 = ResidualArtifactScanner::scan(true, false, false, Vec::new(), None);
    assert!(matches!(r4, ResidualScanResult::PartiallySanitized(_)));
}

#[test]
fn test_local_file_secure_erasure() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let file_path = temp_file.path().to_path_buf();

    // Write sensitive payload
    temp_file.write_all(b"CONFIDENTIAL FORENSIC TARGET DATA").unwrap();
    temp_file.flush().unwrap();

    let initial_size = std::fs::metadata(&file_path).unwrap().len();
    assert!(initial_size > 0);

    // Execute multi-pass secure erase
    let erased_bytes = erase_local_file_destructive(&file_path, 3).expect("Local erase must succeed");
    assert_eq!(erased_bytes, initial_size);

    // Verify file is unlinked from disk
    assert!(!file_path.exists(), "File must no longer exist on filesystem");
}
