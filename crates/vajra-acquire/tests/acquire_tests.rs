//! Comprehensive integration tests for vajra-acquire (§19, §20).

use std::path::PathBuf;
use tempfile::tempdir;
use vajra_acquire::{
    mock::SimulatedFaultyBlockSource,
    profile::AcquisitionProfile,
    AcquisitionConfig, AcquisitionEngine, AcquisitionError, BadSectorMap,
    DEFAULT_BAD_SECTOR_MARKER,
};
use vajra_audit::AuditChain;
use vajra_case_db::{CaseDb, DatabaseKey};
use vajra_core::ReadOnlyBlockSource;
use vajra_custody::CustodyTracker;
use vajra_image::{ForensicImageWriter, RawImageReader, RawImageWriter};

fn create_test_db(dir: &tempfile::TempDir) -> (CaseDb, PathBuf) {
    let db_path = dir.path().join("case_vault.db");
    let key = DatabaseKey::from_raw([0x42; 32]);
    let db = CaseDb::open_file(&db_path, Some(&key)).unwrap();
    (db, db_path)
}

#[test]
fn test_clean_physical_acquisition_roundtrip_with_hashes() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("clean_disk.raw");

    let block_size = 512u32;
    let num_blocks = 64u64;
    let mut raw_bytes = vec![0u8; (num_blocks * block_size as u64) as usize];
    for (i, b) in raw_bytes.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);
    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let (db, _) = create_test_db(&tmp);

    // Register case and evidence in vault
    db.create_case("CASE-001", "Acquire Clean Test", "Examiner A").unwrap();
    db.add_evidence(&vajra_case_db::EvidenceItemRecord {
        evidence_id: "EVID-001".to_string(),
        case_id: "CASE-001".to_string(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "MOCK-SIM-9999".to_string(),
        manufacturer: "Vajra Simulation Lab".to_string(),
        model: "Faulty Mock Disk 1000".to_string(),
        capacity_bytes: raw_bytes.len() as u64,
        interface: "Virtual RAM Bus".to_string(),
        filesystem: None,
        device_fingerprint_hash: source.device_fingerprint().sha256_hash.clone(),
        source_location: None,
        physical_condition: Some("Good".to_string()),
        write_block_status: Some("HardwareEnforced".to_string()),
        current_custody_owner: Some("Examiner A".to_string()),
        current_location: Some("Lab Room 1".to_string()),
    }).unwrap();

    let config = AcquisitionConfig::new(
        "CASE-001",
        "EVID-001",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Physical,
    );

    let result = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        Some(&db),
    )
    .expect("Clean physical acquisition failed");

    assert_eq!(result.total_blocks_acquired, num_blocks);
    assert_eq!(result.total_bytes_written, raw_bytes.len() as u64);
    assert_eq!(result.acquisition_hash, result.verification_hash);
    assert_eq!(result.bad_sector_map.total_unreadable_blocks, 0);

    // Read back through RawImageReader and assert exact byte equality
    let mut reader = RawImageReader::open(&img_out, Some(block_size)).unwrap();
    let img_bytes = reader.read_blocks(0, num_blocks as u32).unwrap();
    assert_eq!(img_bytes, raw_bytes);

    // Verify Evidence Vault entries
    let op = db.get_operation(&result.op_id).unwrap();
    assert_eq!(op.status, "Completed");
    let images = db.list_forensic_images_for_evidence("EVID-001").unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].acquisition_hash, result.acquisition_hash);
    assert_eq!(images[0].verification_hash, Some(result.verification_hash));

    // Verify audit chain integrity
    let report = AuditChain::verify_db(&db).unwrap();
    assert!(report.is_valid);
    assert!(report.total_entries >= 2);

    // Verify custody history
    let custody_events = CustodyTracker::get_history(&db, "EVID-001").unwrap();
    assert!(!custody_events.is_empty());
}

#[test]
fn test_partial_lba_range_acquisition() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("partial.raw");

    let block_size = 512u32;
    let num_blocks = 100u64;
    let mut raw_bytes = vec![0u8; (num_blocks * block_size as u64) as usize];
    for (i, b) in raw_bytes.iter_mut().enumerate() {
        *b = ((i * 31) % 256) as u8;
    }

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);
    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let config = AcquisitionConfig::new(
        "CASE-002",
        "EVID-002",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Partial { start_lba: 10, end_lba: 25 },
    );

    let result = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        None,
    )
    .expect("Partial acquisition failed");

    assert_eq!(result.total_blocks_acquired, 16);
    assert_eq!(result.total_bytes_written, 16 * 512);

    let mut reader = RawImageReader::open(&img_out, Some(block_size)).unwrap();
    let read_back = reader.read_blocks(0, 16).unwrap();
    let expected_slice = &raw_bytes[10 * 512..26 * 512];
    assert_eq!(read_back, expected_slice);
}

#[test]
fn test_bad_sector_flowchart_and_authoritative_map_guarantee() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("damaged_media.raw");

    let block_size = 512u32;
    let num_blocks = 32u64;
    let mut raw_bytes = vec![0x11u8; (num_blocks * block_size as u64) as usize];

    // Intentionally populate healthy LBA 2 with the exact DEFAULT_BAD_SECTOR_MARKER bytes
    // to test and prove the BadSectorMap single-source-of-truth guarantee!
    for i in 0..512 {
        raw_bytes[2 * 512 + i] = DEFAULT_BAD_SECTOR_MARKER[i % DEFAULT_BAD_SECTOR_MARKER.len()];
    }

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);

    // Inject permanent bad sector at LBA 7 and LBA 8
    source.inject_permanent_bad_sector(7, 8, "Uncorrectable Sector Error (UNC) at sector 7-8");

    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let mut config = AcquisitionConfig::new(
        "CASE-003",
        "EVID-003",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Physical,
    );
    config.strategy.max_retries = 2;
    config.strategy.retry_backoff_ms = 1;

    let result = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        None,
    )
    .expect("Acquisition with bad sectors must complete gracefully");

    // 1. Assert BadSectorMap recorded exactly LBAs 7 and 8
    assert_eq!(result.bad_sector_map.total_unreadable_blocks, 2);
    assert_eq!(result.bad_sector_map.total_unreadable_bytes, 1024);
    assert!(result.bad_sector_map.is_lba_bad(7));
    assert!(result.bad_sector_map.is_lba_bad(8));
    assert!(!result.bad_sector_map.is_lba_bad(2), "Healthy LBA 2 must NOT be marked bad in map");
    assert!(!result.bad_sector_map.is_lba_bad(6));
    assert!(!result.bad_sector_map.is_lba_bad(9));

    // 2. Read back from generated image
    let mut reader = RawImageReader::open(&img_out, Some(block_size)).unwrap();

    // Verify healthy LBA 2 content
    let lba_2_bytes = reader.read_blocks(2, 1).unwrap();
    // Verify substituted LBA 7 content
    let lba_7_bytes = reader.read_blocks(7, 1).unwrap();

    // Both LBA 2 and LBA 7 contain DEFAULT_BAD_SECTOR_MARKER bytes in raw hex:
    assert_eq!(&lba_2_bytes[..16], DEFAULT_BAD_SECTOR_MARKER);
    assert_eq!(&lba_7_bytes[..16], DEFAULT_BAD_SECTOR_MARKER);

    // PROOF: A naive byte-check alone CANNOT distinguish between LBA 2 (legitimate content)
    // and LBA 7 (substituted bad sector), whereas BadSectorMap is 100% authoritative and correct!
    assert!(!result.bad_sector_map.is_lba_bad(2));
    assert!(result.bad_sector_map.is_lba_bad(7));

    // 3. Verify healthy LBA 0 retained original 0x11 bytes
    let lba_0_bytes = reader.read_blocks(0, 1).unwrap();
    assert_eq!(lba_0_bytes, vec![0x11; 512]);
}

#[test]
fn test_transient_failure_recovery_with_backoff() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("transient_recovered.raw");

    let block_size = 512u32;
    let num_blocks = 16u64;
    let raw_bytes = vec![0x33u8; (num_blocks * block_size as u64) as usize];

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);

    // LBA 5 fails 2 times, then succeeds on retry 3
    source.inject_transient_failure(5, 5, 2);

    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let mut config = AcquisitionConfig::new(
        "CASE-004",
        "EVID-004",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Physical,
    );
    config.strategy.max_retries = 3;
    config.strategy.retry_backoff_ms = 1;

    let result = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        None,
    )
    .expect("Transient recovery must succeed");

    // Must have 0 bad sectors recorded because retry succeeded
    assert_eq!(result.bad_sector_map.total_unreadable_blocks, 0);

    // LBA 5 read count must be at least 3 attempts
    assert!(source.read_attempts_for_lba(5) >= 3);
}

#[test]
fn test_block_size_reduction_to_single_sector() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("reduced_blocks.raw");

    let block_size = 512u32;
    let num_blocks = 32u64;
    let raw_bytes = vec![0x44u8; (num_blocks * block_size as u64) as usize];

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);

    // LBA 8..15 fails when reading > 1 block at a time (e.g. chunk reads of 8 fail, but 1-sector reads succeed)
    source.inject_fail_above_block_size(8, 15, 1);

    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let mut config = AcquisitionConfig::new(
        "CASE-005",
        "EVID-005",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Physical,
    );
    config.strategy.initial_chunk_sectors = 8; // Attempt 8 sectors at once
    config.strategy.min_chunk_sectors = 1;
    config.strategy.max_retries = 1;
    config.strategy.retry_backoff_ms = 1;

    let result = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        None,
    )
    .expect("Block reduction acquisition must succeed");

    // Because single-sector reads succeeded, zero sectors should be marked unreadable
    assert_eq!(result.bad_sector_map.total_unreadable_blocks, 0);
    assert_eq!(result.total_blocks_acquired, 32);

    let mut reader = RawImageReader::open(&img_out, Some(block_size)).unwrap();
    let img_bytes = reader.read_blocks(0, 32).unwrap();
    assert_eq!(img_bytes, raw_bytes);
}

#[test]
fn test_preflight_insufficient_storage_space_rejection() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("should_never_be_created.raw");

    let block_size = 512u32;
    let num_blocks = 128u64; // Requires 65,536 bytes
    let raw_bytes = vec![0x55u8; (num_blocks * block_size as u64) as usize];

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes, block_size);
    let mut writer = RawImageWriter::create(&img_out, block_size).unwrap();

    let mut config = AcquisitionConfig::new(
        "CASE-006",
        "EVID-006",
        "Examiner A",
        img_out.clone(),
        AcquisitionProfile::Physical,
    );
    // Simulate only 1,024 bytes available
    config.simulated_available_space = Some(1024);

    let err = AcquisitionEngine::acquire(
        &mut source,
        &mut writer,
        &config,
        None,
        None,
        None,
    )
    .expect_err("Must reject acquisition due to insufficient storage space");

    match err {
        AcquisitionError::InsufficientStorageSpace {
            required_bytes,
            available_bytes,
        } => {
            assert_eq!(required_bytes, 65536);
            assert_eq!(available_bytes, 1024);
        }
        other => panic!("Expected InsufficientStorageSpace, got {:?}", other),
    }
}

#[test]
fn test_interrupted_acquisition_and_resumption_from_checkpoint() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("resumable_disk.raw");

    let block_size = 512u32;
    let num_blocks = 100u64;
    let mut raw_bytes = vec![0u8; (num_blocks * block_size as u64) as usize];
    for (i, b) in raw_bytes.iter_mut().enumerate() {
        *b = (i % 255) as u8;
    }

    let mut source = SimulatedFaultyBlockSource::new(raw_bytes.clone(), block_size);
    let (db, _) = create_test_db(&tmp);

    db.create_case("CASE-007", "Resumption Test", "Examiner A").unwrap();
    db.add_evidence(&vajra_case_db::EvidenceItemRecord {
        evidence_id: "EVID-007".to_string(),
        case_id: "CASE-007".to_string(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "MOCK-SIM-9999".to_string(),
        manufacturer: "Vajra Simulation Lab".to_string(),
        model: "Faulty Mock Disk 1000".to_string(),
        capacity_bytes: raw_bytes.len() as u64,
        interface: "Virtual RAM Bus".to_string(),
        filesystem: None,
        device_fingerprint_hash: source.device_fingerprint().sha256_hash.clone(),
        source_location: None,
        physical_condition: Some("Good".to_string()),
        write_block_status: Some("HardwareEnforced".to_string()),
        current_custody_owner: Some("Examiner A".to_string()),
        current_location: Some("Lab".to_string()),
    }).unwrap();

    let op_id = "OP-INTERRUPT-101";

    // 1. Manually construct an interrupted checkpoint at LBA 50 in the database
    let mut partial_writer = RawImageWriter::create(&img_out, block_size).unwrap();
    partial_writer.write_image_blocks(0, &raw_bytes[..50 * 512]).unwrap();
    partial_writer.finalize().unwrap();

    let checkpoint = vajra_acquire::AcquisitionCheckpoint {
        op_id: op_id.to_string(),
        case_id: "CASE-007".to_string(),
        evidence_id: "EVID-007".to_string(),
        source_fingerprint: source.device_fingerprint().sha256_hash.clone(),
        output_path: img_out.display().to_string(),
        profile: AcquisitionProfile::Physical,
        start_lba: 0,
        current_lba: 50,
        end_lba: 99,
        total_blocks: 100,
        bytes_written: 50 * 512,
        bad_sector_map: BadSectorMap::new(),
        started_at: chrono::Utc::now().to_rfc3339(),
        last_updated_at: chrono::Utc::now().to_rfc3339(),
    };

    db.record_operation(&vajra_case_db::OperationRecord {
        op_id: op_id.to_string(),
        case_id: "CASE-007".to_string(),
        evidence_id: Some("EVID-007".to_string()),
        op_type: "Acquire".to_string(),
        parameters_json: Some(checkpoint.to_json()),
        tool_version: "0.1.0".to_string(),
        build_id: "test".to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: None,
        status: "InProgress".to_string(),
    }).unwrap();

    // 2. Resume acquisition from checkpoint
    let res = AcquisitionEngine::resume(
        &mut source,
        op_id,
        &db,
        None,
        None,
    )
    .expect("Resume acquisition failed");

    assert_eq!(res.total_bytes_written, 100 * 512);

    // 3. Verify complete reconstructed image matches raw source bytes exactly
    let mut reader = RawImageReader::open(&img_out, Some(block_size)).unwrap();
    let img_bytes = reader.read_blocks(0, 100).unwrap();
    assert_eq!(img_bytes, raw_bytes);
}

#[test]
fn test_resume_device_mismatch_rejected() {
    let tmp = tempdir().unwrap();
    let img_out = tmp.path().join("mismatch.raw");

    let block_size = 512u32;
    let mut source_wrong = SimulatedFaultyBlockSource::new(vec![0x77; 512 * 10], block_size);
    let (db, _) = create_test_db(&tmp);

    let op_id = "OP-MISMATCH-999";
    let checkpoint = vajra_acquire::AcquisitionCheckpoint {
        op_id: op_id.to_string(),
        case_id: "CASE-008".to_string(),
        evidence_id: "EVID-008".to_string(),
        source_fingerprint: "EXPECTED_CORRECT_HASH_1234567890".to_string(),
        output_path: img_out.display().to_string(),
        profile: AcquisitionProfile::Physical,
        start_lba: 0,
        current_lba: 5,
        end_lba: 9,
        total_blocks: 10,
        bytes_written: 5 * 512,
        bad_sector_map: BadSectorMap::new(),
        started_at: chrono::Utc::now().to_rfc3339(),
        last_updated_at: chrono::Utc::now().to_rfc3339(),
    };

    db.create_case("CASE-008", "Mismatch Test", "Examiner A").unwrap();
    db.add_evidence(&vajra_case_db::EvidenceItemRecord {
        evidence_id: "EVID-008".to_string(),
        case_id: "CASE-008".to_string(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "MOCK-SIM-8888".to_string(),
        manufacturer: "Vajra".to_string(),
        model: "Mock".to_string(),
        capacity_bytes: 5120,
        interface: "RAM".to_string(),
        filesystem: None,
        device_fingerprint_hash: "EXPECTED_CORRECT_HASH_1234567890".to_string(),
        source_location: None,
        physical_condition: None,
        write_block_status: None,
        current_custody_owner: None,
        current_location: None,
    }).unwrap();

    db.record_operation(&vajra_case_db::OperationRecord {
        op_id: op_id.to_string(),
        case_id: "CASE-008".to_string(),
        evidence_id: Some("EVID-008".to_string()),
        op_type: "Acquire".to_string(),
        parameters_json: Some(checkpoint.to_json()),
        tool_version: "0.1.0".to_string(),
        build_id: "test".to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: None,
        status: "InProgress".to_string(),
    }).unwrap();

    let err = AcquisitionEngine::resume(
        &mut source_wrong,
        op_id,
        &db,
        None,
        None,
    )
    .expect_err("Must reject resume when device fingerprint mismatches");

    match err {
        AcquisitionError::DeviceMismatchOnResume {
            expected_fingerprint,
            actual_fingerprint,
        } => {
            assert_eq!(expected_fingerprint, "EXPECTED_CORRECT_HASH_1234567890");
            assert_ne!(actual_fingerprint, expected_fingerprint);
        }
        other => panic!("Expected DeviceMismatchOnResume, got {:?}", other),
    }
}
