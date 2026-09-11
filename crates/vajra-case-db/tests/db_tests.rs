//! Integration tests for vajra-case-db (§17, §22).

use vajra_case_db::{CaseDb, CaseStatus, DatabaseKey, DbError, EvidenceItemRecord};

#[test]
fn test_database_initialization_and_migration() {
    let db = CaseDb::open_in_memory().expect("Should initialize in-memory database and run migrations");
    let cases = db.list_cases().expect("Should query cases table");
    assert_eq!(cases.len(), 0);
}

#[test]
fn test_case_lifecycle_and_tombstoning_triggers() {
    let db = CaseDb::open_in_memory().expect("Database init failed");

    // 1. Create active case
    let case = db
        .create_case("CASE-2026-001", "Forensic Investigation Alpha", "INV-4821")
        .expect("Should create active case");
    assert_eq!(case.status, CaseStatus::Active);

    // 2. Fetch case
    let fetched = db.get_case("CASE-2026-001").expect("Should fetch created case");
    assert_eq!(fetched.case_name, "Forensic Investigation Alpha");
    assert_eq!(fetched.status, CaseStatus::Active);

    // 3. Close case (transition Active -> Closed)
    db.close_case("CASE-2026-001").expect("Should close active case");
    let closed = db.get_case("CASE-2026-001").expect("Should fetch closed case");
    assert_eq!(closed.status, CaseStatus::Closed);

    // 4. Attempt to close an already closed case via API -> Rejected
    let err = db.close_case("CASE-2026-001").unwrap_err();
    match err {
        DbError::IllegalStateTransition { from, to, .. } => {
            assert_eq!(from, "Closed");
            assert_eq!(to, "Closed");
        }
        other => panic!("Expected IllegalStateTransition error, got: {:?}", other),
    }

    // 5. Attempt to reopen closed case via raw SQL update -> Rejected by SQL Trigger
    let reopen_res = db.execute_raw("UPDATE cases SET status = 'Active' WHERE case_id = 'CASE-2026-001';");
    assert!(reopen_res.is_err(), "Raw SQL update reopening case must be aborted by trigger");

    // 6. Attempt to delete case via raw SQL -> Rejected by SQL Trigger
    let delete_res = db.execute_raw("DELETE FROM cases WHERE case_id = 'CASE-2026-001';");
    assert!(delete_res.is_err(), "Raw SQL case deletion must be aborted by trigger");

    // 7. Verify case remains intact and in Closed status
    let verified = db.get_case("CASE-2026-001").expect("Case must still exist");
    assert_eq!(verified.status, CaseStatus::Closed);
}

#[test]
fn test_evidence_item_registration_and_query() {
    let db = CaseDb::open_in_memory().expect("Database init failed");
    db.create_case("CASE-TEST", "Test Case", "INV-1").unwrap();

    let item = EvidenceItemRecord {
        evidence_id: "EVID-001".to_string(),
        case_id: "CASE-TEST".to_string(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "0025_38F4_51B3_DC6A".to_string(),
        manufacturer: "Samsung".to_string(),
        model: "MZVL81T0HFLB-00BH1".to_string(),
        capacity_bytes: 1_024_209_543_168,
        interface: "NVMe".to_string(),
        filesystem: Some("NTFS".to_string()),
        device_fingerprint_hash: "c51b430363f618e1965f2f891fc767d5576064169b23b6ff57398d2cc9e33b79".to_string(),
        source_location: Some("Suspect Laptop Bay 0".to_string()),
        physical_condition: Some("Good / Nominal".to_string()),
        write_block_status: Some("Hardware Blocked".to_string()),
        current_custody_owner: Some("Examiner A".to_string()),
        current_location: Some("Vault Locker 4".to_string()),
    };

    db.add_evidence(&item).expect("Should add evidence item");

    let fetched = db.get_evidence("EVID-001").expect("Should retrieve evidence item");
    assert_eq!(fetched.device_serial, "0025_38F4_51B3_DC6A");
    assert_eq!(fetched.capacity_bytes, 1_024_209_543_168);
    assert_eq!(fetched.device_fingerprint_hash, "c51b430363f618e1965f2f891fc767d5576064169b23b6ff57398d2cc9e33b79");

    let list = db.list_evidence_for_case("CASE-TEST").unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn test_argon2id_key_derivation_and_zeroize() {
    let salt = b"vajra_test_salt_1234";
    let key1 = DatabaseKey::from_passphrase("correct_forensic_passphrase", salt)
        .expect("Argon2id derivation should succeed");
    let key2 = DatabaseKey::from_passphrase("correct_forensic_passphrase", salt)
        .expect("Argon2id derivation should succeed");
    let key3 = DatabaseKey::from_passphrase("differing_passphrase", salt)
        .expect("Argon2id derivation should succeed");

    assert_eq!(key1.as_bytes(), key2.as_bytes());
    assert_ne!(key1.as_bytes(), key3.as_bytes());
    assert_eq!(key1.as_bytes().len(), 32);

    // Test short salt error
    let short_salt_err = DatabaseKey::from_passphrase("pass", b"short");
    assert!(short_salt_err.is_err());
}

#[test]
fn test_sqlcipher_encryption_at_rest_and_wrong_key_rejection() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("vajra_test_vault_{}.db", uuid::Uuid::new_v4()));

    let salt = b"salt_for_encryption_test_123";
    let correct_key = DatabaseKey::from_passphrase("correct_investigator_passphrase", salt)
        .expect("Valid Argon2id key");
    let wrong_key = DatabaseKey::from_passphrase("wrong_investigator_passphrase", salt)
        .expect("Valid Argon2id key");

    // 1. Create encrypted database on disk with correct_key
    {
        let db = CaseDb::open_file(&db_path, Some(&correct_key))
            .expect("Should create and open encrypted database");

        // Assert SQLCipher is linked and returns genuine cipher version
        let cipher_ver = db.cipher_version().expect("Query cipher_version failed");
        assert!(cipher_ver.is_some(), "PRAGMA cipher_version must return a version string in SQLCipher build");
        let ver = cipher_ver.unwrap();
        assert!(!ver.is_empty(), "cipher_version must not be empty");
        println!("[+] SQLCipher Active Version: {}", ver);

        // Insert case with verifiable proof string
        db.create_case("CASE-PROOF-01", "PROOF-STRING-VERIFY-ENCRYPTION-XYZ123", "INV-VERIFY")
            .expect("Should insert case into encrypted database");
    }

    // 2. Read raw on-disk bytes directly from file and assert proof string is NOT in raw bytes
    {
        let raw_bytes = std::fs::read(&db_path).expect("Read raw database file");
        let needle = b"PROOF-STRING-VERIFY-ENCRYPTION-XYZ123";
        let found = raw_bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!found, "Raw database file must NOT contain plaintext proof string; it must be ciphertext!");

        // Also check SQLite magic header: SQLite format 3\0 (offset 0..16)
        // In SQLCipher, the first 16 bytes are a random salt, NOT 'SQLite format 3\0'
        assert_ne!(&raw_bytes[0..15], b"SQLite format 3", "SQLCipher database header must be encrypted/salted, not plain SQLite");
    }

    // 3. Attempt to open with WRONG key -> Must fail at SQLCipher level
    {
        let wrong_res = CaseDb::open_file(&db_path, Some(&wrong_key));
        assert!(wrong_res.is_err(), "Opening encrypted database with wrong key must fail");
    }

    // 4. Attempt to open WITHOUT key -> Must fail at SQLCipher level
    {
        let no_key_res = CaseDb::open_file(&db_path, None);
        assert!(no_key_res.is_err(), "Opening encrypted database without key must fail");
    }

    // 5. Open with CORRECT key -> Must succeed and retrieve the case
    {
        let db = CaseDb::open_file(&db_path, Some(&correct_key))
            .expect("Should open with correct key");
        let fetched = db.get_case("CASE-PROOF-01").expect("Should fetch case");
        assert_eq!(fetched.case_name, "PROOF-STRING-VERIFY-ENCRYPTION-XYZ123");
    }

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}
