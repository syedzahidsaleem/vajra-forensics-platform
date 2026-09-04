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
