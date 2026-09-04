//! Integration tests for vajra-audit (§39, §40).

use std::fs;
use tempfile::tempdir;
use vajra_audit::{
    export_anchor, verify_anchor, verify_signature, AuditChain, AuditEntry, AuditError,
    OperatorKeyPair, GENESIS_PREV_HASH,
};
use vajra_case_db::CaseDb;

#[test]
fn test_genesis_block_and_hash_chaining() {
    let db = CaseDb::open_in_memory().unwrap();

    let e1 = AuditChain::append(
        &db,
        "CASE-001",
        "INV-1",
        "CaseCreated",
        "Case Initialized",
        "SUCCESS",
    )
    .unwrap();

    assert_eq!(e1.seq, 1);
    assert_eq!(e1.prev_hash, GENESIS_PREV_HASH);
    assert!(e1.verify_integrity());

    let e2 = AuditChain::append(
        &db,
        "CASE-001",
        "INV-1",
        "DeviceEnumeration",
        "NVMe PhysicalDrive0",
        "SUCCESS",
    )
    .unwrap();

    assert_eq!(e2.seq, 2);
    assert_eq!(e2.prev_hash, e1.entry_hash);
    assert!(e2.verify_integrity());

    let report = AuditChain::verify_db(&db).unwrap();
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.latest_seq, 2);
    assert_eq!(report.latest_hash, e2.entry_hash);
    assert!(report.is_valid);
}

#[test]
fn test_tamper_detection_content_modification() {
    let db = CaseDb::open_in_memory().unwrap();

    AuditChain::append(&db, "CASE-001", "INV-1", "Op1", "Target1", "SUCCESS").unwrap();
    AuditChain::append(&db, "CASE-001", "INV-1", "Op2", "Target2", "SUCCESS").unwrap();
    AuditChain::append(&db, "CASE-001", "INV-1", "Op3", "Target3", "SUCCESS").unwrap();

    // Verify initially intact
    assert!(AuditChain::verify_db(&db).is_ok());

    // Tamper with entry #2 payload directly in DB table
    let records = db.get_audit_log_entries().unwrap();
    let mut tampered_entry: AuditEntry = serde_json::from_str(&records[1].entry_json).unwrap();
    tampered_entry.result = "FAILED: MALICIOUS ALTERATION".to_string();
    let tampered_json = serde_json::to_string(&tampered_entry).unwrap();

    db.execute_raw(&format!(
        "UPDATE audit_log SET entry_json = '{}' WHERE seq = 2",
        tampered_json
    ))
    .unwrap();

    // Verify that the chain verification detects the exact tampered entry
    let err = AuditChain::verify_db(&db).unwrap_err();
    match err {
        AuditError::HashMismatchAtSeq { seq, .. } => {
            assert_eq!(seq, 2);
        }
        other => panic!("Expected HashMismatchAtSeq at seq 2, got: {:?}", other),
    }
}

#[test]
fn test_tamper_detection_entry_deletion_or_reordering() {
    let db = CaseDb::open_in_memory().unwrap();

    AuditChain::append(&db, "CASE-001", "INV-1", "Op1", "Target1", "SUCCESS").unwrap();
    AuditChain::append(&db, "CASE-001", "INV-1", "Op2", "Target2", "SUCCESS").unwrap();
    AuditChain::append(&db, "CASE-001", "INV-1", "Op3", "Target3", "SUCCESS").unwrap();

    // Delete entry #2
    db.execute_raw("DELETE FROM audit_log WHERE seq = 2").unwrap();

    // Verify verification fails identifying the gap
    let err = AuditChain::verify_db(&db).unwrap_err();
    match err {
        AuditError::SequenceGap { expected, found } => {
            assert_eq!(expected, 2);
            assert_eq!(found, 3);
        }
        AuditError::ChainBrokenAtSeq { seq, .. } => {
            assert_eq!(seq, 3);
        }
        other => panic!("Expected sequence gap or broken chain error, got: {:?}", other),
    }
}

#[test]
fn test_digital_signatures_and_pki_roundtrip() {
    let keypair = OperatorKeyPair::generate();
    let message = b"VAJRA_FORENSIC_REPORT_SHA256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let signature = keypair.sign(message);
    let pk_bytes = hex::decode(keypair.public_key_hex()).unwrap();

    // Valid signature check
    let valid = verify_signature(&pk_bytes, message, &signature).expect("Signature verification failed");
    assert!(valid);

    // Tampered message check
    let tampered_message = b"VAJRA_FORENSIC_REPORT_SHA256_TAMPERED";
    let invalid = verify_signature(&pk_bytes, tampered_message, &signature).expect("Verification failed");
    assert!(!invalid);

    // X.509 cert generation
    let cert_pem = keypair.generate_self_signed_cert("INV-4821").expect("Should generate certificate PEM");
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(cert_pem.contains("END CERTIFICATE"));
}

#[test]
fn test_external_anchoring_and_history_rewrite_detection() {
    let tmp = tempdir().unwrap();
    let anchor_path = tmp.path().join("case_anchor.json");

    let db = CaseDb::open_in_memory().unwrap();
    let keypair = OperatorKeyPair::generate();

    AuditChain::append(&db, "CASE-001", "INV-1", "Op1", "Target1", "SUCCESS").unwrap();
    let e2 = AuditChain::append(&db, "CASE-001", "INV-1", "Op2", "Target2", "SUCCESS").unwrap();

    // 1. Export signed anchor checkpoint
    let checkpoint = export_anchor(&db, "CASE-001", "INV-1", &keypair, &anchor_path)
        .expect("Anchor export failed");
    assert_eq!(checkpoint.sequence, 2);
    assert_eq!(checkpoint.chain_head_hash, e2.entry_hash);

    // 2. Verify against unmodified live DB -> Succeeds
    let report = verify_anchor(&db, &anchor_path).expect("Anchor verification should succeed");
    assert!(report.is_signature_valid);
    assert!(report.is_chain_consistent);

    // 3. Simulate Attacker Model: Rewrite history and forge a self-consistent new hash chain
    // (Attacker modifies Op2 and recomputes all hashes so internal verify_db would pass)
    let forged_e2_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let forged_entry = AuditEntry {
        seq: 2,
        timestamp_utc: e2.timestamp_utc,
        operator_id: "INV-1".to_string(),
        case_id: "CASE-001".to_string(),
        operation: "Op2_Forged".to_string(),
        target_descriptor: "Target2".to_string(),
        result: "SUCCESS".to_string(),
        prev_hash: e2.prev_hash,
        entry_hash: forged_e2_hash.to_string(),
    };

    let forged_json = serde_json::to_string(&forged_entry).unwrap();
    db.execute_raw(&format!(
        "UPDATE audit_log SET entry_json = '{}', entry_hash = '{}' WHERE seq = 2",
        forged_json, forged_e2_hash
    ))
    .unwrap();

    // 4. Verify against external anchor -> Fails with AnchorMismatch!
    let verify_err = verify_anchor(&db, &anchor_path).unwrap_err();
    match verify_err {
        AuditError::AnchorMismatch {
            seq,
            live_hash,
            anchor_hash,
        } => {
            assert_eq!(seq, 2);
            assert_eq!(live_hash, forged_e2_hash);
            assert_eq!(anchor_hash, e2.entry_hash);
        }
        other => panic!("Expected AnchorMismatch error, got: {:?}", other),
    }

    fs::remove_file(anchor_path).ok();
}
