//! End-to-end integration tests for vajra-cli and Vault/Audit/Custody subsystems (§17, §21, §22, §39, §40).

use tempfile::tempdir;
use vajra_audit::{export_anchor, verify_anchor, AuditChain, OperatorKeyPair, GENESIS_PREV_HASH};
use vajra_case_db::{CaseDb, CaseStatus, DbError, EvidenceItemRecord};
use vajra_custody::{CustodyEvent, CustodyEventType, CustodyTracker};

#[test]
fn test_end_to_end_forensic_case_lifecycle() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("forensic_vault.db");
    let anchor_path = tmp.path().join("external_anchor.json");

    // 1. Initialize encrypted database
    let db = CaseDb::open_file(&db_path, None).expect("Should initialize case database");

    // 2. Create new active case (§22)
    let case = db
        .create_case("CASE-2026-HQ-01", "Operation Cyber Shield", "INV-8834")
        .expect("Should create active case");
    assert_eq!(case.status, CaseStatus::Active);

    // 3. Register physical evidence item with deterministic SHA-256 fingerprint (§22, §23)
    let evidence = EvidenceItemRecord {
        evidence_id: "EVID-8B3F91AC".to_string(),
        case_id: case.case_id.clone(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "0025_38F4_51B3_DC6A".to_string(),
        manufacturer: "Samsung".to_string(),
        model: "MZVL81T0HFLB-00BH1".to_string(),
        capacity_bytes: 1_024_209_543_168,
        interface: "NVMe".to_string(),
        filesystem: Some("NTFS".to_string()),
        device_fingerprint_hash: "8b3f91ac74624b593ef2d3ef0c2be482e99d8e75db7111fa05470b13cf106b02".to_string(),
        source_location: Some("Primary Workstation Bay 0".to_string()),
        physical_condition: Some("Good / Undamaged".to_string()),
        write_block_status: Some("Hardware Blocker Active".to_string()),
        current_custody_owner: None,
        current_location: None,
    };
    db.add_evidence(&evidence).expect("Should add evidence item");

    // 4. Log chronological Chain of Custody events (§21)
    let e1 = CustodyEvent {
        event_id: "EVT-01".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        event_type: CustodyEventType::Seized,
        from_party: None,
        to_party: Some("Detective Sharma".to_string()),
        timestamp_utc: "2026-08-30T10:00:00Z".to_string(),
        location: Some("Suspect Server Room".to_string()),
        purpose: Some("Seizure under search warrant".to_string()),
        evidence_condition: Some("Tamper bag sealed".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e1).expect("Record Seized event");

    let e2 = CustodyEvent {
        event_id: "EVT-02".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        event_type: CustodyEventType::Received,
        from_party: None,
        to_party: Some("Detective Sharma".to_string()),
        timestamp_utc: "2026-08-30T11:15:00Z".to_string(),
        location: Some("Evidence Intake Facility".to_string()),
        purpose: Some("Case Booking".to_string()),
        evidence_condition: Some("Bag seal intact".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e2).expect("Record Received event");

    let e3 = CustodyEvent {
        event_id: "EVT-03".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        event_type: CustodyEventType::StorageChange,
        from_party: None,
        to_party: None,
        timestamp_utc: "2026-08-30T12:00:00Z".to_string(),
        location: Some("Evidence Vault Locker 12".to_string()),
        purpose: Some("Secure storage".to_string()),
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e3).expect("Record StorageChange event");

    let e4 = CustodyEvent {
        event_id: "EVT-04".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        event_type: CustodyEventType::Transferred,
        from_party: Some("Detective Sharma".to_string()),
        to_party: Some("Examiner Zahid".to_string()),
        timestamp_utc: "2026-08-30T14:30:00Z".to_string(),
        location: Some("Forensic Workstation 1".to_string()),
        purpose: Some("Forensic imaging and carving".to_string()),
        evidence_condition: Some("Seal verified".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e4).expect("Record Transferred event");

    // Verify custody history report
    let history = CustodyTracker::get_history(&db, &evidence.evidence_id).expect("Get history");
    assert_eq!(history.len(), 4);
    let report_text = CustodyTracker::format_history_report(&evidence.evidence_id, "Samsung NVMe 1TB", &history);
    assert!(report_text.contains("Seized"));
    assert!(report_text.contains("Transferred from Detective Sharma to Examiner Zahid"));
    assert!(report_text.contains("NOTE: This interface records operator-reported custody events"));

    // 5. Append sequential hash-chained audit log entries (§39)
    let a1 = AuditChain::append(
        &db,
        &case.case_id,
        "INV-8834",
        "CaseCreated",
        &case.case_id,
        "SUCCESS",
    )
    .expect("Append audit 1");
    assert_eq!(a1.seq, 1);
    assert_eq!(a1.prev_hash, GENESIS_PREV_HASH);

    let a2 = AuditChain::append(
        &db,
        &case.case_id,
        "INV-8834",
        "PhysicalAcquisition",
        &evidence.evidence_id,
        "SUCCESS",
    )
    .expect("Append audit 2");
    assert_eq!(a2.seq, 2);
    assert_eq!(a2.prev_hash, a1.entry_hash);

    let a3 = AuditChain::append(
        &db,
        &case.case_id,
        "INV-8834",
        "SHA256HashVerification",
        &evidence.evidence_id,
        "SUCCESS",
    )
    .expect("Append audit 3");
    assert_eq!(a3.seq, 3);
    assert_eq!(a3.prev_hash, a2.entry_hash);

    // 6. Cryptographically verify audit chain
    let chain_report = AuditChain::verify_db(&db).expect("Chain verification must succeed");
    assert_eq!(chain_report.total_entries, 3);
    assert_eq!(chain_report.latest_seq, 3);
    assert!(chain_report.is_valid);

    // 7. Export signed external anchor checkpoint (§40)
    let operator_key = OperatorKeyPair::generate();
    let checkpoint = export_anchor(&db, &case.case_id, "INV-8834", &operator_key, &anchor_path)
        .expect("Anchor export");
    assert_eq!(checkpoint.sequence, 3);
    assert_eq!(checkpoint.chain_head_hash, a3.entry_hash);

    // 8. Verify live database against external anchor (§40)
    let anchor_report = verify_anchor(&db, &anchor_path).expect("Anchor verification");
    assert!(anchor_report.is_signature_valid);
    assert!(anchor_report.is_chain_consistent);

    // 9. Close and tombstone the case permanently (§22)
    db.close_case(&case.case_id).expect("Close case");
    let closed_case = db.get_case(&case.case_id).expect("Get closed case");
    assert_eq!(closed_case.status, CaseStatus::Closed);

    // 10. Verify that re-closing, reopening, or deleting the case is strictly rejected
    let reclose_err = db.close_case(&case.case_id).unwrap_err();
    match reclose_err {
        DbError::IllegalStateTransition { from, to, .. } => {
            assert_eq!(from, "Closed");
            assert_eq!(to, "Closed");
        }
        other => panic!("Expected IllegalStateTransition, got: {:?}", other),
    }

    let reopen_res = db.execute_raw(&format!(
        "UPDATE cases SET status = 'Active' WHERE case_id = '{}'",
        case.case_id
    ));
    assert!(reopen_res.is_err(), "Trigger must abort case reopening");

    let delete_res = db.execute_raw(&format!(
        "DELETE FROM cases WHERE case_id = '{}'",
        case.case_id
    ));
    assert!(delete_res.is_err(), "Trigger must abort case deletion");
}
