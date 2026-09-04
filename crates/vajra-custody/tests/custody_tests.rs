//! Integration tests for vajra-custody (§21).

use vajra_case_db::{CaseDb, EvidenceItemRecord};
use vajra_custody::{CustodyEvent, CustodyEventType, CustodyTracker};

fn setup_db_with_evidence() -> (CaseDb, String) {
    let db = CaseDb::open_in_memory().unwrap();
    db.create_case("CASE-001", "Homicide Investigation", "INV-1").unwrap();

    let item = EvidenceItemRecord {
        evidence_id: "E-001".to_string(),
        case_id: "CASE-001".to_string(),
        item_type: "PhysicalDevice".to_string(),
        device_serial: "0025_38F4_51B3_DC6A".to_string(),
        manufacturer: "Samsung".to_string(),
        model: "980 PRO 2TB".to_string(),
        capacity_bytes: 2_000_398_934_016,
        interface: "NVMe".to_string(),
        filesystem: Some("NTFS".to_string()),
        device_fingerprint_hash: "8B3F91AC".to_string(),
        source_location: Some("Suspect Laptop".to_string()),
        physical_condition: Some("Intact".to_string()),
        write_block_status: None,
        current_custody_owner: None,
        current_location: None,
    };
    db.add_evidence(&item).unwrap();

    (db, "E-001".to_string())
}

#[test]
fn test_valid_custody_event_sequence() {
    let (db, evid_id) = setup_db_with_evidence();

    // 1. 15:31 Seized
    let e1 = CustodyEvent {
        event_id: "EVT-1".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Seized,
        from_party: None,
        to_party: Some("Officer A".to_string()),
        timestamp_utc: "2026-08-30T15:31:00Z".to_string(),
        location: Some("Field Scene 4".to_string()),
        purpose: Some("Evidence seizure".to_string()),
        evidence_condition: Some("Sealed tamper bag".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e1).unwrap();

    // 2. 15:42 Received
    let e2 = CustodyEvent {
        event_id: "EVT-2".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Received,
        from_party: None,
        to_party: Some("Officer A".to_string()),
        timestamp_utc: "2026-08-30T15:42:00Z".to_string(),
        location: Some("Evidence Intake".to_string()),
        purpose: Some("Booking evidence".to_string()),
        evidence_condition: Some("Bag intact".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e2).unwrap();

    // 3. 16:03 StorageChange
    let e3 = CustodyEvent {
        event_id: "EVT-3".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::StorageChange,
        from_party: None,
        to_party: None,
        timestamp_utc: "2026-08-30T16:03:00Z".to_string(),
        location: Some("Evidence Locker 4".to_string()),
        purpose: Some("Secure overnight storage".to_string()),
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e3).unwrap();

    // 4. 09:12 (next day) Transferred
    let e4 = CustodyEvent {
        event_id: "EVT-4".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Transferred,
        from_party: Some("Officer A".to_string()),
        to_party: Some("Examiner B".to_string()),
        timestamp_utc: "2026-08-31T09:12:00Z".to_string(),
        location: Some("Forensic Laboratory".to_string()),
        purpose: Some("Forensic imaging".to_string()),
        evidence_condition: Some("Tamper seal verified".to_string()),
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e4).unwrap();

    // 5. 09:18 WriteBlockerAttached
    let e5 = CustodyEvent {
        event_id: "EVT-5".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::WriteBlockerAttached,
        from_party: None,
        to_party: Some("Examiner B".to_string()),
        timestamp_utc: "2026-08-31T09:18:00Z".to_string(),
        location: Some("Forensic Workstation 1".to_string()),
        purpose: Some("Tableau T35u Bridge attached".to_string()),
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e5).unwrap();

    // 6. 09:24 AnalysisStarted
    let e6 = CustodyEvent {
        event_id: "EVT-6".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::AnalysisStarted,
        from_party: None,
        to_party: Some("Examiner B".to_string()),
        timestamp_utc: "2026-08-31T09:24:00Z".to_string(),
        location: Some("Forensic Workstation 1".to_string()),
        purpose: Some("Vajra Module 0 physical acquisition".to_string()),
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e6).unwrap();

    let history = CustodyTracker::get_history(&db, &evid_id).unwrap();
    assert_eq!(history.len(), 6);

    let report_text = CustodyTracker::format_history_report(&evid_id, "Samsung 980 PRO 2TB", &history);
    assert!(report_text.contains("Evidence #E-001 (Samsung 980 PRO 2TB)"));
    assert!(report_text.contains("Seized"));
    assert!(report_text.contains("Transferred from Officer A to Examiner B"));
    assert!(report_text.contains("NOTE: This interface records operator-reported custody events"));
}

#[test]
fn test_invalid_initial_event_rejection() {
    let (db, evid_id) = setup_db_with_evidence();

    // Attempting to record Transferred first
    let invalid_evt = CustodyEvent {
        event_id: "EVT-ERR".to_string(),
        evidence_id: evid_id,
        event_type: CustodyEventType::Transferred,
        from_party: Some("Officer A".to_string()),
        to_party: Some("Examiner B".to_string()),
        timestamp_utc: "2026-08-30T10:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };

    let res = CustodyTracker::record_event(&db, &invalid_evt);
    assert!(res.is_err(), "Must reject Transferred as initial event");
}

#[test]
fn test_transfer_missing_parties_rejection() {
    let (db, evid_id) = setup_db_with_evidence();

    let e1 = CustodyEvent {
        event_id: "EVT-1".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Received,
        from_party: None,
        to_party: Some("Officer A".to_string()),
        timestamp_utc: "2026-08-30T10:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e1).unwrap();

    let bad_transfer = CustodyEvent {
        event_id: "EVT-2".to_string(),
        evidence_id: evid_id,
        event_type: CustodyEventType::Transferred,
        from_party: None, // Missing from_party
        to_party: Some("Examiner B".to_string()),
        timestamp_utc: "2026-08-30T11:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };

    let res = CustodyTracker::record_event(&db, &bad_transfer);
    assert!(res.is_err(), "Must reject transfer missing from_party");
}

#[test]
fn test_event_after_terminal_disposal_rejection() {
    let (db, evid_id) = setup_db_with_evidence();

    let e1 = CustodyEvent {
        event_id: "EVT-1".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Received,
        from_party: None,
        to_party: Some("Officer A".to_string()),
        timestamp_utc: "2026-08-30T10:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e1).unwrap();

    let e2 = CustodyEvent {
        event_id: "EVT-2".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Returned,
        from_party: Some("Officer A".to_string()),
        to_party: Some("Owner John Doe".to_string()),
        timestamp_utc: "2026-08-30T17:00:00Z".to_string(),
        location: None,
        purpose: Some("Court return order".to_string()),
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e2).unwrap();

    // Attempt to log AnalysisStarted after evidence was returned
    let post_return = CustodyEvent {
        event_id: "EVT-3".to_string(),
        evidence_id: evid_id,
        event_type: CustodyEventType::AnalysisStarted,
        from_party: None,
        to_party: Some("Examiner C".to_string()),
        timestamp_utc: "2026-08-30T18:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };

    let res = CustodyTracker::record_event(&db, &post_return);
    assert!(res.is_err(), "Must reject custody event on returned evidence");
}

#[test]
fn test_non_monotonic_timestamp_rejection() {
    let (db, evid_id) = setup_db_with_evidence();

    // Event 1 at 12:00:00Z
    let e1 = CustodyEvent {
        event_id: "EVT-1".to_string(),
        evidence_id: evid_id.clone(),
        event_type: CustodyEventType::Received,
        from_party: None,
        to_party: Some("Officer A".to_string()),
        timestamp_utc: "2026-08-30T12:00:00Z".to_string(),
        location: None,
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };
    CustodyTracker::record_event(&db, &e1).unwrap();

    // Event 2 at 11:00:00Z (out of order, earlier than event 1)
    let e2_earlier = CustodyEvent {
        event_id: "EVT-2".to_string(),
        evidence_id: evid_id,
        event_type: CustodyEventType::StorageChange,
        from_party: None,
        to_party: None,
        timestamp_utc: "2026-08-30T11:00:00Z".to_string(),
        location: Some("Evidence Locker 3".to_string()),
        purpose: None,
        evidence_condition: None,
        signature_ref: None,
    };

    let res = CustodyTracker::record_event(&db, &e2_earlier);
    assert!(res.is_err(), "Must reject out-of-order non-monotonic timestamp");
    match res.unwrap_err() {
        vajra_custody::CustodyError::NonMonotonicTimestamp { previous, current } => {
            assert_eq!(previous, "2026-08-30T12:00:00Z");
            assert_eq!(current, "2026-08-30T11:00:00Z");
        }
        other => panic!("Expected NonMonotonicTimestamp error, got: {:?}", other),
    }
}
