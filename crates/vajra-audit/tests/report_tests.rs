//! Unit and Integration Tests for vajra-audit Unified Report Engine (§41, §40).

use chrono::Utc;
use std::collections::HashMap;
use tempfile::tempdir;
use vajra_audit::report::timestamp::{encode_rfc3161_request, parse_pki_status};
use vajra_audit::report::*;
use vajra_case_db::CaseDb;

#[test]
fn test_encode_rfc3161_request_der_structure() {
    let dummy_hash = [0xABu8; 32];
    let der = encode_rfc3161_request(&dummy_hash);

    assert!(!der.is_empty(), "DER request must not be empty");
    assert_eq!(der[0], 0x30, "DER root must be a SEQUENCE tag (0x30)");
    // Must contain SHA-256 OID: 06 09 60 86 48 01 65 03 04 02 01
    let oid_bytes = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    assert!(
        der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
        "DER request must contain SHA-256 AlgorithmIdentifier OID"
    );
}

#[test]
fn test_parse_pki_status_rfc3161() {
    // 1. Granted: status = 0
    // Root SEQUENCE (len 7): 30 07
    //   PKIStatusInfo SEQUENCE (len 5): 30 05
    //     PKIStatus INTEGER (len 1, val 0): 02 01 00
    //     (optional trailing fields or tokens would follow in real responses)
    let granted_der = vec![0x30, 0x07, 0x30, 0x05, 0x02, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(parse_pki_status(&granted_der), Ok(0));

    // 2. GrantedWithMods: status = 1
    let granted_with_mods_der = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
    assert_eq!(parse_pki_status(&granted_with_mods_der), Ok(1));

    // 3. Rejection: status = 2 (RFC 3161 §2.4.2 rejection)
    let rejection_der = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    assert_eq!(parse_pki_status(&rejection_der), Ok(2));

    // 4. RevocationWarning: status = 4
    let warning_der = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x04];
    assert_eq!(parse_pki_status(&warning_der), Ok(4));

    // 5. Multi-byte length DER encoding (e.g. realistic large TimeStampResp > 128 bytes)
    let mut large_resp = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE len 256
    large_resp.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x00]); // PKIStatusInfo { status: 0 }
    large_resp.resize(260, 0xAA); // trailing dummy token bytes
    assert_eq!(parse_pki_status(&large_resp), Ok(0));

    // 6. Malformed DER: Empty input
    assert!(parse_pki_status(&[]).is_err());

    // 7. Malformed DER: Not a SEQUENCE root
    assert!(parse_pki_status(&[0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]).is_err());

    // 8. Malformed DER: Truncated inside PKIStatusInfo
    assert!(parse_pki_status(&[0x30, 0x05, 0x30, 0x03, 0x02]).is_err());

    // 9. Malformed DER: Missing INTEGER tag
    assert!(parse_pki_status(&[0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 0x00]).is_err());
}

#[test]
fn test_timestamp_offline_graceful_fallback() {
    let dummy_hash = [0x42u8; 32];
    // Point at an unreachable local port to force offline fallback
    let ts_record = fetch_timestamp_opportunistic(&dummy_hash, Some("http://127.0.0.1:9"), Some(100));

    assert!(!ts_record.is_rfc3161);
    assert_eq!(ts_record.tsa_url, None);
    assert_eq!(
        ts_record.status_label,
        "Local timestamp — RFC 3161 unavailable at generation time"
    );
    assert!(!ts_record.timestamp_utc.is_empty());
}

#[test]
fn test_all_six_report_types_generation_and_signing() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("case_test.db");
    let db = CaseDb::open_file(db_path.to_str().unwrap(), None).expect("CaseDb must initialize");

    let case_id = "CASE-2026-REPORT-001";
    let _ = db.create_case(case_id, "Report Engine E2E Case", "INV-99");

    let generator = ReportGenerator::new("OP-CHIEF");

    // 1. Forensic Examination Report
    let exam_report = generator
        .generate_forensic_examination_report(case_id, "Comprehensive forensic exam complete.", &db)
        .expect("Forensic exam report generation must succeed");
    assert_eq!(exam_report.report_type, ReportType::ForensicExamination);
    assert_eq!(exam_report.content_sha256.len(), 64);
    assert!(!exam_report.signature_hex.is_empty());
    assert!(!exam_report.signing_cert_pem.is_empty());

    // 2. Sanitization Certificate Report
    let cert = SanitizationCertData {
        certificate_id: "CERT-SAN-001".to_string(),
        device_serial: "SAMSUNG-SSD-999".to_string(),
        manufacturer: "Samsung".to_string(),
        model: "PM9A3".to_string(),
        media_type: "NVMe SSD".to_string(),
        capacity_bytes: 512000000000,
        sanitization_method: "NVMe Block Erase".to_string(),
        standard_reference: "NIST SP 800-88 Rev. 2 (Purge tier); IEEE 2883-2022".to_string(),
        timestamp_completed: Utc::now().to_rfc3339(),

        operator_id: "OP-CHIEF".to_string(),
        layer1_controller_confirmation: "PASS".to_string(),
        layer2_readback_samples: "PASS".to_string(),
        layer3_full_read: "N/A".to_string(),
        layer4_entropy_analysis: "PASS".to_string(),
        layer5_recovery_carve: "PASS (0 artifacts)".to_string(),
        overall_assurance: "HIGH".to_string(),
        assurance_justification: None,
    };
    let san_report = generator
        .generate_sanitization_certificate_report(case_id, cert, &db)
        .expect("Sanitization cert report generation must succeed");
    assert_eq!(san_report.report_type, ReportType::SanitizationCertificate);

    // 3. Acquisition Report
    let acq_payload = AcquisitionReportPayload {
        case_id: case_id.to_string(),
        evidence_id: "EVID-001".to_string(),
        device_serial: "WD-RED-101".to_string(),
        manufacturer: "Western Digital".to_string(),
        model: "WD40EFRX".to_string(),
        capacity_bytes: 1048576,
        device_fingerprint_hash: "a1b2c3d4e5f6".to_string(),
        image_format: "RAW".to_string(),
        image_file_path: "/tmp/evidence_001.raw".to_string(),
        acquisition_hash_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        verification_hash_sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
        re_read_verified: true,
        total_sectors: 2048,
        bad_sector_count: 0,
        bad_sector_ranges: Vec::new(),
        started_at: Utc::now().to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        operator: "OP-CHIEF".to_string(),
    };
    let acq_report = generator
        .generate_acquisition_report(case_id, acq_payload, &db)
        .expect("Acquisition report generation must succeed");
    assert_eq!(acq_report.report_type, ReportType::AcquisitionReport);

    // 4. Recovery Report
    let rec_payload = RecoveryReportPayload {
        case_id: case_id.to_string(),
        target_source: "/evidence/disk.img".to_string(),
        partition_offset_lba: 0,
        tiers_executed: vec!["Tier 1 (Metadata)".to_string(), "Tier 2 (Signature)".to_string()],
        total_recovered_artifacts: 2,
        tier1_count: 1,
        tier2_count: 1,
        tier3_count: 0,
        type_counts: HashMap::new(),
        artifacts: Vec::new(),
    };
    let rec_report = generator
        .generate_recovery_report(case_id, rec_payload, &db)
        .expect("Recovery report generation must succeed");
    assert_eq!(rec_report.report_type, ReportType::RecoveryReport);

    // 5. Device Health Report
    let health_payload = DeviceHealthPayload {
        case_id: case_id.to_string(),
        device_path: "/dev/sdb".to_string(),
        serial: "WD-RED-101".to_string(),
        model: "WD40EFRX".to_string(),
        vendor: "Western Digital".to_string(),
        interface: "SATA".to_string(),
        media_type: "HDD".to_string(),
        capacity_bytes: 1048576,
        device_fingerprint_hash: "a1b2c3d4e5f6".to_string(),
        health_status: "Healthy".to_string(),
        temperature_celsius: Some(34),
        power_on_hours: Some(1200),
        power_cycles: Some(45),
        critical_warning_flags: Vec::new(),
        raw_attributes: Vec::new(),
        decision_engine_recommendation: "Drive healthy for forensic imaging".to_string(),
    };
    let health_report = generator
        .generate_device_health_report(case_id, health_payload, &db)
        .expect("Device health report generation must succeed");
    assert_eq!(health_report.report_type, ReportType::DeviceHealthReport);

    // 6. Chain of Custody Report
    let custody_payload = ChainOfCustodyPayload {
        case_id: case_id.to_string(),
        evidence_id: "EVID-001".to_string(),
        device_serial: "WD-RED-101".to_string(),
        manufacturer: "Western Digital".to_string(),
        model: "WD40EFRX".to_string(),
        current_owner: "Inv. Jane Doe".to_string(),
        current_location: "Secure Evidence Locker A".to_string(),
        physical_condition: "Intact / Bagged & Tagged".to_string(),
        total_events: 1,
        events: Vec::new(),
    };
    let custody_report = generator
        .generate_chain_of_custody_report(case_id, custody_payload, &db)
        .expect("Chain of custody report generation must succeed");
    assert_eq!(custody_report.report_type, ReportType::ChainOfCustodyReport);

    // Verify all 6 reports were recorded in CaseDb
    let db_reports = db.list_reports_for_case(case_id).unwrap();
    assert_eq!(db_reports.len(), 6, "All 6 report records must be stored in database");
}
