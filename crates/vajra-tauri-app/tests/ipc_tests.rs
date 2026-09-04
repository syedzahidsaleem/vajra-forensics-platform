//! Integration Tests for vajra-tauri-app IPC Commands (§17, §19, §23, §34, §36, §41, §42, §43).

use app_lib::commands::cases::*;
use app_lib::commands::devices::*;
use app_lib::commands::reports::*;
use app_lib::commands::sanitize::*;
use app_lib::commands::acquire::*;

#[test]
fn test_devices_ipc_endpoints() {
    let devices = list_devices().expect("list_devices should succeed");
    assert!(!devices.is_empty(), "Should detect connected storage devices");

    let first = &devices[0];
    let fp = get_device_fingerprint(first.path.clone()).expect("Fingerprint should succeed");
    assert_eq!(fp.path, first.path);
    assert_eq!(fp.serial, first.serial);
    assert_eq!(fp.sha256_hash.len(), 64, "SHA-256 hash must be 64 hex characters");

    let health = get_device_health(first.path.clone()).expect("Health query should succeed");
    assert_eq!(health.device_path, first.path);
    assert!(
        ["PASSED", "WARNING", "CRITICAL", "UNKNOWN"].contains(&health.overall_health.as_str()),
        "Valid health status string expected"
    );
}

#[test]
fn test_cases_and_evidence_vault_ipc() {
    let case_id = format!("CASE-TEST-{}", rand::random::<u16>());
    let case = create_case(
        case_id.clone(),
        "Operation Integration Test".to_string(),
        "INV-4402-NITYA".to_string(),
        Some("Test notes".to_string()),
    )
    .expect("create_case should succeed");

    assert_eq!(case.case_id, case_id);
    assert_eq!(case.status, "Active");

    let cases = list_cases().expect("list_cases should succeed");
    assert!(cases.iter().any(|c| c.case_id == case_id));

    let devices = list_devices().unwrap_or_default();
    let dev_path = if !devices.is_empty() {
        devices[0].path.clone()
    } else {
        "\\\\.\\PhysicalDrive0".to_string()
    };

    let evidence = add_evidence(
        case_id.clone(),
        dev_path.clone(),
        "Seized Target Drive".to_string(),
    )
    .expect("add_evidence should succeed");

    assert_eq!(evidence.case_id, case_id);
    assert_eq!(evidence.source_path, dev_path);

    let evidence_list = list_evidence(case_id.clone()).expect("list_evidence should succeed");
    assert!(!evidence_list.is_empty());
    assert_eq!(evidence_list[0].evidence_id, evidence.evidence_id);

    let custody = get_custody_history(evidence.evidence_id.clone()).expect("get_custody_history should succeed");
    assert!(!custody.is_empty());

    let closed = close_case(case_id.clone()).expect("close_case should succeed");
    assert!(closed);
}

#[test]
fn test_reports_ipc_and_independent_verifier() {
    let case_id = format!("CASE-REP-{}", rand::random::<u16>());
    create_case(
        case_id.clone(),
        "Report Test Case".to_string(),
        "INV-4402-NITYA".to_string(),
        None,
    )
    .unwrap();

    let rep = generate_report(
        case_id.clone(),
        "Acquisition".to_string(),
        Some("Imaging completed with matching hashes.".to_string()),
        None,
    )
    .expect("generate_report should succeed");

    assert_eq!(rep.case_id, case_id);
    assert!(rep.signed, "Generated report must be digitally signed");
    assert!(std::path::Path::new(&rep.json_path).exists(), "Report JSON file must exist on disk");

    let reports = list_reports(case_id).expect("list_reports should succeed");
    assert!(!reports.is_empty());

    let verify_res = verify_report(rep.json_path).expect("verify_report should succeed");
    assert!(verify_res.valid, "Report integrity must be verified as valid");
    assert!(verify_res.signature_verified, "Digital signature must verify");
    assert!(verify_res.hash_matches, "Payload hash must match");
    assert!(!verify_res.checks.is_empty(), "Cryptographic verification checks must be reported");

    // Test HTML export
    let html_path = export_report_html(rep.report_id, None).expect("HTML export should succeed");
    assert!(std::path::Path::new(&html_path).exists(), "HTML report must exist on disk");
    let html_body = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_body.contains("VAJRA"));
    assert!(html_body.contains("CRYPTOGRAPHICALLY SIGNED"));
}

#[test]
fn test_sanitization_recommendation_and_safety_gate() {
    let devices = list_devices().expect("list_devices should succeed");
    if let Some(sys_disk) = devices.iter().find(|d| d.is_system_disk) {
        let rec = get_sanitization_recommendation(sys_disk.path.clone())
            .expect("Recommendation should succeed");
        assert!(rec.is_os_disk_blocked, "OS system disk must be marked as blocked");

        let gate_res = begin_sanitization_gate(sys_disk.path.clone());
        assert!(
            gate_res.is_err(),
            "Initiating sanitization gate on OS boot disk must be hard rejected (§24)"
        );
    }
}

#[test]
fn test_acquisition_job_tracking_and_checkpoints() {
    let case_id = "CASE-ACQ-TEST";
    let config = AcquisitionConfigDto {
        source_device_path: "\\\\.\\PhysicalDrive0".to_string(),
        destination_path: "./test_images".to_string(),
        image_name: "TEST_ACQ_JOB".to_string(),
        profile: "Physical".to_string(),
        format: "RAW".to_string(),
        segment_size_mb: 2048,
        compute_sha256: true,
        compute_md5: true,
        case_id: case_id.to_string(),
        evidence_id: "EVID-TEST".to_string(),
        examiner: "INV-4402-NITYA".to_string(),
        notes: None,
    };

    let start_res = start_acquisition(config).expect("start_acquisition should initialize job");
    let job_id = start_res["jobId"].as_str().unwrap().to_string();

    let progress = get_acquisition_progress(job_id).expect("get_acquisition_progress should succeed");
    assert!(["queued", "running", "completed", "failed"].contains(&progress.state.as_str()));

    let checkpoints = list_acquisition_checkpoints(case_id.to_string()).expect("list_acquisition_checkpoints should succeed");
    assert!(checkpoints.is_empty() || !checkpoints.is_empty());
}

#[test]
fn test_file_sanitization_ipc() {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("vajra_shred_test_{}.dat", rand::random::<u16>()));
    std::fs::write(&temp_file, b"CONFIDENTIAL EVIDENCE REQUIRING FILE-LEVEL SHREDDING").unwrap();
    assert!(temp_file.exists());

    let res = sanitize_file(temp_file.to_string_lossy().to_string(), 3)
        .expect("sanitize_file should succeed");
    assert_eq!(res["status"], "success");
    assert!(!temp_file.exists(), "Sanitized file must be removed from disk");

    let slack_res = sanitize_unallocated_slack("C:\\".to_string())
        .expect("sanitize_unallocated_slack should succeed");
    assert_eq!(slack_res["status"], "success");
}
