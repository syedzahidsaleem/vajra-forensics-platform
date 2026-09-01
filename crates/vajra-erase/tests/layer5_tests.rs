//! Multi-Layer Sanitization Verification & Layer 5 Override Tests (§37, §38).

use chrono::Utc;
use vajra_audit::pki::OperatorKeyPair;
use vajra_core::media_type::MediaType;
use vajra_core::sanitize::SanitizeMethod;
use vajra_device::DeviceDescriptor;
use vajra_erase::certificate::SanitizationCertificate;
use vajra_erase::gate::DeviceConfirmationGate;
use vajra_erase::methods::execute_sanitization_destructive;
use vajra_erase::mock::MockWritableDevice;
use vajra_erase::verify::{verify_sanitization, OverallAssurance};

fn make_mock_device_descriptor(total_bytes: u64, media_type: MediaType) -> DeviceDescriptor {
    DeviceDescriptor {
        path: "/dev/mock_disk0".to_string(),
        device_index: 0,
        manufacturer: "Samsung".to_string(),
        model: if media_type == MediaType::Nvme { "PM9A3 NVMe Enterprise SSD".to_string() } else { "870_EVO".to_string() },
        serial: "S5GXNF0R123456".to_string(),
        capacity_bytes: total_bytes,
        logical_block_size: 512,
        physical_block_size: 512,
        media_type,
        interface: if media_type == MediaType::Nvme { "NVMe".to_string() } else { "SATA".to_string() },
        partition_table: "GPT".to_string(),
        is_system_disk: false,
        is_read_only: false,
        is_write_blocked: false,
        write_blocker_info: None,
        boundary_sample: vec![0u8; 512],
    }
}

#[test]
fn test_clean_controller_native_sanitization_high_assurance() {
    let mut mock_dev = MockWritableDevice::new(200, 512, MediaType::Nvme);
    let dev_desc = make_mock_device_descriptor(200 * 512, MediaType::Nvme);

    // 1. Pass confirmation gate
    let pending = DeviceConfirmationGate::begin(&dev_desc, "analyst_alice", "S5GXNF0R123456", true)
        .expect("Gate begin must pass");
    let token = pending.finalize(true).expect("Gate finalize must pass");

    // 2. Execute Controller-Native Sanitization
    let start_time = Utc::now();
    let res = execute_sanitization_destructive(
        &mut mock_dev,
        &SanitizeMethod::NvmeSanitizeBlock,
        &token,
        |_p, _tp, _w, _t| {},
    );
    let end_time = Utc::now();
    assert!(res.is_ok(), "Sanitize command must succeed");

    // 3. Multi-Layer Verification
    let sample_lbas = [0, 1, 10, 50, 100, 199];
    let (report, artifacts) = verify_sanitization(
        &mut mock_dev,
        &res,
        &sample_lbas,
        0.999,
        0.0001,
        Some(&SanitizeMethod::NvmeSanitizeBlock),
    );

    assert!(report.layer1.passed);
    assert!(report.layer2.passed);
    assert!(report.layer3.passed);
    assert!(report.layer4.passed);
    assert!(report.layer5.passed);
    assert_eq!(artifacts.len(), 0);
    assert_eq!(report.overall_assurance, OverallAssurance::High);

    // 4. Generate Certificate
    let keypair = OperatorKeyPair::generate();
    let cert = SanitizationCertificate::generate(
        &dev_desc,
        SanitizeMethod::NvmeSanitizeBlock,
        "NIST SP 800-88 Rev. 2 (Purge tier); IEEE 2883-2022",
        start_time,
        end_time,
        &report,
        "analyst_alice",
        Some(&keypair),
    );

    let cert_text = cert.render_text();
    println!("{}", cert_text);
    assert!(cert_text.contains("Overall Assurance: HIGH"));
    assert!(cert.residual_risk_warning.is_none());
}

#[test]
fn test_flash_host_overwrite_assurance_capped_at_medium() {
    let mut mock_dev = MockWritableDevice::new(200, 512, MediaType::Nvme);
    let dev_desc = make_mock_device_descriptor(200 * 512, MediaType::Nvme);

    // 1. Pass confirmation gate
    let pending = DeviceConfirmationGate::begin(&dev_desc, "analyst_alice", "S5GXNF0R123456", true).unwrap();
    let token = pending.finalize(true).unwrap();

    // 2. Execute Host Overwrite against NVMe SSD
    let start_time = Utc::now();
    let res = execute_sanitization_destructive(
        &mut mock_dev,
        &SanitizeMethod::HostOverwriteSinglePass,
        &token,
        |_p, _tp, _w, _t| {},
    );
    let end_time = Utc::now();
    assert!(res.is_ok());

    // 3. Multi-Layer Verification
    let sample_lbas = [0, 1, 10, 50, 100, 199];
    let (report, artifacts) = verify_sanitization(
        &mut mock_dev,
        &res,
        &sample_lbas,
        0.999,
        0.0001,
        Some(&SanitizeMethod::HostOverwriteSinglePass),
    );

    // All 5 verification layers pass on addressable LBAs:
    assert!(report.layer1.passed);
    assert!(report.layer2.passed);
    assert!(report.layer3.passed);
    assert!(report.layer4.passed);
    assert!(report.layer5.passed);
    assert_eq!(artifacts.len(), 0);

    // BUT §33a Structural Assurance Cap forces Overall Assurance to MEDIUM:
    assert_eq!(
        report.overall_assurance,
        OverallAssurance::Medium,
        "§33a HONESTY REQUIREMENT: Host-level overwrite on SSD/NVMe MUST be capped at MEDIUM!"
    );
    assert!(report.summary_reason.contains("capped at MEDIUM per §33a"));

    // 4. Generate Certificate
    let keypair = OperatorKeyPair::generate();
    let cert = SanitizationCertificate::generate(
        &dev_desc,
        SanitizeMethod::HostOverwriteSinglePass,
        "NIST SP 800-88 Rev. 2 (Clear tier); IEEE 2883-2022",
        start_time,
        end_time,
        &report,
        "analyst_alice",
        Some(&keypair),
    );

    let cert_text = cert.render_text();
    println!("{}", cert_text);
    assert!(cert_text.contains("Overall Assurance: MEDIUM"));
    assert!(cert.residual_risk_warning.is_some(), "Certificate MUST embed §33a residual risk warning");
    assert!(cert_text.contains("Residual Risk Disclosure (§33a)"));
}

#[test]
fn test_layer5_isolated_override_scenario() {
    let mut mock_dev = MockWritableDevice::new(2000, 512, MediaType::Hdd);
    let _dev_desc = make_mock_device_descriptor(2000 * 512, MediaType::Hdd);

    // Populate a valid PDF file at LBA 1500 (outside deterministic sample and outside statistical sample)
    let pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n60\n%%EOF\n";
    mock_dev.populate_data(1500, pdf_bytes);

    // Simulate sanitization command returning success
    let command_ok: Result<(), vajra_erase::error::EraseError> = Ok(());

    // Deterministic sample checks boundaries: LBA 0, 1, 2, 1999 (which are clean 0x00)
    let sample_lbas = [0, 1, 2, 1999];

    // Multi-Layer Verification with fixed seed (0xCAFE_BABE_DEAD_BEEF) for reproducible test execution:
    let (report, artifacts) = vajra_erase::verify::verify_sanitization_with_seed(
        &mut mock_dev,
        &command_ok,
        &sample_lbas,
        0.90, // Sample size ~46 sectors out of 2000 (which do not hit LBA 1500)
        0.05,
        Some(&SanitizeMethod::HostOverwriteSinglePass),
        Some(0xCAFE_BABE_DEAD_BEEF),
    );

    println!("Isolated Layer 5 Override Report:\n{:#?}", report);

    // PROOF OF LAYER 5 ISOLATION:
    // Layers 1, 2, 3, and 4 ALL report PASS:
    assert!(report.layer1.passed, "Layer 1 command report is PASS");
    assert!(report.layer2.passed, "Layer 2 device status is PASS");
    assert!(report.layer3.passed, "Layer 3 sampled sectors are PASS");
    assert!(report.layer4.passed, "Layer 4 statistical sample is PASS");

    // ONLY Layer 5 independent carving discovers the residual PDF at LBA 1500:
    assert!(!report.layer5.passed, "Layer 5 MUST FAIL due to residual artifact");
    assert_eq!(artifacts.len(), 1, "Layer 5 finds exactly 1 recoverable artifact");
    assert_eq!(report.layer5.recovered_artifacts_count, 1);

    // Resolution Override Rule forces overall assurance to FAILED despite Layers 1-4 ALL PASSING:
    assert_eq!(
        report.overall_assurance,
        OverallAssurance::Failed,
        "OVERRIDE RULE: When Layers 1-4 ALL PASS, Layer 5 failure MUST override overall assurance to FAILED!"
    );
    assert!(report.summary_reason.contains("OVERRIDE FAILURE"));
}
