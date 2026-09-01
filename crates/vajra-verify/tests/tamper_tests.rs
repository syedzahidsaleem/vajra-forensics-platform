//! Independent Verifier Tamper Detection Test Suite (§42, §40).
//!
//! Tests that `vajra-verify` independently validates intact reports and accurately identifies
//! all distinct tampering scenarios with granular, non-generic check failures.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use vajra_verify::models::*;
use vajra_verify::verifier::*;

/// Helper to construct a canonical test report envelope with valid cryptographic bindings.
fn create_valid_test_envelope() -> (VjrEnvelope, SigningKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    // Create a self-signed X.509 cert PEM containing this public key
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Vajra Operator: OP-TEST");
    dn.push(rcgen::DnType::OrganizationName, "Vajra Digital Forensics");

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = dn;

    let secret_bytes = signing_key.to_bytes();
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    pkcs8.extend_from_slice(&secret_bytes);

    let b64 = base64_encode_test(&pkcs8);
    let pem_str = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64);
    let rcgen_key = rcgen::KeyPair::from_pem(&pem_str).unwrap();
    let cert = params.self_signed(&rcgen_key).unwrap();
    let cert_pem = cert.pem();


    let content_json = r#"{
  "case_id": "CASE-2026-TAMPER-TEST",
  "examiner_notes": "Forensic examination of disk image.",
  "findings_count": 4
}"#.to_string();

    let mut hasher = Sha256::new();
    hasher.update(content_json.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let content_sha256 = hex::encode(digest);

    // Sign the 32-byte digest
    let signature = signing_key.sign(&digest);
    let signature_hex = hex::encode(signature.to_bytes());

    let mut entry0 = VjrAuditEntry {
        seq: 1,
        timestamp_utc: "2026-08-31T10:00:00Z".to_string(),
        operator_id: "OP-TEST".to_string(),
        case_id: "CASE-2026-TAMPER-TEST".to_string(),
        operation: "CaseCreated".to_string(),
        target_descriptor: "Case init".to_string(),
        result: "SUCCESS".to_string(),
        prev_hash: GENESIS_PREV_HASH.to_string(),
        entry_hash: String::new(),
    };
    entry0.entry_hash = compute_independent_entry_hash(&entry0);

    let mut entry1 = VjrAuditEntry {
        seq: 2,
        timestamp_utc: "2026-08-31T10:05:00Z".to_string(),
        operator_id: "OP-TEST".to_string(),
        case_id: "CASE-2026-TAMPER-TEST".to_string(),
        operation: "GenerateReport".to_string(),
        target_descriptor: "Report generated".to_string(),
        result: "SUCCESS".to_string(),
        prev_hash: entry0.entry_hash.clone(),
        entry_hash: String::new(),
    };
    entry1.entry_hash = compute_independent_entry_hash(&entry1);

    let envelope = VjrEnvelope {
        report_id: "REP-001".to_string(),
        case_id: "CASE-2026-TAMPER-TEST".to_string(),
        report_type: "ForensicExamination".to_string(),
        title: "Test Forensic Examination Report".to_string(),
        created_at_utc: "2026-08-31T10:05:00Z".to_string(),
        operator_id: "OP-TEST".to_string(),
        tool_version: "0.1.0".to_string(),
        build_id: "VAJRA-CORE-B08".to_string(),
        content_json,
        content_markdown: "# Test Report\nFindings: 4".to_string(),
        content_sha256,
        audit_chain_segment: vec![entry0, entry1],
        signature_hex,
        signing_cert_pem: cert_pem,
        certificate_chain_pem: None,
        trusted_timestamp: VjrTimestampRecord {
            is_rfc3161: false,
            tsa_url: None,
            timestamp_utc: "2026-08-31T10:05:00Z".to_string(),
            token_der_base64: None,
            status_label: "Local timestamp — RFC 3161 unavailable at generation time".to_string(),
        },
        evidence_manifest: Vec::new(),
    };

    (envelope, signing_key)
}

#[test]
fn test_intact_report_all_checks_pass() {
    let (envelope, _) = create_valid_test_envelope();

    // Verify
    let report = verify_report_envelope(&envelope, None);
    println!("{}", report.format_summary());

    assert!(report.content_hash_check.is_pass(), "Content hash must pass");
    assert!(report.certificate_check.is_pass(), "Certificate check must pass");
    assert!(report.audit_chain_check.is_pass(), "Audit chain check must pass");
    assert!(report.timestamp_check.is_pass(), "Timestamp check must pass");
}

#[test]
fn test_tamper_scenario_1_content_modified_without_hash_update() {
    let (mut envelope, _) = create_valid_test_envelope();

    // Tamper: Modify a single character in content_json (e.g. findings_count 4 -> 99)
    envelope.content_json = envelope.content_json.replace("\"findings_count\": 4", "\"findings_count\": 99");

    let report = verify_report_envelope(&envelope, None);
    println!("--- TAMPER SCENARIO 1 RESULT ---");
    println!("{}", report.format_summary());

    assert!(!report.overall_valid, "Tampered report must be marked INVALID");
    assert!(!report.content_hash_check.is_pass(), "Content hash check must fail");
    if let CheckStatus::Fail(ref msg) = report.content_hash_check {
        assert!(msg.contains("Hash mismatch"), "Must report explicit hash mismatch");
    } else {
        panic!("Expected CheckStatus::Fail");
    }
}

#[test]
fn test_tamper_scenario_2_hash_recomputed_without_resigning() {
    let (mut envelope, _) = create_valid_test_envelope();

    // Tamper: Modify content AND update content_sha256 to hide hash mismatch, but do NOT resign
    envelope.content_json = envelope.content_json.replace("\"findings_count\": 4", "\"findings_count\": 99");

    let mut hasher = Sha256::new();
    hasher.update(envelope.content_json.as_bytes());
    envelope.content_sha256 = hex::encode(hasher.finalize());

    let report = verify_report_envelope(&envelope, None);
    println!("--- TAMPER SCENARIO 2 RESULT ---");
    println!("{}", report.format_summary());

    assert!(!report.overall_valid, "Tampered report must be marked INVALID");
    assert!(report.content_hash_check.is_pass(), "Content hash recomputed so passes");
    assert!(!report.digital_signature_check.is_pass(), "Digital signature must fail stale hash");
    if let CheckStatus::Fail(ref msg) = report.digital_signature_check {
        assert!(msg.contains("signature verification failed"), "Must report explicit signature failure");
    } else {
        panic!("Expected CheckStatus::Fail");
    }
}

#[test]
fn test_tamper_scenario_3_signature_from_different_keypair() {
    let (mut envelope, _) = create_valid_test_envelope();

    // Tamper: Sign with a different, unauthorized operator keypair
    let mut csprng = OsRng;
    let imposter_key = SigningKey::generate(&mut csprng);

    let digest_bytes = hex::decode(&envelope.content_sha256).unwrap();
    let imposter_sig = imposter_key.sign(&digest_bytes);
    envelope.signature_hex = hex::encode(imposter_sig.to_bytes());

    let report = verify_report_envelope(&envelope, None);
    println!("--- TAMPER SCENARIO 3 RESULT ---");
    println!("{}", report.format_summary());

    assert!(!report.overall_valid, "Imposter signed report must be marked INVALID");
    assert!(!report.digital_signature_check.is_pass(), "Signature must fail against certificate public key");
}

#[test]
fn test_tamper_scenario_4_audit_chain_entry_modified() {
    let (mut envelope, _) = create_valid_test_envelope();

    // Tamper: Modify entry 0's operation string in the audit chain segment
    envelope.audit_chain_segment[0].operation = "UnauthorizedTamperOp".to_string();

    let report = verify_report_envelope(&envelope, None);
    println!("--- TAMPER SCENARIO 4 RESULT ---");
    println!("{}", report.format_summary());

    assert!(!report.overall_valid, "Audit-tampered report must be marked INVALID");
    assert!(!report.audit_chain_check.is_pass(), "Audit chain check must fail");
    if let CheckStatus::Fail(ref msg) = report.audit_chain_check {
        assert!(msg.contains("Tampered audit entry at seq #1"), "Must report specific broken seq number");
    } else {
        panic!("Expected CheckStatus::Fail");
    }
}

#[test]
fn test_tamper_scenario_5_stripped_or_invalidated_timestamp() {
    let (mut envelope, _) = create_valid_test_envelope();

    // Tamper: Invalidate timestamp status label to unrecognized string
    envelope.trusted_timestamp.status_label = "Tampered Unknown Timestamp Provider".to_string();

    let report = verify_report_envelope(&envelope, None);
    println!("--- TAMPER SCENARIO 5 RESULT ---");
    println!("{}", report.format_summary());

    assert!(!report.overall_valid, "Stripped/unrecognized timestamp must be marked INVALID");
    assert!(!report.timestamp_check.is_pass(), "Timestamp check must fail");
}

fn base64_encode_test(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

