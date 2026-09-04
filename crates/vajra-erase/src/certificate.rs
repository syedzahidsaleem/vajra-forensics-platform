//! Sanitization Certificate Generation (§38).
//!
//! Generates cryptographically verifiable, machine-readable JSON and human-readable text
//! sanitization certificates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vajra_audit::pki::OperatorKeyPair;
use vajra_core::SanitizeMethod;
use vajra_device::DeviceDescriptor;

use crate::verify::{MultiLayerVerificationReport, OverallAssurance};

/// Device metadata embedded in the certificate (§38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDeviceDetails {
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
    pub media_type: String,
    pub interface_type: String,
    pub device_fingerprint: String,
}

/// Verification results summary in certificate (§38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateVerificationSummary {
    pub layer1_command: String,
    pub layer2_status: String,
    pub layer3_deterministic: String,
    pub layer4_statistical: String,
    pub layer5_recovery_scan: String,
    pub overall_assurance: OverallAssurance,
}

/// Cryptographically signed Sanitization Certificate (§38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationCertificate {
    pub certificate_id: String,
    pub device: CertificateDeviceDetails,
    pub method: SanitizeMethod,
    pub standard_reference: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub verification: CertificateVerificationSummary,
    pub residual_risk_warning: Option<String>,
    pub operator_id: String,
    pub certificate_sha256: String,
    pub digital_signature_hex: String,
    pub trusted_timestamp: String,
}

impl SanitizationCertificate {
    /// Generates and signs a Sanitization Certificate (§38).
    pub fn generate(
        device: &DeviceDescriptor,
        method: SanitizeMethod,
        standard_reference: &str,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        report: &MultiLayerVerificationReport,
        operator_id: &str,
        signing_key: Option<&OperatorKeyPair>,
    ) -> Self {
        let cert_id = format!("SAN-{}-{}", Utc::now().format("%Y"), &Uuid::new_v4().to_string()[..8].to_uppercase());

        let dev_details = CertificateDeviceDetails {
            vendor: device.manufacturer.clone(),
            model: device.model.clone(),
            serial: device.serial.clone(),
            capacity_bytes: device.capacity_bytes,
            media_type: device.media_type.to_string(),
            interface_type: device.interface.clone(),
            device_fingerprint: vajra_device::fingerprint_device(device)
                .map(|f| f.sha256_hash)
                .unwrap_or_else(|_| "N/A".to_string()),
        };

        let ver_summary = CertificateVerificationSummary {
            layer1_command: if report.layer1.passed { "PASS".to_string() } else { "FAILED".to_string() },
            layer2_status: if report.layer2.passed { "PASS".to_string() } else { "FAILED".to_string() },
            layer3_deterministic: if report.layer3.passed {
                format!("PASS ({} sample sectors verified clean)", report.layer3.verified_sectors_count)
            } else {
                "FAILED".to_string()
            },
            layer4_statistical: if report.layer4.passed {
                format!("PASS ({:.1}% confidence, {:.2}% defect rate, {} sectors sampled)", report.layer4.params.confidence_c * 100.0, report.layer4.params.assumed_defect_rate_p * 100.0, report.layer4.sampled_sectors_count)
            } else {
                "FAILED".to_string()
            },
            layer5_recovery_scan: if report.layer5.passed {
                "PASS — 0 artifacts recoverable".to_string()
            } else {
                format!("FAILED — {} artifacts recoverable", report.layer5.recovered_artifacts_count)
            },
            overall_assurance: report.overall_assurance,
        };

        // §33a Residual Risk Disclosure for flash-based media subjected to host overwrite:
        let is_flash_media = matches!(
            device.media_type,
            vajra_core::MediaType::Nvme
                | vajra_core::MediaType::SataSsd
                | vajra_core::MediaType::Usb
                | vajra_core::MediaType::SdCard
        );
        let is_host_overwrite = matches!(
            method,
            SanitizeMethod::HostOverwriteSinglePass | SanitizeMethod::HostOverwriteMultiPass { .. }
        );

        let residual_risk_warning = if is_flash_media && is_host_overwrite {
            Some(
                "RESIDUAL RISK DISCLOSURE (§33a, NIST SP 800-88 §2.4): Host-level logical overwrite cannot address unmapped, wear-leveled, or over-provisioned NAND flash blocks managed by the device controller (FTL). Residual raw data may remain accessible via physical chip-off extraction. Overall assurance is structurally capped at MEDIUM."
                    .to_string(),
            )
        } else {
            None
        };

        // Compute SHA-256 of canonical payload
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            cert_id,
            dev_details.serial,
            method,
            standard_reference,
            started_at.to_rfc3339(),
            completed_at.to_rfc3339(),
            ver_summary.overall_assurance
        );

        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let cert_hash = hex::encode(hasher.finalize());

        // Digital signature via vajra-audit Ed25519 keypair
        let signature_hex = if let Some(key) = signing_key {
            let sig_bytes = key.sign(cert_hash.as_bytes());
            hex::encode(sig_bytes)
        } else {
            "UNSIGNED_LOCAL_TEST_KEY".to_string()
        };

        SanitizationCertificate {
            certificate_id: cert_id,
            device: dev_details,
            method,
            standard_reference: standard_reference.to_string(),
            started_at,
            completed_at,
            verification: ver_summary,
            residual_risk_warning,
            operator_id: operator_id.to_string(),
            certificate_sha256: cert_hash,
            digital_signature_hex: signature_hex,
            trusted_timestamp: "Not available — generated offline, local timestamp only".to_string(),
        }
    }

    /// Renders human-readable text representation matching the verbatim §38 specification.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                 VAJRA — SECURE MEDIA SANITIZATION CERTIFICATE\n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Certificate ID: {}\n\n", self.certificate_id));

        out.push_str("Device Details:\n");
        out.push_str(&format!("  Manufacturer: {:<16} Model: {:<16} Serial: {}\n", self.device.vendor, self.device.model, self.device.serial));
        out.push_str(&format!("  Capacity:     {:<16} Interface: {:<12} Media: {}\n", format!("{:.2} GB", self.device.capacity_bytes as f64 / 1_000_000_000.0), self.device.interface_type, self.device.media_type));
        out.push_str(&format!("  Device SHA-256 Fingerprint: {}\n\n", self.device.device_fingerprint));

        out.push_str("Sanitization Execution:\n");
        out.push_str(&format!("  Method:             {}\n", self.method));
        out.push_str(&format!("  Standard Reference: {}\n", self.standard_reference));
        out.push_str(&format!("  Started:            {}\n", self.started_at.to_rfc3339()));
        out.push_str(&format!("  Completed:          {}\n\n", self.completed_at.to_rfc3339()));

        out.push_str("Independent Multi-Layer Verification (§37):\n");
        out.push_str(&format!("  Layer 1 (Command Level):       {}\n", self.verification.layer1_command));
        out.push_str(&format!("  Layer 2 (Device Status):       {}\n", self.verification.layer2_status));
        out.push_str(&format!("  Layer 3 (Deterministic):       {}\n", self.verification.layer3_deterministic));
        out.push_str(&format!("  Layer 4 (Statistical Sample):  {}\n", self.verification.layer4_statistical));
        out.push_str(&format!("  Layer 5 (Recovery-Engine Scan):{}\n\n", self.verification.layer5_recovery_scan));

        out.push_str(&format!("Overall Assurance: {}\n\n", self.verification.overall_assurance));

        if let Some(ref risk) = self.residual_risk_warning {
            out.push_str("Residual Risk Disclosure (§33a):\n");
            out.push_str(&format!("  {}\n\n", risk));
        }

        out.push_str(&format!("Operator ID:             {}\n", self.operator_id));
        out.push_str(&format!("Certificate SHA-256:     {}\n", self.certificate_sha256));
        out.push_str(&format!("Ed25519 Signature:       {}\n", self.digital_signature_hex));
        out.push_str(&format!("Trusted Timestamp:       {}\n", self.trusted_timestamp));
        out.push_str("================================================================================\n");

        out
    }
}
