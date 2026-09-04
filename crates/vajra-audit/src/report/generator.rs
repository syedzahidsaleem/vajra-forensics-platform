//! Forensic Report Compilation and Signing Engine (§41, §42, §40).
//!
//! Generates structured JSON and Markdown for all six §41 report types,
//! binds RFC 3161 timestamps, signs with Ed25519 / X.509, and records audit log events (§39, §40).

use crate::chain::AuditChain;
use crate::error::AuditError;
use crate::pki::OperatorKeyPair;
use crate::report::model::*;
use crate::report::timestamp::fetch_timestamp_opportunistic;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vajra_case_db::{CaseDb, ReportRecord};

const TOOL_VERSION: &str = "0.1.0";
const BUILD_ID: &str = "VAJRA-CORE-B08";

/// Main report generator and cryptographic packaging engine (§41, §42).
pub struct ReportGenerator {
    operator_keypair: OperatorKeyPair,
    operator_id: String,
    tsa_url: Option<String>,
}

impl ReportGenerator {
    pub fn new(operator_id: &str) -> Self {
        Self {
            operator_keypair: OperatorKeyPair::generate(),
            operator_id: operator_id.to_string(),
            tsa_url: None,
        }
    }

    pub fn with_keypair(operator_id: &str, keypair: OperatorKeyPair) -> Self {
        Self {
            operator_keypair: keypair,
            operator_id: operator_id.to_string(),
            tsa_url: None,
        }
    }

    pub fn with_tsa_url(mut self, url: &str) -> Self {
        self.tsa_url = Some(url.to_string());
        self
    }

    // =========================================================================
    // Core Cryptographic Packaging & Audit Pipeline (§40, §41)
    // =========================================================================

    /// Packages serialized content, computes SHA-256, binds timestamp, signs,
    /// appends to audit log, and creates the finalized `ReportEnvelope`.
    #[allow(clippy::too_many_arguments)]
    pub fn package_and_sign(
        &self,
        case_id: &str,
        report_type: ReportType,
        title: &str,
        content_json: String,
        content_markdown: String,
        evidence_manifest: Vec<EvidenceManifestItem>,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let report_id = Uuid::new_v4().to_string();
        let now_utc = Utc::now().to_rfc3339();

        // 1. Compute Content SHA-256 Digest
        let mut hasher = Sha256::new();
        hasher.update(content_json.as_bytes());
        let digest_bytes: [u8; 32] = hasher.finalize().into();
        let content_sha256 = hex::encode(digest_bytes);

        // 2. Opportunistic RFC 3161 Timestamp Fetch
        let trusted_timestamp = fetch_timestamp_opportunistic(
            &digest_bytes,
            self.tsa_url.as_deref(),
            None,
        );

        // 3. Ed25519 Digital Signature over Content Hash
        let sig_bytes = self.operator_keypair.sign(&digest_bytes);
        let signature_hex = hex::encode(sig_bytes);

        // 4. X.509 Certificate Generation (§40)
        let cert_pem = self.operator_keypair.generate_self_signed_cert(&self.operator_id)?;

        // 5. Append Report Generation Event to Audit Chain (§12.1, §39)
        let audit_desc = format!(
            "Generated {} #{} (SHA256: {})",
            report_type.display_name(),
            report_id,
            content_sha256
        );
        let _ = AuditChain::append(
            db,
            case_id,
            &self.operator_id,
            "GenerateReport",
            &audit_desc,
            "SUCCESS",
        )?;

        // Retrieve current case audit chain segment
        let audit_chain_segment = AuditChain::load_entries(db)?;

        let envelope = ReportEnvelope {
            report_id: report_id.clone(),
            case_id: case_id.to_string(),
            report_type,
            title: title.to_string(),
            created_at_utc: now_utc,
            operator_id: self.operator_id.clone(),
            tool_version: TOOL_VERSION.to_string(),
            build_id: BUILD_ID.to_string(),
            content_json,
            content_markdown,
            content_sha256,
            audit_chain_segment,
            signature_hex: signature_hex.clone(),
            signing_cert_pem: cert_pem.clone(),
            certificate_chain_pem: None,
            trusted_timestamp: trusted_timestamp.clone(),
            evidence_manifest,
        };

        // 6. Persist to Case Database reports table (§22)
        let record = ReportRecord {
            report_id,
            case_id: case_id.to_string(),
            report_type: report_type.as_str().to_string(),
            file_path_pdf: None,
            file_path_json: Some(format!("{}.vjr", envelope.report_id)),
            signature: Some(signature_hex),
            certificate_chain: Some(cert_pem),
            trusted_timestamp: Some(trusted_timestamp.status_label),
        };
        let _ = db.record_report(&record);

        Ok(envelope)
    }

    // =========================================================================
    // Report 1: Forensic Examination Report (§41)
    // =========================================================================

    pub fn generate_forensic_examination_report(
        &self,
        case_id: &str,
        examiner_notes: &str,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let case_record = db.get_case(case_id)?;

        let evidence_items = db.list_evidence_for_case(case_id)?;
        let operations = db.get_operations_for_case(case_id)?;
        let recovered_artifacts = db.get_recovered_artifacts_for_case(case_id)?;
        let forensic_images = db.get_forensic_images_for_case(case_id)?;

        let mut custody_summary = Vec::new();
        for item in &evidence_items {
            if let Ok(events) = db.list_custody_events_for_evidence(&item.evidence_id) {
                custody_summary.extend(events);
            }
        }

        let payload = ForensicExamPayload {
            case_id: case_record.case_id.clone(),
            case_name: case_record.case_name.clone(),
            investigator_id: case_record.investigator_id.clone(),
            created_at: case_record.created_at.clone(),
            case_status: case_record.status.to_string(),
            evidence_items: evidence_items.clone(),
            operations,
            recovered_artifacts: recovered_artifacts.clone(),
            custody_summary,
            examiner_notes: examiner_notes.to_string(),
        };

        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# FORENSIC EXAMINATION REPORT\n\n");
        md.push_str(&format!("**Case ID:** {}\n", payload.case_id));
        md.push_str(&format!("**Case Name:** {}\n", payload.case_name));
        md.push_str(&format!("**Lead Investigator:** {}\n", payload.investigator_id));
        md.push_str(&format!("**Case Status:** {}\n\n", payload.case_status));

        md.push_str("## 1. Registered Evidence Items\n\n");
        md.push_str("| Evidence ID | Serial | Manufacturer | Model | Capacity | Interface | Fingerprint (SHA-256) |\n");
        md.push_str("|---|---|---|---|---|---|---|\n");
        for item in &payload.evidence_items {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} MB | {} | `{}` |\n",
                item.evidence_id, item.device_serial, item.manufacturer, item.model,
                item.capacity_bytes / (1024 * 1024), item.interface, item.device_fingerprint_hash
            ));
        }

        md.push_str("\n## 2. Recovered Artifacts Summary\n\n");
        md.push_str(&format!("**Total Recovered Artifacts:** {}\n\n", payload.recovered_artifacts.len()));
        md.push_str("| Artifact ID | Type | Tier | Confidence | Original Path | Recovered Path |\n");
        md.push_str("|---|---|---|---|---|---|\n");
        for art in &payload.recovered_artifacts {
            md.push_str(&format!(
                "| {} | {} | Tier {} | {:.1}% | {} | {} |\n",
                art.artifact_id, art.file_type, art.recovery_tier,
                art.confidence_score * 100.0,
                art.original_path.as_deref().unwrap_or("-"),
                art.recovered_path
            ));
        }

        md.push_str("\n## 3. Examiner Notes & Analysis\n\n");
        md.push_str(examiner_notes);
        md.push_str("\n\n---\n*Designed for forensic defensibility per Vajra Master Blueprint §41.*");

        let mut manifest = Vec::new();
        for img in forensic_images {
            manifest.push(EvidenceManifestItem {
                evidence_id: img.evidence_id,
                file_name: img.file_path,
                sha256_hash: img.acquisition_hash,
                size_bytes: 0,
            });
        }

        self.package_and_sign(
            case_id,
            ReportType::ForensicExamination,
            &format!("Forensic Examination Report — Case {}", case_id),
            content_json,
            md,
            manifest,
            db,
        )
    }

    // =========================================================================
    // Report 2: Sanitization Certificate (§38, §41)
    // =========================================================================

    pub fn generate_sanitization_certificate_report(
        &self,
        case_id: &str,
        cert: SanitizationCertData,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let payload = SanitizationCertPayload {
            certificate: cert.clone(),
        };

        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# DATA SANITIZATION CERTIFICATE\n\n");
        md.push_str(&format!("**Certificate ID:** {}\n", cert.certificate_id));
        md.push_str(&format!("**Device Serial:** {}\n", cert.device_serial));
        md.push_str(&format!("**Device Model:** {} ({})\n", cert.model, cert.manufacturer));
        md.push_str(&format!("**Media Type:** {}\n", cert.media_type));
        md.push_str(&format!("**Capacity:** {} bytes\n", cert.capacity_bytes));
        md.push_str(&format!("**Method:** {}\n", cert.sanitization_method));
        md.push_str(&format!("**Standard Reference:** {}\n\n", cert.standard_reference));

        md.push_str("## Multi-Layer Verification Results (§37)\n\n");
        md.push_str(&format!("- Layer 1 (Controller Confirmation): {}\n", cert.layer1_controller_confirmation));
        md.push_str(&format!("- Layer 2 (Readback Sample Verification): {}\n", cert.layer2_readback_samples));
        md.push_str(&format!("- Layer 3 (Full Surface Read Verification): {}\n", cert.layer3_full_read));
        md.push_str(&format!("- Layer 4 (Entropy/Statistical Scan): {}\n", cert.layer4_entropy_analysis));
        md.push_str(&format!("- Layer 5 (Independent Recovery Scan): {}\n\n", cert.layer5_recovery_carve));

        md.push_str(&format!("**Overall Assurance Level:** {}\n", cert.overall_assurance));
        if let Some(ref note) = cert.assurance_justification {
            md.push_str(&format!("**Assurance Note:** {}\n", note));
        }

        self.package_and_sign(
            case_id,
            ReportType::SanitizationCertificate,
            &format!("Sanitization Certificate — Device {}", cert.device_serial),
            content_json,
            md,
            Vec::new(),
            db,
        )
    }

    // =========================================================================
    // Report 3: Acquisition Report (§41)
    // =========================================================================

    pub fn generate_acquisition_report(
        &self,
        case_id: &str,
        payload: AcquisitionReportPayload,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# FORENSIC ACQUISITION REPORT\n\n");
        md.push_str(&format!("**Case ID:** {}\n", payload.case_id));
        md.push_str(&format!("**Evidence ID:** {}\n", payload.evidence_id));
        md.push_str(&format!("**Device Serial:** {}\n", payload.device_serial));
        md.push_str(&format!("**Make / Model:** {} {}\n", payload.manufacturer, payload.model));
        md.push_str(&format!("**Capacity:** {} bytes\n", payload.capacity_bytes));
        md.push_str(&format!("**Device Fingerprint:** `{}`\n\n", payload.device_fingerprint_hash));

        md.push_str("## Image Integrity Details\n\n");
        md.push_str(&format!("- **Image Format:** {}\n", payload.image_format));
        md.push_str(&format!("- **Destination File:** {}\n", payload.image_file_path));
        md.push_str(&format!("- **Acquisition Hash (SHA-256):** `{}`\n", payload.acquisition_hash_sha256));
        if let Some(ref ver_hash) = payload.verification_hash_sha256 {
            md.push_str(&format!("- **Verification Hash (SHA-256):** `{}`\n", ver_hash));
            md.push_str(&format!("- **Re-Read Match Status:** {}\n", if payload.re_read_verified { "MATCH / VERIFIED" } else { "MISMATCH" }));
        }

        md.push_str("\n## Bad Sector Map (§20)\n\n");
        md.push_str(&format!("- **Total Scanned Sectors:** {}\n", payload.total_sectors));
        md.push_str(&format!("- **Unreadable / Bad Sectors:** {}\n", payload.bad_sector_count));
        if payload.bad_sector_count > 0 {
            md.push_str("- **Bad LBA Ranges:**\n");
            for (start, count) in &payload.bad_sector_ranges {
                md.push_str(&format!("  * LBA {} .. {}\n", start, start + count));
            }
        } else {
            md.push_str("- **Sector Status:** 100% clean physical read (0 bad sectors encountered).\n");
        }

        let manifest = vec![EvidenceManifestItem {
            evidence_id: payload.evidence_id.clone(),
            file_name: payload.image_file_path.clone(),
            sha256_hash: payload.acquisition_hash_sha256.clone(),
            size_bytes: payload.capacity_bytes,
        }];

        self.package_and_sign(
            case_id,
            ReportType::AcquisitionReport,
            &format!("Acquisition Report — Evidence {}", payload.evidence_id),
            content_json,
            md,
            manifest,
            db,
        )
    }

    // =========================================================================
    // Report 4: Recovery Report (§31, §41)
    // =========================================================================

    pub fn generate_recovery_report(
        &self,
        case_id: &str,
        payload: RecoveryReportPayload,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# FILE RECOVERY & CARVING REPORT\n\n");
        md.push_str(&format!("**Case ID:** {}\n", payload.case_id));
        md.push_str(&format!("**Target Source:** {}\n", payload.target_source));
        md.push_str(&format!("**Partition Offset:** LBA {}\n", payload.partition_offset_lba));
        md.push_str(&format!("**Recovery Tiers Active:** {}\n\n", payload.tiers_executed.join(", ")));

        md.push_str("## Recovery Statistics Summary\n\n");
        md.push_str(&format!("- **Total Recovered Files:** {}\n", payload.total_recovered_artifacts));
        md.push_str(&format!("  * Tier 1 (Metadata Recovery): {}\n", payload.tier1_count));
        md.push_str(&format!("  * Tier 2 (Signature + Structural Validation): {}\n", payload.tier2_count));
        md.push_str(&format!("  * Tier 3 (Bifragment Gap Carving): {}\n\n", payload.tier3_count));

        md.push_str("## Recovered Artifacts & Provenance (§31)\n\n");
        for art in &payload.artifacts {
            md.push_str(&format!("### Artifact #R-{}: {}\n", art.id, art.filename_guess.as_deref().unwrap_or(&art.file_type)));
            md.push_str(&format!("- **Recovery Tier:** Tier {}\n", art.recovery_tier));
            md.push_str(&format!("- **Size:** {} bytes\n", art.recovered_bytes));
            md.push_str(&format!("- **SHA-256:** `{}`\n", art.content_hash));
            md.push_str(&format!("- **Confidence Score:** {:.1}%\n", art.confidence_score * 100.0));
            md.push_str(&format!("  * Structural: {:.1}% | Meta: {:.1}% | Entropy: {:.1}%\n",
                art.structural_score * 100.0,
                art.metadata_score * 100.0,
                art.entropy_score * 100.0
            ));
            if let Some(ref basis) = art.explainability {
                md.push_str(&format!("  * **ML Signal Basis:** {}\n", basis));
            }
            if let Some(ref lim) = art.limitations {
                md.push_str(&format!("- **Limitations:** {}\n", lim));
            }
            md.push('\n');
        }


        self.package_and_sign(
            case_id,
            ReportType::RecoveryReport,
            &format!("Recovery Report — Case {}", case_id),
            content_json,
            md,
            Vec::new(),
            db,
        )
    }

    // =========================================================================
    // Report 5: Device Health Report (§23, §41)
    // =========================================================================

    pub fn generate_device_health_report(
        &self,
        case_id: &str,
        payload: DeviceHealthPayload,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# DEVICE HEALTH DIAGNOSTICS REPORT\n\n");
        md.push_str(&format!("**Case ID:** {}\n", payload.case_id));
        md.push_str(&format!("**Device Path:** {}\n", payload.device_path));
        md.push_str(&format!("**Serial Number:** {}\n", payload.serial));
        md.push_str(&format!("**Make / Model:** {} {}\n", payload.vendor, payload.model));
        md.push_str(&format!("**Interface / Media:** {} / {}\n", payload.interface, payload.media_type));
        md.push_str(&format!("**Capacity:** {} bytes\n", payload.capacity_bytes));
        md.push_str(&format!("**Device Fingerprint:** `{}`\n\n", payload.device_fingerprint_hash));

        md.push_str("## SMART / NVMe Diagnostics (§23)\n\n");
        md.push_str(&format!("- **Overall Health Status:** {}\n", payload.health_status));
        if let Some(temp) = payload.temperature_celsius {
            md.push_str(&format!("- **Temperature:** {} °C\n", temp));
        }
        if let Some(poh) = payload.power_on_hours {
            md.push_str(&format!("- **Power-On Hours:** {} hours\n", poh));
        }
        if let Some(cycles) = payload.power_cycles {
            md.push_str(&format!("- **Power Cycles:** {}\n", cycles));
        }

        md.push_str("\n## Decision Engine Assessment (§34)\n\n");
        md.push_str(&format!("**Recommendation:** {}\n", payload.decision_engine_recommendation));

        self.package_and_sign(
            case_id,
            ReportType::DeviceHealthReport,
            &format!("Device Health Report — Device {}", payload.serial),
            content_json,
            md,
            Vec::new(),
            db,
        )
    }

    // =========================================================================
    // Report 6: Chain of Custody Report (§21, §41)
    // =========================================================================

    pub fn generate_chain_of_custody_report(
        &self,
        case_id: &str,
        payload: ChainOfCustodyPayload,
        db: &CaseDb,
    ) -> Result<ReportEnvelope, AuditError> {
        let content_json = serde_json::to_string_pretty(&payload)?;

        let mut md = String::new();
        md.push_str("# CHAIN OF CUSTODY REPORT\n\n");
        md.push_str(&format!("**Case ID:** {}\n", payload.case_id));
        md.push_str(&format!("**Evidence ID:** {}\n", payload.evidence_id));
        md.push_str(&format!("**Device Serial:** {}\n", payload.device_serial));
        md.push_str(&format!("**Make / Model:** {} {}\n", payload.manufacturer, payload.model));
        md.push_str(&format!("**Current Custody Owner:** {}\n", payload.current_owner));
        md.push_str(&format!("**Current Location:** {}\n", payload.current_location));
        md.push_str(&format!("**Physical Condition:** {}\n\n", payload.physical_condition));

        md.push_str("## Chronological Custody Ledger (§21)\n\n");
        md.push_str("| Timestamp (UTC) | Action | From | To | Location | Purpose | Condition |\n");
        md.push_str("|---|---|---|---|---|---|---|\n");
        for ev in &payload.events {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                ev.timestamp_utc, ev.event_type,
                ev.from_party.as_deref().unwrap_or("-"),
                ev.to_party.as_deref().unwrap_or("-"),
                ev.location.as_deref().unwrap_or("-"),
                ev.purpose.as_deref().unwrap_or("-"),
                ev.evidence_condition.as_deref().unwrap_or("-")
            ));
        }

        self.package_and_sign(
            case_id,
            ReportType::ChainOfCustodyReport,
            &format!("Chain of Custody Report — Evidence {}", payload.evidence_id),
            content_json,
            md,
            Vec::new(),
            db,
        )
    }
}
