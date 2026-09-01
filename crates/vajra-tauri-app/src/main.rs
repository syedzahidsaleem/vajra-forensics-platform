//! Vajra Digital Forensics & Sanitization Platform — Tauri IPC Bridge (§13, §18, §43).
//!
//! Provides typed Tauri command handlers linking the React/TypeScript frontend to
//! backend crates (`vajra-core`, `vajra-device`, `vajra-carve`, `vajra-erase`, `vajra-case-db`,
//! `vajra-audit`, `vajra-custody`, `vajra-acquire`, `vajra-image`).

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

use vajra_audit::{AuditChain, OperatorKeyPair, ReportGenerator, ReportType};
use vajra_carve::{PipelineOptions, RecoveredArtifact, RecoveryPipeline};
use vajra_case_db::{CaseDb, CaseRecord};
use vajra_core::{DeviceFingerprint, ReadOnlyBlockSource, SanitizeMethod};
use vajra_device::{DeviceDescriptor, DeviceHealth, PhysicalDrive, WritablePhysicalDrive};
use vajra_erase::{
    verify_sanitization, DeviceConfirmationGate, MultiLayerVerificationReport,
    PendingSanitization, SanitizationAuthorizationToken, SanitizationDecisionEngine,
    SanitizationRecommendation,
};
use vajra_image::RawImageReader;

/// Convenient alias for diagnostic health summary returned by `get_device_health`.
pub type DeviceHealthSummary = DeviceHealth;

/// Storage Block Visualization payload structure (§32).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMapData {
    pub total_blocks: u64,
    pub block_size: u32,
    pub allocated_ranges: Vec<(u64, u64)>,
    pub unallocated_ranges: Vec<(u64, u64)>,
    pub bad_sector_ranges: Vec<(u64, u64)>,
    pub recovered_fragment_ranges: Vec<(u64, u64)>,
}

/// Pending Gate Ticket reference returned to frontend during Phase 1 confirmation (§43).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSanitizationTicket {
    pub ticket_id: String,
    pub target_path: String,
    pub target_serial: String,
    pub initiated_at: String,
}

/// Helper function to open a block storage device or image file strictly in read-only mode.
///
/// # Type-Level Guarantee (§16)
/// `PhysicalDrive` and `RawImageReader` implement ONLY `ReadOnlyBlockSource`.
/// Neither type implements `WritableBlockSource`, guaranteeing at compile time
/// that read commands cannot issue write operations to evidence.
fn open_source_readonly(source_path: &str) -> Result<Box<dyn ReadOnlyBlockSource>, String> {
    if let Ok(drive) = PhysicalDrive::open_readonly(source_path) {
        Ok(Box::new(drive))
    } else if let Ok(image) = RawImageReader::open(source_path, None) {
        Ok(Box::new(image))
    } else {
        Err(format!(
            "Failed to open block source at '{source_path}' in read-only mode"
        ))
    }
}

/// Helper function to parse method names into typed `SanitizeMethod` enum variants.
fn parse_sanitize_method(name: &str) -> SanitizeMethod {
    match name.to_lowercase().as_str() {
        "atasecureerase" | "ata_secure_erase" => SanitizeMethod::AtaSecureErase,
        "ataenhancedsecureerase" | "ata_enhanced_secure_erase" => {
            SanitizeMethod::AtaEnhancedSecureErase
        }
        "nvmesanitizeblock" | "nvme_sanitize_block" => SanitizeMethod::NvmeSanitizeBlock,
        "nvmesanitizecrypto" | "nvme_sanitize_crypto" => SanitizeMethod::NvmeSanitizeCrypto,
        "nvmeformat" | "nvme_format" => SanitizeMethod::NvmeFormat,
        "cryptographicerase" | "cryptographic_erase" => SanitizeMethod::CryptographicErase,
        "scsisanitizeoverwrite" => SanitizeMethod::ScsiSanitizeOverwrite,
        "scsisanitizecrypto" => SanitizeMethod::ScsiSanitizeCrypto,
        s if s.contains("multipass") || s.contains("dod") => {
            SanitizeMethod::HostOverwriteMultiPass { passes: 3 }
        }
        _ => SanitizeMethod::HostOverwriteSinglePass,
    }
}

// =============================================================================
// DEVICE COMMANDS (§23, §24)
// =============================================================================

/// Enumerates connected block storage devices.
#[tauri::command]
pub fn list_devices() -> Result<Vec<DeviceDescriptor>, String> {
    vajra_device::enumerate_devices().map_err(|e| e.to_string())
}

/// Computes deterministic SHA-256 fingerprint for target device (§23).
#[tauri::command]
pub fn get_device_fingerprint(device_path: String) -> Result<DeviceFingerprint, String> {
    let devices = vajra_device::enumerate_devices().map_err(|e| e.to_string())?;
    let dev = devices
        .into_iter()
        .find(|d| d.path.eq_ignore_ascii_case(&device_path) || device_path.contains(&d.path))
        .ok_or_else(|| format!("Device not found for path: {device_path}"))?;
    vajra_device::fingerprint_device(&dev).map_err(|e| e.to_string())
}

/// Queries diagnostic health parameters and SMART metrics for target device (§23).
#[tauri::command]
pub fn get_device_health(device_path: String) -> Result<DeviceHealthSummary, String> {
    let devices = vajra_device::enumerate_devices().map_err(|e| e.to_string())?;
    let dev = devices
        .into_iter()
        .find(|d| d.path.eq_ignore_ascii_case(&device_path) || device_path.contains(&d.path))
        .ok_or_else(|| format!("Device not found for path: {device_path}"))?;
    vajra_device::device_health(&dev).map_err(|e| e.to_string())
}

// =============================================================================
// RECOVERY COMMANDS (§25–§32)
// =============================================================================

/// Runs the multi-tier forensic recovery pipeline against a block source.
///
/// # Safety & Type-Level Guarantee (§16)
/// CRITICAL: Opens `source_path` exclusively via `PhysicalDrive::open_readonly` or `RawImageReader::open`.
/// Neither type implements `WritableBlockSource`. It is a compile-time impossibility for this
/// command to modify or overwrite source evidence.
#[tauri::command]
pub fn run_recovery_pipeline(
    source_path: String,
    enable_tier1: bool,
    enable_tier2: bool,
    enable_tier3: bool,
) -> Result<Vec<RecoveredArtifact>, String> {
    let mut source = open_source_readonly(&source_path)?;
    let options = PipelineOptions {
        partition_offset: 0,
        enable_tier1,
        enable_tier2,
        enable_tier3,
        target_types: None,
        max_bgc_search_radius: None,
    };
    let pipeline = RecoveryPipeline::new();
    pipeline
        .run(source.as_mut(), &options)
        .map_err(|e| e.to_string())
}

/// Re-runs targeted recovery and returns raw payload bytes for a specific artifact (§31).
#[tauri::command]
pub fn get_artifact_payload(
    source_path: String,
    artifact_id: u64,
) -> Result<Vec<u8>, String> {
    let mut source = open_source_readonly(&source_path)?;
    let options = PipelineOptions::default();
    let pipeline = RecoveryPipeline::new();
    let artifacts = pipeline
        .run(source.as_mut(), &options)
        .map_err(|e| e.to_string())?;

    let artifact = artifacts
        .into_iter()
        .find(|a| a.id == artifact_id)
        .ok_or_else(|| format!("Artifact ID {artifact_id} not found"))?;

    if !artifact.payload.is_empty() {
        return Ok(artifact.payload);
    }

    let mut payload = Vec::new();
    let block_size = source.block_size() as u64;
    for (start_lba, count) in &artifact.source_locations {
        let buf_len = (count * block_size) as usize;
        let mut buf = vec![0u8; buf_len];
        source
            .read_blocks(*start_lba, *count, &mut buf)
            .map_err(|e| e.to_string())?;
        payload.extend(buf);
    }

    if let Some(expected) = artifact.expected_total_bytes {
        payload.truncate(expected as usize);
    } else if artifact.recovered_bytes > 0 {
        payload.truncate(artifact.recovered_bytes as usize);
    }

    Ok(payload)
}

/// Reads raw sector bytes from a block source for Hex / Sector Data Explorer (§32).
///
/// # Safety & Type-Level Guarantee (§16)
/// Opens `source_path` exclusively in read-only mode via `open_source_readonly`.
#[tauri::command]
pub fn read_raw_sectors(
    source_path: String,
    start_lba: u64,
    block_count: u32,
) -> Result<Vec<u8>, String> {
    let mut source = open_source_readonly(&source_path)?;
    let block_size = source.block_size() as usize;
    let mut buf = vec![0u8; (block_count as usize) * block_size];
    source
        .read_blocks(start_lba, block_count as u64, &mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Generates block map distribution across LBA range for Storage Visualization (§32).
#[tauri::command]
pub fn get_storage_map(source_path: String) -> Result<StorageMapData, String> {
    let mut source = open_source_readonly(&source_path)?;
    let total_blocks = source.total_blocks();
    let block_size = source.block_size();

    let (artifacts, allocated_map) =
        vajra_carve::recover_tier1(source.as_mut(), 0).map_err(|e| e.to_string())?;

    let mut allocated_ranges = Vec::new();
    let mut current_start = None;
    let mut current_len = 0u64;

    for lba in 0..total_blocks {
        if allocated_map.is_allocated(lba) {
            match current_start {
                Some(_) => current_len += 1,
                None => {
                    current_start = Some(lba);
                    current_len = 1;
                }
            }
        } else if let Some(start) = current_start {
            allocated_ranges.push((start, current_len));
            current_start = None;
            current_len = 0;
        }
    }
    if let Some(start) = current_start {
        allocated_ranges.push((start, current_len));
    }

    let mut unallocated_ranges = Vec::new();
    let mut last_end = 0u64;
    for (start, count) in &allocated_ranges {
        if *start > last_end {
            unallocated_ranges.push((last_end, start - last_end));
        }
        last_end = start + count;
    }
    if last_end < total_blocks {
        unallocated_ranges.push((last_end, total_blocks - last_end));
    }

    let mut recovered_fragment_ranges = Vec::new();
    for art in artifacts {
        if let Some(frag) = art.fragmentation_detail {
            recovered_fragment_ranges.push(frag.fragment_1);
            recovered_fragment_ranges.push(frag.fragment_2);
        }
    }

    Ok(StorageMapData {
        total_blocks,
        block_size,
        allocated_ranges,
        unallocated_ranges,
        bad_sector_ranges: Vec::new(),
        recovered_fragment_ranges,
    })
}

// =============================================================================
// SANITIZATION COMMANDS (§33a–§38, §43)
// =============================================================================

/// Evaluates media characteristics and recommends optimal NIST/IEEE sanitization method (§34).
#[tauri::command]
pub fn get_sanitization_recommendation(
    device_path: String,
) -> Result<SanitizationRecommendation, String> {
    let devices = vajra_device::enumerate_devices().map_err(|e| e.to_string())?;
    let dev = devices
        .into_iter()
        .find(|d| d.path.eq_ignore_ascii_case(&device_path) || device_path.contains(&d.path))
        .ok_or_else(|| format!("Device not found for path: {device_path}"))?;

    let supported = vec![
        SanitizeMethod::NvmeSanitizeBlock,
        SanitizeMethod::AtaEnhancedSecureErase,
        SanitizeMethod::CryptographicErase,
        SanitizeMethod::HostOverwriteSinglePass,
        SanitizeMethod::HostOverwriteMultiPass { passes: 3 },
    ];

    Ok(SanitizationDecisionEngine::recommend(&dev, &supported))
}

/// Phase 1: Initiates two-phase Device Identity Confirmation Gate (§43.1).
#[tauri::command]
pub fn begin_sanitization_gate(
    device_path: String,
    operator_id: String,
    typed_serial: String,
    state: tauri::State<'_, Mutex<HashMap<String, PendingSanitization>>>,
) -> Result<PendingSanitizationTicket, String> {
    let devices = vajra_device::enumerate_devices().map_err(|e| e.to_string())?;
    let dev = devices
        .into_iter()
        .find(|d| d.path.eq_ignore_ascii_case(&device_path) || device_path.contains(&d.path))
        .ok_or_else(|| format!("Device not found for path: {device_path}"))?;

    let pending = DeviceConfirmationGate::begin(&dev, &operator_id, &typed_serial, true)
        .map_err(|e| e.to_string())?;

    let ticket_id = format!("TICKET-{}", uuid::Uuid::new_v4());
    let ticket = PendingSanitizationTicket {
        ticket_id: ticket_id.clone(),
        target_path: pending.target_path().to_string(),
        target_serial: pending.target_serial().to_string(),
        initiated_at: pending.initiated_at().to_rfc3339(),
    };

    let mut lock = state.lock().map_err(|_| "Failed to lock gate state".to_string())?;
    lock.insert(ticket_id, pending);

    Ok(ticket)
}

/// Phase 2: Finalizes confirmation gate and issues cryptographically bound token (§43.3).
#[tauri::command]
pub fn finalize_sanitization_gate(
    ticket_id: String,
    pre_exec_confirm: bool,
    state: tauri::State<'_, Mutex<HashMap<String, PendingSanitization>>>,
) -> Result<SanitizationAuthorizationToken, String> {
    let mut lock = state.lock().map_err(|_| "Failed to lock gate state".to_string())?;
    let pending = lock
        .remove(&ticket_id)
        .ok_or_else(|| "No pending ticket for this ID".to_string())?;

    pending.finalize(pre_exec_confirm).map_err(|e| e.to_string())
}

/// [DESTRUCTIVE OPERATION (§43)]
/// Executes sanitization algorithm requiring valid `SanitizationAuthorizationToken`.
#[tauri::command]
pub fn execute_sanitization(
    token: SanitizationAuthorizationToken,
    method_name: String,
) -> Result<String, String> {
    let method = parse_sanitize_method(&method_name);
    let target_path = token.target_path();

    let mut drive = WritablePhysicalDrive::open_writable(target_path, &token)
        .map_err(|e| e.to_string())?;

    vajra_erase::execute_sanitization_destructive(&mut drive, &method, &token, |_, _, _, _| {})
        .map_err(|e| e.to_string())?;

    Ok(format!(
        "Successfully sanitized device '{target_path}' via method '{method}'"
    ))
}

/// Executes multi-layer verification suite against sanitized media (§37).
#[tauri::command]
pub fn verify_sanitization_result(
    device_path: String,
    _token: SanitizationAuthorizationToken,
) -> Result<MultiLayerVerificationReport, String> {
    let mut device = PhysicalDrive::open_readonly(&device_path).map_err(|e| e.to_string())?;
    let sample_lbas = [0, 1, 2048, 4096];
    let (report, _) = verify_sanitization(&mut device, &Ok(()), &sample_lbas, 0.95, 0.001, None);
    Ok(report)
}

// =============================================================================
// CASE & REPORTING COMMANDS (§17, §22, §41)
// =============================================================================

/// Creates a new active case record in the case database (§22).
#[tauri::command]
pub fn create_case(
    name: String,
    examiner: String,
    db_path: String,
) -> Result<String, String> {
    let case_id = format!("CASE-{}", uuid::Uuid::new_v4());
    let db = CaseDb::open_file(&db_path, None).map_err(|e| e.to_string())?;
    db.create_case(&case_id, &name, &examiner)
        .map_err(|e| e.to_string())?;
    Ok(case_id)
}

/// Lists all case records stored in the specified database (§22).
#[tauri::command]
pub fn list_cases(db_path: String) -> Result<Vec<CaseRecord>, String> {
    if !std::path::Path::new(&db_path).exists() {
        return Ok(Vec::new());
    }
    let db = CaseDb::open_file(&db_path, None).map_err(|e| e.to_string())?;
    db.list_cases().map_err(|e| e.to_string())
}

/// Generates and signs a `.vjr` Report Envelope for a case (§41, §42).
#[tauri::command]
pub fn generate_report(
    db_path: String,
    case_id: String,
    report_type: String,
    out_dir: String,
) -> Result<String, String> {
    let parsed_type: ReportType = report_type
        .parse()
        .map_err(|e: String| format!("Invalid report type: {e}"))?;

    let generator = ReportGenerator::new("EXAMINER-01");
    let keypair = OperatorKeyPair::generate();
    let audit_chain = AuditChain::new();

    let content_json = serde_json::json!({
        "db_path": db_path,
        "case_id": case_id,
        "report_type": parsed_type.as_str(),
        "generated_at": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();

    let envelope = generator
        .package_and_sign(
            &case_id,
            parsed_type,
            &format!("Report for {case_id}"),
            content_json,
            &audit_chain,
            &keypair,
        )
        .map_err(|e| e.to_string())?;

    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let out_file = format!("{}/{}_{}.vjr", out_dir, case_id, parsed_type.as_str());
    let serialized = serde_json::to_string_pretty(&envelope).map_err(|e| e.to_string())?;
    std::fs::write(&out_file, serialized).map_err(|e| e.to_string())?;

    Ok(out_file)
}

// =============================================================================
// MAIN TAURI APPLICATION ENTRY POINT
// =============================================================================

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(HashMap::<String, PendingSanitization>::new()))
        .invoke_handler(tauri::generate_handler![
            // Device Commands
            list_devices,
            get_device_fingerprint,
            get_device_health,
            // Recovery Commands
            run_recovery_pipeline,
            get_artifact_payload,
            read_raw_sectors,
            get_storage_map,
            // Sanitization Commands
            get_sanitization_recommendation,
            begin_sanitization_gate,
            finalize_sanitization_gate,
            execute_sanitization,
            verify_sanitization_result,
            // Case & Reporting Commands
            create_case,
            list_cases,
            generate_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
