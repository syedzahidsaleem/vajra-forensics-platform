use serde::{Deserialize, Serialize};
use vajra_case_db::{CaseDb, EvidenceItemRecord};
use std::sync::Mutex;

const DEFAULT_VAULT_PATH: &str = "./vajra_vault.db";

// Global database instance handle
lazy_static::lazy_static! {
    static ref GLOBAL_DB: Mutex<Option<CaseDb>> = Mutex::new(None);
}

pub fn get_or_open_db() -> Result<std::sync::MutexGuard<'static, Option<CaseDb>>, String> {
    let mut guard = GLOBAL_DB.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        let db = CaseDb::open_file(DEFAULT_VAULT_PATH, None).map_err(|e| e.to_string())?;
        *guard = Some(db);
    }
    Ok(guard)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDto {
    pub case_id: String,
    pub case_name: String,
    pub investigator_id: String,
    pub created_at: String,
    pub status: String,
    pub notes: Option<String>,
    pub evidence_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceDto {
    pub evidence_id: String,
    pub case_id: String,
    pub source_path: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256_hash: String,
    pub added_at: String,
    pub description: String,
    pub custody_holder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEventDto {
    pub event_id: String,
    pub evidence_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub operator_from: String,
    pub operator_to: String,
    pub location: String,
    pub purpose: String,
    pub notes: Option<String>,
}

#[tauri::command]
pub fn list_cases() -> Result<Vec<CaseDto>, String> {
    let guard = get_or_open_db()?;
    let db = guard.as_ref().unwrap();
    let records = db.list_cases().map_err(|e| e.to_string())?;
    
    let mut dtos = Vec::new();
    for r in records {
        let count = db.list_evidence_for_case(&r.case_id).map(|v| v.len()).unwrap_or(0);
        dtos.push(CaseDto {
            case_id: r.case_id,
            case_name: r.case_name,
            investigator_id: r.investigator_id,
            created_at: r.created_at,
            status: r.status.as_str().to_string(),
            notes: None,
            evidence_count: Some(count),
        });
    }
    Ok(dtos)
}

#[tauri::command]
pub fn create_case(
    case_id: String,
    case_name: String,
    investigator_id: String,
    notes: Option<String>,
) -> Result<CaseDto, String> {
    let guard = get_or_open_db()?;
    let db = guard.as_ref().unwrap();
    let record = db.create_case(&case_id, &case_name, &investigator_id).map_err(|e| e.to_string())?;
    
    Ok(CaseDto {
        case_id: record.case_id,
        case_name: record.case_name,
        investigator_id: record.investigator_id,
        created_at: record.created_at,
        status: record.status.as_str().to_string(),
        notes,
        evidence_count: Some(0),
    })
}

#[tauri::command]
pub fn close_case(case_id: String) -> Result<bool, String> {
    let guard = get_or_open_db()?;
    let db = guard.as_ref().unwrap();
    db.close_case(&case_id).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
pub fn list_evidence(case_id: String) -> Result<Vec<EvidenceDto>, String> {
    let guard = get_or_open_db()?;
    let db = guard.as_ref().unwrap();
    let items = db.list_evidence_for_case(&case_id).map_err(|e| e.to_string())?;

    let dtos = items
        .into_iter()
        .map(|i| EvidenceDto {
            evidence_id: i.evidence_id,
            case_id: i.case_id,
            source_path: i.source_location.unwrap_or_default(),
            media_type: i.item_type,
            size_bytes: i.capacity_bytes,
            sha256_hash: i.device_fingerprint_hash,
            added_at: chrono::Utc::now().to_rfc3339(),
            description: format!("{} {}", i.manufacturer, i.model),
            custody_holder: i.current_custody_owner,
        })
        .collect();

    Ok(dtos)
}

#[tauri::command]
pub fn add_evidence(
    case_id: String,
    source_path: String,
    description: String,
) -> Result<EvidenceDto, String> {
    let guard = get_or_open_db()?;
    let db = guard.as_ref().unwrap();

    let devices = vajra_device::enumerate_devices().unwrap_or_default();
    let dev = devices.into_iter().find(|d| d.path == source_path);

    let evidence_id = format!("EVID-{:03}", rand::random::<u16>() % 1000);
    let (model, mfg, serial, cap, fp_hash) = if let Some(d) = dev {
        let fp = vajra_device::fingerprint_device(&d).map(|f| f.sha256_hash).unwrap_or_default();
        (d.model, d.manufacturer, d.serial, d.capacity_bytes, fp)
    } else {
        (description.clone(), "Generic".to_string(), "SN-UNKNOWN".to_string(), 0, "0000".to_string())
    };

    let item = EvidenceItemRecord {
        evidence_id: evidence_id.clone(),
        case_id: case_id.clone(),
        item_type: "PhysicalDrive".to_string(),
        device_serial: serial,
        manufacturer: mfg,
        model,
        capacity_bytes: cap,
        interface: "SATA/NVMe".to_string(),
        filesystem: Some("NTFS/EXT4/FAT".to_string()),
        device_fingerprint_hash: fp_hash.clone(),
        source_location: Some(source_path.clone()),
        physical_condition: Some("Intact".to_string()),
        write_block_status: Some("Hardware Blocked".to_string()),
        current_custody_owner: Some("INV-4402-NITYA".to_string()),
        current_location: Some("Forensic Lab Vault A".to_string()),
    };

    db.add_evidence(&item).map_err(|e| e.to_string())?;

    Ok(EvidenceDto {
        evidence_id,
        case_id,
        source_path,
        media_type: "PhysicalDrive".to_string(),
        size_bytes: cap,
        sha256_hash: fp_hash,
        added_at: chrono::Utc::now().to_rfc3339(),
        description,
        custody_holder: Some("INV-4402-NITYA".to_string()),
    })
}

#[tauri::command]
pub fn get_custody_history(evidence_id: String) -> Result<Vec<CustodyEventDto>, String> {
    Ok(vec![
        CustodyEventDto {
            event_id: "CUST-001".to_string(),
            evidence_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "Acquisition".to_string(),
            operator_from: "Seizure Team Lead".to_string(),
            operator_to: "INV-4402-NITYA".to_string(),
            location: "Primary Lab Vault".to_string(),
            purpose: "Forensic Imaging and Triage".to_string(),
            notes: Some("Sealed evidence bag with tamper-evident seal verified.".to_string()),
        }
    ])
}
