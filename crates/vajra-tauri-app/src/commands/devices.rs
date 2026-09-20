use serde::{Deserialize, Serialize};
use vajra_device::{device_health, enumerate_devices, fingerprint_device, DeviceDescriptor};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprintDto {
    pub path: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
    pub serial: String,
    pub model: String,
    pub vendor: String,
    pub sector_sample_hash: Option<String>,
    pub computed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHealthDto {
    pub device_path: String,
    pub overall_health: String,
    pub temperature_celsius: Option<i32>,
    pub power_on_hours: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub wear_level_percent: Option<u8>,
    pub is_failing: bool,
    pub recommendation: String,
}

#[tauri::command]
pub fn list_devices() -> Result<Vec<DeviceDescriptor>, String> {
    enumerate_devices().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_device_fingerprint(device_path: String) -> Result<DeviceFingerprintDto, String> {
    let devices = enumerate_devices().map_err(|e| e.to_string())?;
    let target = devices
        .into_iter()
        .find(|d| d.path == device_path)
        .ok_or_else(|| format!("Device not found: {}", device_path))?;

    let fp = fingerprint_device(&target).map_err(|e| e.to_string())?;
    let boundary_hash = if !target.boundary_sample.is_empty() {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&target.boundary_sample);
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };

    Ok(DeviceFingerprintDto {
        path: target.path,
        sha256_hash: fp.sha256_hash,
        size_bytes: target.capacity_bytes,
        serial: target.serial,
        model: target.model,
        vendor: target.manufacturer,
        sector_sample_hash: boundary_hash,
        computed_at: chrono::Utc::now().to_rfc3339(),
    })
}

#[tauri::command]
pub fn get_device_health(device_path: String) -> Result<DeviceHealthDto, String> {
    let devices = enumerate_devices().map_err(|e| e.to_string())?;
    let target = devices
        .into_iter()
        .find(|d| d.path == device_path)
        .ok_or_else(|| format!("Device not found: {}", device_path))?;

    match device_health(&target) {
        Ok(health) => {
            let is_failing = match health.status {
                vajra_device::HealthStatus::Critical => true,
                _ => false,
            };

            let status_str = match health.status {
                vajra_device::HealthStatus::Good => "PASSED",
                vajra_device::HealthStatus::Warning => "WARNING",
                vajra_device::HealthStatus::Critical => "CRITICAL",
                vajra_device::HealthStatus::Unknown => "UNKNOWN",
            };

            let temp = if let Some(ref nvme) = health.nvme_health {
                Some(nvme.temperature_celsius)
            } else if let Some(ref hdd) = health.hdd_health {
                Some(hdd.temperature_celsius)
            } else {
                None
            };

            let hours = if let Some(ref nvme) = health.nvme_health {
                Some(nvme.power_on_hours as u64)
            } else if let Some(ref hdd) = health.hdd_health {
                Some(hdd.power_on_hours)
            } else {
                None
            };

            let wear = if let Some(ref nvme) = health.nvme_health {
                Some(nvme.available_spare_percent)
            } else {
                None
            };

            let reallocated = if let Some(ref hdd) = health.hdd_health {
                Some(hdd.reallocated_sectors)
            } else {
                None
            };

            let pending = if let Some(ref hdd) = health.hdd_health {
                Some(hdd.pending_sectors)
            } else {
                None
            };

            Ok(DeviceHealthDto {
                device_path: target.path,
                overall_health: status_str.to_string(),
                temperature_celsius: temp,
                power_on_hours: hours,
                reallocated_sectors: reallocated,
                pending_sectors: pending,
                wear_level_percent: wear,
                is_failing,
                recommendation: health.recommendation,
            })
        }
        Err(e) => {
            // Graceful non-elevated fallback
            Ok(DeviceHealthDto {
                device_path: target.path,
                overall_health: "UNKNOWN".to_string(),
                temperature_celsius: None,
                power_on_hours: None,
                reallocated_sectors: None,
                pending_sectors: None,
                wear_level_percent: None,
                is_failing: false,
                recommendation: format!("SMART diagnostics limited: {}", e),
            })
        }
    }
}
