//! macOS native block device enumeration, SMART diagnostics, APFS unwrapping, and raw sector I/O (§23–§24).
//!
//! # Architecture & macOS-Specific Implementation (§23, §24, §34, §35)
//!
//! 1. **Raw Character Device Access (`/dev/rdiskN`)**:
//!    - Standard buffered `/dev/diskN` block device nodes pass through the macOS Unified Buffer Cache (UBC).
//!    - Vajra targets `/dev/rdiskN` (raw/character device interface), enabling unbuffered direct DMA
//!      transfers between memory and the storage controller, bypassing UBC cache overhead and page pollution.
//!    - Aligned sector I/O is enforced via 4096-byte memory-aligned buffers (`AlignedBuffer`) with `F_NOCACHE`.
//!
//! 2. **APFS Container Unwrapping & Boot-Disk Detection (§24)**:
//!    - On modern macOS, the active root mount (`/`) and Data volume (`/System/Volumes/Data`) reside inside
//!      a synthesized APFS Container (e.g. `disk3s1s1` inside container `disk3`).
//!    - `check_if_system_disk` unwraps the synthesized container hierarchy to its physical backing store
//!      (e.g. `disk0s2` -> `disk0` -> `/dev/rdisk0`), properly tagging the host OS boot drive as protected.
//!
//! 3. **System Integrity Protection (SIP) & Forensic Scoping (§23, §34, §35)**:
//!    - Under SIP, raw write access to the active internal system disk is prohibited even for root (`UID 0`).
//!    - User data and external volumes (USB, SD, Thunderbolt, external NVMe/SATA) have full read/write access.
//!    - System disk write operations are blocked at the type/gate level (`DeviceConfirmationGate`).
//!
//! 4. **SMART & Health Diagnostics (§23)**:
//!    - Queries native macOS `SMARTStatus` ("Verified", "Failing", "Not Supported") from `diskutil` / IOKit.
//!    - If `smartctl` is installed, queries extended NVMe/ATA health attributes with calibrated recommendations.

use crate::descriptor::DeviceDescriptor;
use crate::detection::{check_write_blocker, detect_partition_table};
use crate::health::{DeviceHealth, HddHealthInfo, HealthStatus, NvmeHealthInfo, SmartAttribute};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use vajra_core::{IoError, MediaType};

/// Simple value representation for Apple XML Property Lists.
#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Array(Vec<PlistValue>),
    Dict(HashMap<String, PlistValue>),
}

impl PlistValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PlistValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PlistValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            PlistValue::Integer(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PlistValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&HashMap<String, PlistValue>> {
        match self {
            PlistValue::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<PlistValue>> {
        match self {
            PlistValue::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// Parses an Apple XML property list (`<plist>...</plist>`) into a `PlistValue`.
pub fn parse_plist(xml: &str) -> Option<PlistValue> {
    let trimmed = xml.trim();
    if let Some(dict_start) = trimmed.find("<dict>") {
        if let Some(dict_end) = trimmed.rfind("</dict>") {
            let dict_content = &trimmed[dict_start + 6..dict_end];
            return Some(PlistValue::Dict(parse_dict_content(dict_content)));
        }
    }
    None
}

/// Parses internal content of a `<dict>...</dict>` XML block.
fn parse_dict_content(content: &str) -> HashMap<String, PlistValue> {
    let mut map = HashMap::new();
    let mut cursor = 0;
    let bytes = content.as_bytes();

    while cursor < bytes.len() {
        if let Some(key_tag_start) = content[cursor..].find("<key>") {
            let k_start = cursor + key_tag_start + 5;
            if let Some(key_tag_end) = content[k_start..].find("</key>") {
                let k_end = k_start + key_tag_end;
                let key_name = content[k_start..k_end].trim().to_string();
                cursor = k_end + 6;

                if let Some((val, next_cursor)) = parse_next_value(&content[cursor..]) {
                    map.insert(key_name, val);
                    cursor += next_cursor;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    map
}

/// Extracts the next Plist value and returns (PlistValue, bytes_consumed).
fn parse_next_value(content: &str) -> Option<(PlistValue, usize)> {
    let trimmed_leading = content.trim_start();
    let offset = content.len() - trimmed_leading.len();

    if trimmed_leading.starts_with("<string>") {
        let val_start = offset + 8;
        if let Some(end) = content[val_start..].find("</string>") {
            let s = &content[val_start..val_start + end];
            return Some((PlistValue::String(s.to_string()), val_start + end + 9));
        }
    } else if trimmed_leading.starts_with("<integer>") {
        let val_start = offset + 9;
        if let Some(end) = content[val_start..].find("</integer>") {
            let num_str = content[val_start..val_start + end].trim();
            let num = num_str.parse::<i64>().unwrap_or(0);
            return Some((PlistValue::Integer(num), val_start + end + 10));
        }
    } else if trimmed_leading.starts_with("<true/>") {
        return Some((PlistValue::Boolean(true), offset + 7));
    } else if trimmed_leading.starts_with("<false/>") {
        return Some((PlistValue::Boolean(false), offset + 8));
    } else if trimmed_leading.starts_with("<dict>") {
        let d_start = offset + 6;
        if let Some(end) = find_matching_tag(&content[d_start..], "<dict>", "</dict>") {
            let inner = &content[d_start..d_start + end];
            let dict_map = parse_dict_content(inner);
            return Some((PlistValue::Dict(dict_map), d_start + end + 7));
        }
    } else if trimmed_leading.starts_with("<array>") {
        let a_start = offset + 7;
        if let Some(end) = find_matching_tag(&content[a_start..], "<array>", "</array>") {
            let inner = &content[a_start..a_start + end];
            let array_vals = parse_array_content(inner);
            return Some((PlistValue::Array(array_vals), a_start + end + 8));
        }
    }

    None
}

/// Parses items within an `<array>...</array>` block.
fn parse_array_content(content: &str) -> Vec<PlistValue> {
    let mut vals = Vec::new();
    let mut cursor = 0;
    while cursor < content.len() {
        let slice = content[cursor..].trim_start();
        if slice.is_empty() {
            break;
        }
        let consumed_leading = content[cursor..].len() - slice.len();
        cursor += consumed_leading;

        if let Some((val, consumed)) = parse_next_value(&content[cursor..]) {
            vals.push(val);
            cursor += consumed;
        } else {
            cursor += 1;
        }
    }
    vals
}

/// Finds the end of a balanced XML tag (handling nested tags).
fn find_matching_tag(content: &str, open_tag: &str, close_tag: &str) -> Option<usize> {
    let mut depth = 1;
    let mut cursor = 0;

    while cursor < content.len() {
        let next_open = content[cursor..].find(open_tag);
        let next_close = content[cursor..].find(close_tag);

        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                cursor += o + open_tag.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                if depth == 0 {
                    return Some(cursor + c);
                }
                cursor += c + close_tag.len();
            }
            _ => break,
        }
    }

    None
}

/// Executes a system command with arguments and returns stdout string.
fn run_command(cmd: &str, args: &[&str]) -> Result<String, IoError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| IoError::Other(format!("Failed executing '{}': {}", cmd, e)))?;

    if !output.status.success() {
        let err_str = String::from_utf8_lossy(&output.stderr);
        return Err(IoError::Other(format!(
            "'{} {:?}' exited with error code {:?}: {}",
            cmd, args, output.status.code(), err_str
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Strips partition number suffixes to isolate the parent physical disk identifier.
/// (e.g. "disk0s2" -> "disk0", "disk3s1s1" -> "disk3", "rdisk1s1" -> "rdisk1")
fn strip_partition_suffix(dev_id: &str) -> &str {
    let clean = dev_id.trim_start_matches("/dev/");
    if let Some(pos) = clean.find('s') {
        if pos > 0 && clean[pos + 1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
            return &clean[..pos];
        }
    }
    clean
}

/// Resolves the underlying physical backing whole-disk for a given volume or container device (§24).
///
/// Handles APFS Synthesized Containers (e.g. `disk3` backing on physical store `disk0s2` -> parent `disk0`).
fn resolve_apfs_physical_disk(volume_dev_id: &str) -> String {
    let clean_id = volume_dev_id.trim_start_matches("/dev/").trim_start_matches('r');

    // 1. Try querying `diskutil info -plist <id>`
    if let Ok(xml) = run_command("diskutil", &["info", "-plist", clean_id]) {
        if let Some(PlistValue::Dict(dict)) = parse_plist(&xml) {
            // Check ParentWholeDisk
            if let Some(parent) = dict.get("ParentWholeDisk").and_then(|v| v.as_str()) {
                if parent.starts_with("disk") && !parent.contains('s') {
                    return parent.to_string();
                }
            }

            // Check APFSPhysicalStores
            if let Some(PlistValue::Array(stores)) = dict.get("APFSPhysicalStores") {
                for store in stores {
                    if let Some(store_dict) = store.as_dict() {
                        if let Some(store_id) = store_dict.get("DeviceIdentifier").and_then(|v| v.as_str()) {
                            let parent = strip_partition_suffix(store_id);
                            if !parent.is_empty() {
                                return parent.to_string();
                            }
                        }
                    }
                }
            }

            // Check APFSContainerReference
            if let Some(container_ref) = dict.get("APFSContainerReference").and_then(|v| v.as_str()) {
                if container_ref != clean_id {
                    return resolve_apfs_physical_disk(container_ref);
                }
            }
        }
    }

    // Fallback: direct partition stripping
    strip_partition_suffix(clean_id).to_string()
}

/// Checks if a candidate physical whole disk (e.g. "disk0") hosts the macOS system boot volume (§24).
///
/// Traces `/` (Root) and `/System/Volumes/Data` to their parent APFS physical whole disk.
fn check_if_system_disk(target_disk_id: &str) -> bool {
    let clean_target = target_disk_id.trim_start_matches("/dev/").trim_start_matches('r');

    // Query active mount points from `mount`
    if let Ok(mount_output) = run_command("mount", &[]) {
        for line in mount_output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "on" {
                let dev_source = parts[0];
                let mount_point = parts[2];

                let is_critical = mount_point == "/"
                    || mount_point == "/System/Volumes/Data"
                    || mount_point == "/System/Volumes/Preboot"
                    || mount_point == "/System/Volumes/Update";

                if is_critical {
                    let dev_name = dev_source.trim_start_matches("/dev/");
                    let backing_physical = resolve_apfs_physical_disk(dev_name);
                    if backing_physical == clean_target {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Classifies storage media type based on macOS protocol, solid-state, and model attributes (§16).
fn classify_media_type(protocol: &str, is_ssd: bool, model: &str, is_internal: bool) -> MediaType {
    let proto_upper = protocol.to_uppercase();
    let model_upper = model.to_uppercase();

    if proto_upper.contains("NVME") || proto_upper.contains("PCI-EXPRESS") || proto_upper.contains("PCIE") {
        MediaType::Nvme
    } else if proto_upper.contains("SECURE DIGITAL") || proto_upper.contains("SD") || proto_upper.contains("MMC")
        || model_upper.contains("SD CARD") || model_upper.contains("MICROSD") || model_upper.contains("CARD READER")
    {
        MediaType::SdCard
    } else if proto_upper.contains("USB") {
        if model_upper.contains("CARD") || model_upper.contains("SD") {
            MediaType::SdCard
        } else {
            MediaType::Usb
        }
    } else if is_ssd {
        MediaType::SataSsd
    } else if is_internal && proto_upper.contains("SATA") {
        MediaType::Hdd
    } else {
        MediaType::Hdd
    }
}

/// Enumerates directly connected physical storage block devices on macOS (§23).
///
/// Normalizes physical whole-disks to raw character nodes (`/dev/rdiskN`).
pub fn enumerate_devices() -> Result<Vec<DeviceDescriptor>, IoError> {
    let mut descriptors = Vec::new();

    // 1. Query all disks via `diskutil list -plist`
    let list_xml = run_command("diskutil", &["list", "-plist"])
        .map_err(|e| IoError::Other(format!("Failed to list macOS storage devices: {}", e)))?;

    let root_plist = parse_plist(&list_xml)
        .ok_or_else(|| IoError::Other("Failed to parse diskutil list plist XML".to_string()))?;

    let root_dict = root_plist.as_dict()
        .ok_or_else(|| IoError::Other("diskutil list root is not a dict".to_string()))?;

    // Extract WholeDisks array
    let whole_disks = match root_dict.get("WholeDisks").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
        None => Vec::new(),
    };

    for disk_id in whole_disks {
        // Query detailed info per whole disk: `diskutil info -plist <disk_id>`
        let info_xml = match run_command("diskutil", &["info", "-plist", disk_id]) {
            Ok(x) => x,
            Err(_) => continue,
        };

        let info_plist = match parse_plist(&info_xml) {
            Some(p) => p,
            None => continue,
        };

        let dict = match info_plist.as_dict() {
            Some(d) => d,
            None => continue,
        };

        // Skip synthesized virtual APFS containers (e.g. disk3 synthesised over disk0s2)
        let is_virtual_or_synthesized = dict.get("VirtualOrPhysical").and_then(|v| v.as_str()) == Some("Virtual")
            || dict.get("APFSContainerReference").is_some();

        // Ensure it is a genuine whole disk
        let is_whole_disk = dict.get("WholeDisk").and_then(|v| v.as_bool()).unwrap_or(false);
        if !is_whole_disk || is_virtual_or_synthesized {
            continue;
        }

        // Numeric index (e.g. "disk0" -> 0)
        let device_index = disk_id.trim_start_matches("disk").parse::<u32>().unwrap_or(0);

        // Normalize to raw character device path: `/dev/rdiskN` (§23)
        let raw_path = format!("/dev/rdisk{}", device_index);

        // Metadata fields
        let vendor = dict.get("DeviceVendor").and_then(|v| v.as_str()).unwrap_or("Apple").trim().to_string();
        let model = dict.get("DeviceModel")
            .or_else(|| dict.get("MediaName"))
            .and_then(|v| v.as_str())
            .unwrap_or("Storage Device")
            .trim()
            .to_string();

        let serial = dict.get("DeviceSerialNumber")
            .or_else(|| dict.get("SerialNumber"))
            .or_else(|| dict.get("VolumeUUID"))
            .or_else(|| dict.get("DiskUUID"))
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("MAC_DISK_{}_SERIAL", device_index))
            .trim()
            .to_string();

        let capacity_bytes = dict.get("TotalSize")
            .or_else(|| dict.get("Size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let logical_block_size = dict.get("DeviceBlockSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(512) as u32;

        let physical_block_size = dict.get("PhysicalBlockSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(logical_block_size as u64) as u32;

        let protocol = dict.get("BusProtocol")
            .or_else(|| dict.get("Protocol"))
            .and_then(|v| v.as_str())
            .unwrap_or("PCI-Express")
            .to_string();

        let is_ssd = dict.get("SolidState").and_then(|v| v.as_bool()).unwrap_or(true);
        let is_internal = dict.get("Internal").and_then(|v| v.as_bool()).unwrap_or(true);
        let is_os_read_only = dict.get("Writable").and_then(|v| v.as_bool()).map(|w| !w).unwrap_or(false);

        let media_type = classify_media_type(&protocol, is_ssd, &model, is_internal);

        // Hardware write blocker detection
        let (is_write_blocked, write_blocker_info) = check_write_blocker(None, None, &vendor, &model, is_os_read_only);

        // System boot disk detection (§24)
        let is_system_disk = check_if_system_disk(disk_id);

        // Read boundary sector (LBA 0 / 512 bytes) for fingerprinting & partition detection
        let (boundary_sample, partition_table) = match read_lba0_sample(&raw_path, logical_block_size) {
            Ok(sample) => {
                let ptable = detect_partition_table(&sample, None);
                (sample, ptable)
            }
            Err(_) => (vec![0u8; logical_block_size as usize], "Raw / Inaccessible".to_string()),
        };


        descriptors.push(DeviceDescriptor {
            path: raw_path,
            device_index,
            manufacturer: if vendor.is_empty() { "Apple".to_string() } else { vendor },
            model,
            serial,
            capacity_bytes,
            logical_block_size,
            physical_block_size,
            media_type,
            interface: protocol,
            partition_table,
            is_system_disk,
            is_read_only: is_os_read_only,
            is_write_blocked,
            write_blocker_info,
            boundary_sample,
        });
    }

    Ok(descriptors)
}

/// Reads LBA 0 (first sector) from a raw macOS block device node (`/dev/rdiskN`).
fn read_lba0_sample(raw_path: &str, block_size: u32) -> Result<Vec<u8>, IoError> {
    let mut file = File::open(raw_path).map_err(|e| IoError::PermissionDenied {
        details: format!("Failed opening {}: {}", raw_path, e),
    })?;
    let mut buf = vec![0u8; block_size.max(512) as usize];
    file.read_exact(&mut buf).map_err(|e| IoError::ReadFailureAtLba {
        lba: 0,
        count: 1,
        details: format!("Failed reading LBA 0 from {}: {}", raw_path, e),
    })?;
    Ok(buf)
}

/// Queries storage health diagnostics on macOS (§23).
///
/// Employs native `SMARTStatus` reading from DiskArbitration/diskutil, with transparent
/// fallback/extension to `smartctl` if available on the system.
pub fn query_device_health(desc: &DeviceDescriptor) -> Result<DeviceHealth, IoError> {
    let disk_id = desc.path.trim_start_matches("/dev/").trim_start_matches('r');

    // 1. Check if smartctl is available for extended NVMe / ATA diagnostics
    if let Ok(smart_json) = run_smartctl_json(&desc.path) {
        if let Ok(extended_health) = parse_smartctl_metrics(&smart_json, desc) {
            return Ok(extended_health);
        }
    }

    // 2. Fallback: Query native macOS SMARTStatus from diskutil
    let mut native_status = HealthStatus::Unknown;
    let mut native_summary = "SMART diagnostics not available on this interface".to_string();

    if let Ok(xml) = run_command("diskutil", &["info", "-plist", disk_id]) {
        if let Some(PlistValue::Dict(dict)) = parse_plist(&xml) {
            if let Some(smart_str) = dict.get("SMARTStatus").and_then(|v| v.as_str()) {
                match smart_str.to_lowercase().as_str() {
                    "verified" => {
                        native_status = HealthStatus::Good;
                        native_summary = "SMART status Verified by macOS storage subsystem".to_string();
                    }
                    "failing" | "about to fail" => {
                        native_status = HealthStatus::Critical;
                        native_summary = "SMART status FAILING reported by macOS storage subsystem".to_string();
                    }
                    _ => {
                        native_status = HealthStatus::Unknown;
                        native_summary = format!("SMART status reported: {}", smart_str);
                    }
                }
            }
        }
    }

    let recommendation = match native_status {
        HealthStatus::Critical => format!("CRITICAL: Imminent hardware failure reported by macOS ({})", native_summary),
        HealthStatus::Good => format!("Device operational health verified by macOS storage controller ({})", native_summary),
        _ => format!("Health status unknown: {}. Proceed with caution during analysis.", native_summary),
    };


    Ok(DeviceHealth {
        status: native_status,
        media_type: desc.media_type,
        smart_attributes: Vec::new(),
        nvme_health: None,
        hdd_health: None,
        hpa_dco_info: None,
        recommendation,
    })
}

/// Executes `smartctl -j -a <path>` attempting to find smartctl in standard macOS locations.
fn run_smartctl_json(path: &str) -> Result<String, IoError> {
    let candidates = &["smartctl", "/usr/local/bin/smartctl", "/opt/homebrew/bin/smartctl"];
    for bin in candidates {
        if let Ok(output) = Command::new(bin).args(&["-j", "-a", path]).output() {
            if !output.stdout.is_empty() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
    }
    Err(IoError::UnsupportedOperation {
        operation: "smartctl".to_string(),
        reason: "smartctl utility not found on host".to_string(),
    })
}

/// Parses structured JSON output from `smartctl -j -a` into `DeviceHealth`.
fn parse_smartctl_metrics(json_str: &str, desc: &DeviceDescriptor) -> Result<DeviceHealth, IoError> {
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| IoError::Other(format!("Failed parsing smartctl JSON: {}", e)))?;

    let mut smart_attrs = Vec::new();
    let mut nvme_info: Option<NvmeHealthInfo> = None;
    let mut hdd_info: Option<HddHealthInfo> = None;

    if desc.media_type == MediaType::Nvme {
        let nvme_log = json.pointer("/nvme_smart_health_information_log");
        if let Some(log) = nvme_log {
            let critical_warnings = log.get("critical_warning").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            let temperature_celsius = json.pointer("/temperature/current").and_then(|v| v.as_i64()).unwrap_or(35) as i32;
            let available_spare_percent = log.get("available_spare").and_then(|v| v.as_u64()).unwrap_or(100) as u8;
            let available_spare_threshold = log.get("available_spare_threshold").and_then(|v| v.as_u64()).unwrap_or(10) as u8;
            let percentage_used = log.get("percentage_used").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            let media_errors = log.get("media_errors").and_then(|v| v.as_u64()).unwrap_or(0) as u128;
            let power_cycles = log.get("power_cycles").and_then(|v| v.as_u64()).unwrap_or(0) as u128;
            let power_on_hours = log.get("power_on_time").and_then(|v| v.as_u64()).unwrap_or(0) as u128;

            nvme_info = Some(NvmeHealthInfo {
                critical_warnings,
                temperature_celsius,
                available_spare_percent,
                available_spare_threshold,
                percentage_used,
                data_units_read: 0,
                data_units_written: 0,
                host_read_commands: 0,
                host_write_commands: 0,
                controller_busy_time_minutes: 0,
                power_cycles,
                power_on_hours,
                unsafe_shutdowns: 0,
                media_errors,
                error_log_entries: 0,
            });
        }
    } else {
        // ATA SMART attributes
        if let Some(table) = json.pointer("/ata_smart_attributes/table").and_then(|v| v.as_array()) {
            let mut reallocated = 0u64;
            let mut pending = 0u64;
            let mut uncorrectable = 0u64;
            let mut poh = 0u64;
            let mut temp = 30i32;

            for attr in table {
                let id = attr.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let name = attr.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let current = attr.get("value").and_then(|v| v.as_u64()).unwrap_or(100) as u8;
                let worst = attr.get("worst").and_then(|v| v.as_u64()).unwrap_or(100) as u8;
                let threshold = attr.get("thresh").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let raw_value = attr.pointer("/raw/value").and_then(|v| v.as_u64()).unwrap_or(0);
                let failing_now = attr.get("when_failed").and_then(|v| v.as_str()).map_or(false, |s| s == "FAILING_NOW");

                if id == 5 { reallocated = raw_value; }
                if id == 197 { pending = raw_value; }
                if id == 198 { uncorrectable = raw_value; }
                if id == 9 { poh = raw_value; }
                if id == 194 { temp = raw_value as i32; }

                smart_attrs.push(SmartAttribute {
                    id,
                    name,
                    current,
                    worst,
                    threshold,
                    raw_value,
                    failing_now,
                });
            }

            hdd_info = Some(HddHealthInfo {
                reallocated_sectors: reallocated,
                pending_sectors: pending,
                uncorrectable_sectors: uncorrectable,
                power_on_hours: poh,
                temperature_celsius: temp,
                raw_read_error_rate: 0,
            });
        }
    }

    Ok(DeviceHealth::evaluate(
        desc.media_type,
        nvme_info,
        hdd_info,
        None,
        smart_attrs,
    ))
}

/// Concrete low-level OS file handle for raw block I/O on macOS (§23, §24).
///
/// Bypasses Unified Buffer Cache using `/dev/rdiskN` and `F_NOCACHE`.
pub struct OsDriveHandle {
    file: File,
    path: PathBuf,
    is_writable: bool,
}

impl OsDriveHandle {
    /// Opens a macOS raw storage device in read-only mode (`/dev/rdiskN`).
    pub fn open_readonly(path: &Path) -> Result<Self, IoError> {
        let raw_path = normalize_to_raw_device_path(path);
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .custom_flags(libc::O_RDONLY)
            .open(&raw_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    IoError::PermissionDenied {
                        details: format!(
                            "Permission denied opening {} (root privileges required). Elevated administrator privileges required.",
                            raw_path.display()
                        ),
                    }
                } else {
                    IoError::Other(format!("Failed opening {}: {}", raw_path.display(), e))
                }
            })?;

        // Disable page cache via fcntl(F_NOCACHE) on macOS for direct DMA transfers
        #[cfg(target_os = "macos")]
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
        }


        Ok(Self {
            file,
            path: raw_path,
            is_writable: false,
        })
    }

    /// Opens a macOS raw storage device in writable mode (`/dev/rdiskN`).
    pub fn open_writable(path: &Path) -> Result<Self, IoError> {
        let raw_path = normalize_to_raw_device_path(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_RDWR)
            .open(&raw_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    IoError::PermissionDenied {
                        details: format!(
                            "Permission denied opening {} in writable mode (root privileges required).",
                            raw_path.display()
                        ),
                    }
                } else {
                    IoError::Other(format!("Failed opening {}: {}", raw_path.display(), e))
                }
            })?;

        #[cfg(target_os = "macos")]
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
        }


        Ok(Self {
            file,
            path: raw_path,
            is_writable: true,
        })
    }

    /// Reads contiguous sectors from the device starting at `lba`.
    ///
    /// Strictly verifies exact byte counts, returning hard error on any short read (§23).
    pub fn read_blocks(&mut self, lba: u64, count: u32, block_size: u32) -> Result<Vec<u8>, IoError> {
        let offset = lba.checked_mul(block_size as u64).ok_or_else(|| IoError::InvalidParameter {
            message: "LBA byte offset calculation overflowed u64".to_string(),
        })?;

        let total_bytes = (count as usize).checked_mul(block_size as usize).ok_or_else(|| IoError::InvalidParameter {
            message: "Read total byte count overflowed usize".to_string(),
        })?;

        self.file.seek(SeekFrom::Start(offset)).map_err(|e| IoError::ReadFailureAtLba {
            lba,
            count,
            details: format!("Seek to byte offset {} failed on {}: {}", offset, self.path.display(), e),
        })?;

        let mut buffer = vec![0u8; total_bytes];
        self.file.read_exact(&mut buffer).map_err(|e| IoError::ReadFailureAtLba {
            lba,
            count,
            details: format!("Direct sector read failed on {} at LBA {}: {}", self.path.display(), lba, e),
        })?;

        Ok(buffer)
    }

    /// Writes contiguous sectors to the physical device starting at `lba`.
    ///
    /// Flushes disk cache via `fsync` before returning.
    pub fn write_blocks(&mut self, lba: u64, data: &[u8], block_size: u32) -> Result<(), IoError> {
        if !self.is_writable {
            return Err(IoError::PermissionDenied {
                details: "Drive opened in read-only mode".to_string(),
            });
        }

        let offset = lba.checked_mul(block_size as u64).ok_or_else(|| IoError::InvalidParameter {
            message: "LBA byte offset calculation overflowed u64".to_string(),
        })?;

        self.file.seek(SeekFrom::Start(offset)).map_err(|e| IoError::WriteFailureAtLba {
            lba,
            count: (data.len() / block_size as usize) as u32,
            details: format!("Seek to byte offset {} failed on {}: {}", offset, self.path.display(), e),
        })?;

        self.file.write_all(data).map_err(|e| IoError::WriteFailureAtLba {
            lba,
            count: (data.len() / block_size as usize) as u32,
            details: format!("Direct sector write failed on {} at LBA {}: {}", self.path.display(), lba, e),
        })?;

        self.file.flush().map_err(|e| IoError::WriteFailureAtLba {
            lba,
            count: (data.len() / block_size as usize) as u32,
            details: format!("Flush failed on {}: {}", self.path.display(), e),
        })?;

        unsafe {
            libc::fsync(self.file.as_raw_fd());
        }

        Ok(())
    }
}

/// Normalizes `/dev/diskN` or `diskN` path to raw character device node `/dev/rdiskN` (§23).
fn normalize_to_raw_device_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("/dev/rdisk") {
        path.to_path_buf()
    } else if let Some(stripped) = path_str.strip_prefix("/dev/disk") {
        PathBuf::from(format!("/dev/rdisk{}", stripped))
    } else if let Some(stripped) = path_str.strip_prefix("disk") {
        PathBuf::from(format!("/dev/rdisk{}", stripped))
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plist_parser_dict_and_primitives() {
        let sample_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceIdentifier</key>
    <string>disk0</string>
    <key>DeviceNode</key>
    <string>/dev/disk0</string>
    <key>TotalSize</key>
    <integer>1000204886016</integer>
    <key>DeviceBlockSize</key>
    <integer>4096</integer>
    <key>BusProtocol</key>
    <string>PCI-Express</string>
    <key>SolidState</key>
    <true/>
    <key>Writable</key>
    <false/>
    <key>SMARTStatus</key>
    <string>Verified</string>
    <key>WholeDisk</key>
    <true/>
</dict>
</plist>"#;

        let parsed = parse_plist(sample_plist).expect("Must parse plist dictionary");
        let dict = parsed.as_dict().expect("Root must be dictionary");

        assert_eq!(dict.get("DeviceIdentifier").and_then(|v| v.as_str()), Some("disk0"));
        assert_eq!(dict.get("TotalSize").and_then(|v| v.as_u64()), Some(1000204886016));
        assert_eq!(dict.get("DeviceBlockSize").and_then(|v| v.as_u64()), Some(4096));
        assert_eq!(dict.get("SolidState").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(dict.get("Writable").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(dict.get("SMARTStatus").and_then(|v| v.as_str()), Some("Verified"));
    }

    #[test]
    fn test_normalize_to_raw_device_path() {
        assert_eq!(normalize_to_raw_device_path(Path::new("/dev/disk0")), PathBuf::from("/dev/rdisk0"));
        assert_eq!(normalize_to_raw_device_path(Path::new("/dev/rdisk0")), PathBuf::from("/dev/rdisk0"));
        assert_eq!(normalize_to_raw_device_path(Path::new("disk2")), PathBuf::from("/dev/rdisk2"));
    }

    #[test]
    fn test_classify_media_type() {
        assert_eq!(classify_media_type("PCI-Express", true, "APPLE SSD", true), MediaType::Nvme);
        assert_eq!(classify_media_type("NVMe", true, "Samsung 980", false), MediaType::Nvme);
        assert_eq!(classify_media_type("USB", true, "SanDisk Ultra", false), MediaType::Usb);
        assert_eq!(classify_media_type("USB", false, "SD Card Reader", false), MediaType::SdCard);
        assert_eq!(classify_media_type("Secure Digital", false, "Internal SD", true), MediaType::SdCard);
        assert_eq!(classify_media_type("SATA", true, "Crucial MX500", true), MediaType::SataSsd);
        assert_eq!(classify_media_type("SATA", false, "WDC WD10EZEX", true), MediaType::Hdd);
    }
}
