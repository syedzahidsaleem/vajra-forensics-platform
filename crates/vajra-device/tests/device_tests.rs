//! Integration and unit tests for vajra-device (§23–§24).

use vajra_core::{MediaType, WriteBlockerDetectionMethod};
use vajra_device::{
    check_write_blocker, detect_partition_table, DeviceDescriptor, DeviceHealth,
    HddHealthInfo, HealthStatus, NvmeHealthInfo,
};

#[test]
fn test_device_descriptor_formatting() {
    let desc = DeviceDescriptor {
        path: "/dev/nvme0n1".to_string(),
        device_index: 0,
        manufacturer: "Samsung".to_string(),
        model: "980 PRO 2TB".to_string(),
        serial: "S5GXNF0R123456".to_string(),
        capacity_bytes: 2_000_398_934_016, // ~2.00 TB
        logical_block_size: 512,
        physical_block_size: 4096,
        media_type: MediaType::Nvme,
        interface: "NVMe".to_string(),
        partition_table: "GPT".to_string(),
        is_system_disk: true,
        is_read_only: false,
        is_write_blocked: false,
        write_blocker_info: None,
        boundary_sample: vec![0u8; 512],
    };

    assert!(desc.formatted_capacity().contains("2.00 TB"));
    assert!(desc.formatted_capacity().contains("1.82 TiB"));
}

#[test]
fn test_write_blocker_signatures() {
    // Tableau T35u
    let (blocked, meta) = check_write_blocker(Some(0x0ECF), Some(0x0002), "Tableau", "T35u", true);
    assert!(blocked);
    let m = meta.unwrap();
    assert_eq!(m.vendor.unwrap(), "Tableau / OpenText");
    assert_eq!(m.model.unwrap(), "T35u USB 3.0 SATA/IDE Bridge");
    assert_eq!(m.detection_method, WriteBlockerDetectionMethod::KnownVidPid);
    assert!(m.is_hardware_blocked);

    // WiebeTech DriveLock
    let (blocked_w, meta_w) = check_write_blocker(Some(0x04E6), Some(0x0002), "CRU", "DriveLock", true);
    assert!(blocked_w);
    assert_eq!(meta_w.unwrap().model.unwrap(), "DriveLock USB Write-Blocker");

    // Standard Non-Blocked USB Drive
    let (blocked_u, meta_u) = check_write_blocker(Some(0x0781), Some(0x5581), "SanDisk", "Ultra USB 3.0", false);
    assert!(!blocked_u);
    assert!(meta_u.is_none());
}

#[test]
fn test_health_diagnostics_formatting() {
    let hdd = HddHealthInfo {
        reallocated_sectors: 24,
        pending_sectors: 7,
        uncorrectable_sectors: 2,
        power_on_hours: 12000,
        temperature_celsius: 42,
        raw_read_error_rate: 0,
    };

    let health = DeviceHealth::evaluate(MediaType::Hdd, None, Some(hdd), None, vec![]);
    assert_eq!(health.status, HealthStatus::Critical);

    let display_str = format!("{}", health);
    assert!(display_str.contains("DEVICE HEALTH"));
    assert!(display_str.contains("Status: CRITICAL"));
    assert!(display_str.contains("Reallocated sectors: 24"));
    assert!(display_str.contains("Pending sectors: 7"));
    assert!(display_str.contains("Uncorrectable sectors: 2"));
    assert!(display_str.contains("Recommendation:"));
}

#[test]
fn test_nvme_health_diagnostics_formatting() {
    let nvme = NvmeHealthInfo {
        critical_warnings: 0,
        temperature_celsius: 36,
        available_spare_percent: 100,
        available_spare_threshold: 10,
        percentage_used: 4,
        data_units_read: 15_000_000,
        data_units_written: 12_000_000,
        host_read_commands: 250_000_000,
        host_write_commands: 200_000_000,
        controller_busy_time_minutes: 500,
        power_cycles: 120,
        power_on_hours: 3200,
        unsafe_shutdowns: 5,
        media_errors: 0,
        error_log_entries: 0,
    };

    let health = DeviceHealth::evaluate(MediaType::Nvme, Some(nvme), None, None, vec![]);
    assert_eq!(health.status, HealthStatus::Good);

    let display_str = format!("{}", health);
    assert!(display_str.contains("Status: GOOD"));
    assert!(display_str.contains("Available Spare: 100%"));
    assert!(display_str.contains("Percentage Used: 4%"));
}

#[test]
fn test_gpt_and_mbr_partition_detection() {
    let mut mbr = [0u8; 512];
    assert_eq!(detect_partition_table(&mbr, None), "Raw / Unpartitioned");

    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    assert_eq!(detect_partition_table(&mbr, None), "MBR (Master Boot Record)");

    mbr[446 + 4] = 0xEE; // GPT Protective MBR entry
    assert_eq!(detect_partition_table(&mbr, None), "GPT (Protective MBR detected)");

    let mut gpt_header = [0u8; 512];
    gpt_header[0..8].copy_from_slice(b"EFI PART");
    assert_eq!(detect_partition_table(&mbr, Some(&gpt_header)), "GPT (GUID Partition Table)");
}

#[test]
fn test_media_type_classification_coverage() {
    assert_eq!(format!("{}", MediaType::Nvme), "NVMe SSD");
    assert_eq!(format!("{}", MediaType::SataSsd), "SATA SSD");
    assert_eq!(format!("{}", MediaType::Hdd), "HDD (Magnetic)");
    assert_eq!(format!("{}", MediaType::Usb), "USB Flash Drive");
    assert_eq!(format!("{}", MediaType::SdCard), "SD/microSD Card");
    assert_eq!(format!("{}", MediaType::Sed), "Self-Encrypting Drive (SED)");
    assert_eq!(format!("{}", MediaType::ForensicImage), "Forensic Disk Image");
}

