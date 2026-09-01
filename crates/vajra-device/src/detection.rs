//! Write-blocker signature matching and partition table inspection.
//!
//! Implements hardware write-blocker identification (§24) and MBR/GPT detection.

use vajra_core::{WriteBlockerDetectionMethod, WriteBlockerMetadata};

/// Known forensic hardware write-blocker signatures (VID, PID, Vendor, Model).
struct KnownWriteBlocker {
    vid: u16,
    pid: u16,
    vendor: &'static str,
    model: &'static str,
}

static KNOWN_WRITE_BLOCKERS: &[KnownWriteBlocker] = &[
    // Tableau / OpenText Forensic Bridges
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0001, vendor: "Tableau / OpenText", model: "T8 Forensic USB Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0002, vendor: "Tableau / OpenText", model: "T35u USB 3.0 SATA/IDE Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0003, vendor: "Tableau / OpenText", model: "T8u USB 3.0 Forensic Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0004, vendor: "Tableau / OpenText", model: "T7u PCIe Forensic Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0005, vendor: "Tableau / OpenText", model: "T9 FireWire/USB Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0008, vendor: "Tableau / OpenText", model: "T6u SAS Forensic Bridge" },
    KnownWriteBlocker { vid: 0x0ECF, pid: 0x0009, vendor: "Tableau / OpenText", model: "T35689iu Forensic Combo Bridge" },
    // WiebeTech / CRU
    KnownWriteBlocker { vid: 0x04E6, pid: 0x0001, vendor: "CRU / WiebeTech", model: "UltraDock Forensic Bridge" },
    KnownWriteBlocker { vid: 0x04E6, pid: 0x0002, vendor: "CRU / WiebeTech", model: "DriveLock USB Write-Blocker" },
    KnownWriteBlocker { vid: 0x04E6, pid: 0x0003, vendor: "CRU / WiebeTech", model: "DittoBeam Forensic Device" },
    KnownWriteBlocker { vid: 0x14BC, pid: 0x0001, vendor: "CRU / WiebeTech", model: "ToughTech Forensic Bridge" },
    // Coolgear / Forensic PC
    KnownWriteBlocker { vid: 0x05E3, pid: 0x0735, vendor: "Coolgear", model: "USB 3.0 Forensic SATA Write Blocker" },
    KnownWriteBlocker { vid: 0x174C, pid: 0x55AA, vendor: "ASMedia / Coolgear", model: "Hardware Write-Blocked Enclosure" },
];

/// Checks if a device matches known hardware write blocker signatures or OS read-only status (§24).
pub fn check_write_blocker(
    vid: Option<u16>,
    pid: Option<u16>,
    vendor_str: &str,
    model_str: &str,
    is_os_read_only: bool,
) -> (bool, Option<WriteBlockerMetadata>) {
    // 1. Check VID/PID table
    if let (Some(v), Some(p)) = (vid, pid) {
        for kb in KNOWN_WRITE_BLOCKERS {
            if kb.vid == v && kb.pid == p {
                return (
                    true,
                    Some(WriteBlockerMetadata {
                        vendor: Some(kb.vendor.to_string()),
                        model: Some(kb.model.to_string()),
                        vid: Some(v),
                        pid: Some(p),
                        detection_method: WriteBlockerDetectionMethod::KnownVidPid,
                        is_hardware_blocked: true,
                        is_os_read_only,
                    }),
                );
            }
        }
    }

    // 2. Check vendor/model strings for write blocker keywords
    let combined = format!("{vendor_str} {model_str}").to_uppercase();
    if combined.contains("TABLEAU")
        || combined.contains("WIEBETECH")
        || combined.contains("FASTBLOC")
        || combined.contains("WRITEBLOCK")
        || combined.contains("WRITE-BLOCK")
        || combined.contains("CRU DITTO")
    {
        return (
            true,
            Some(WriteBlockerMetadata {
                vendor: Some(vendor_str.trim().to_string()),
                model: Some(model_str.trim().to_string()),
                vid,
                pid,
                detection_method: WriteBlockerDetectionMethod::KnownVidPid,
                is_hardware_blocked: true,
                is_os_read_only,
            }),
        );
    }

    // 3. Check OS-level read-only query
    if is_os_read_only {
        return (
            true,
            Some(WriteBlockerMetadata {
                vendor: None,
                model: None,
                vid,
                pid,
                detection_method: WriteBlockerDetectionMethod::OsQuery,
                is_hardware_blocked: false,
                is_os_read_only: true,
            }),
        );
    }

    (false, None)
}

/// Detects partition table format from Sector 0 (MBR) and Sector 1 (GPT Header).
pub fn detect_partition_table(sector_0: &[u8], sector_1: Option<&[u8]>) -> String {
    if sector_0.len() < 512 {
        return "Raw / Unknown".to_string();
    }

    // Check MBR boot signature 0x55, 0xAA at offset 510..512
    let has_mbr_sig = sector_0[510] == 0x55 && sector_0[511] == 0xAA;
    if !has_mbr_sig {
        return "Raw / Unpartitioned".to_string();
    }

    // Check for GPT Protective MBR (partition entry type 0xEE in any of the 4 entries)
    // Partition entry offsets: 446, 462, 478, 494. Partition type is at offset +4.
    let mut has_gpt_protective = false;
    for offset in [446, 462, 478, 494] {
        if sector_0[offset + 4] == 0xEE {
            has_gpt_protective = true;
            break;
        }
    }

    if has_gpt_protective {
        // If sector 1 is available, check for "EFI PART" signature (0x45 0x46 0x49 0x20 0x50 0x41 0x52 0x54)
        if let Some(sec1) = sector_1 {
            if sec1.len() >= 8 && &sec1[0..8] == b"EFI PART" {
                return "GPT (GUID Partition Table)".to_string();
            }
        }
        return "GPT (Protective MBR detected)".to_string();
    }

    "MBR (Master Boot Record)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_write_blocker_detection() {
        let (blocked, meta) = check_write_blocker(Some(0x0ECF), Some(0x0003), "Tableau", "T8u", true);
        assert!(blocked);
        let meta = meta.unwrap();
        assert_eq!(meta.vendor.unwrap(), "Tableau / OpenText");
        assert_eq!(meta.model.unwrap(), "T8u USB 3.0 Forensic Bridge");
        assert_eq!(meta.detection_method, WriteBlockerDetectionMethod::KnownVidPid);
        assert!(meta.is_hardware_blocked);
    }

    #[test]
    fn test_vendor_string_heuristic() {
        let (blocked, meta) = check_write_blocker(None, None, "CRU", "WiebeTech UltraDock v5", false);
        assert!(blocked);
        assert_eq!(meta.unwrap().detection_method, WriteBlockerDetectionMethod::KnownVidPid);
    }

    #[test]
    fn test_os_read_only_fallback() {
        let (blocked, meta) = check_write_blocker(None, None, "Generic", "USB Flash Drive", true);
        assert!(blocked);
        let meta = meta.unwrap();
        assert_eq!(meta.detection_method, WriteBlockerDetectionMethod::OsQuery);
        assert!(!meta.is_hardware_blocked);
        assert!(meta.is_os_read_only);
    }

    #[test]
    fn test_partition_table_detection() {
        let mut mbr = [0u8; 512];
        assert_eq!(detect_partition_table(&mbr, None), "Raw / Unpartitioned");

        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(detect_partition_table(&mbr, None), "MBR (Master Boot Record)");

        mbr[446 + 4] = 0xEE; // GPT protective entry
        let mut gpt_header = [0u8; 512];
        gpt_header[0..8].copy_from_slice(b"EFI PART");
        assert_eq!(detect_partition_table(&mbr, Some(&gpt_header)), "GPT (GUID Partition Table)");
    }
}
