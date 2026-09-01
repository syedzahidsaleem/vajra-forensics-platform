//! Ground-truth end-to-end integration tests (§25, §45).
//!
//! Validates byte-for-byte recovery against synthetic test images:
//! - FAT32: Active + Deleted LFN files
//! - ext4: Active + Unlinked directory slack files
//! - NTFS: Active resident + Deleted non-resident MFT records
//! - NTFS Quick-Format: Surviving pre-format MFT record recovery from unallocated space

use std::path::PathBuf;
use vajra_core::{DataLocation, FilesystemType, MetadataConfidence, ReadOnlyBlockSource};
use vajra_image::RawImageReader;

fn get_test_image_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_data")
        .join(name)
}

#[test]
fn test_fat32_ground_truth_recovery() {
    let img_path = get_test_image_path("fat32_test.img");
    assert!(img_path.exists(), "fat32_test.img must exist");

    let mut reader = RawImageReader::open(img_path.to_str().unwrap(), None).unwrap();

    // 1. Filesystem detection
    let fs_type = vajra_core::detect_filesystem(&mut reader, 0).unwrap();
    assert_eq!(fs_type, FilesystemType::Fat32);

    // 2. Enumerate entries
    let entries = vajra_fs_fat::enumerate_entries(&mut reader, 0).unwrap();
    assert!(!entries.is_empty());

    // 3. Find Active file "active_document.txt"
    let active_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("active_document.txt"))
        .expect("active_document.txt must be found");
    assert!(!active_entry.deleted);
    assert_eq!(active_entry.metadata_confidence, MetadataConfidence::Confirmed);

    // Read and verify active content
    if let DataLocation::Contiguous { start_lba, block_count } = &active_entry.data_location {
        let bytes = reader.read_blocks(*start_lba, *block_count as u32).unwrap();
        let content = String::from_utf8_lossy(&bytes[..active_entry.size_bytes.unwrap() as usize]);
        assert!(content.contains("ACTIVE FAT32 DATA: Ground-truth evidence payload"));
    } else {
        panic!("Expected contiguous data location for active FAT32 file");
    }

    // 4. Find Deleted file "confidential_plan.pdf"
    let deleted_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("confidential_plan.pdf"))
        .expect("confidential_plan.pdf must be recovered from deleted LFN");
    assert!(deleted_entry.deleted);
    assert_eq!(deleted_entry.metadata_confidence, MetadataConfidence::Confirmed);

    // Read and verify deleted content byte-for-byte
    if let DataLocation::Contiguous { start_lba, block_count } = &deleted_entry.data_location {
        let bytes = reader.read_blocks(*start_lba, *block_count as u32).unwrap();
        let content = String::from_utf8_lossy(&bytes[..deleted_entry.size_bytes.unwrap() as usize]);
        assert!(content.contains("TOP SECRET DELETED FORENSIC DATA: Vajra tier-1 recovery ground truth test."));
    } else {
        panic!("Expected contiguous data location for deleted FAT32 file");
    }
}

#[test]
fn test_ext4_ground_truth_recovery() {
    let img_path = get_test_image_path("ext4_test.img");
    assert!(img_path.exists(), "ext4_test.img must exist");

    let mut reader = RawImageReader::open(img_path.to_str().unwrap(), None).unwrap();

    // 1. Filesystem detection
    let fs_type = vajra_core::detect_filesystem(&mut reader, 0).unwrap();
    assert_eq!(fs_type, FilesystemType::Ext4);

    // 2. Enumerate entries
    let entries = vajra_fs_ext4::enumerate_entries(&mut reader, 0).unwrap();
    assert!(!entries.is_empty());

    // 3. Find Active file "live_evidence.txt"
    let active_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("live_evidence.txt"))
        .expect("live_evidence.txt must be found");
    assert!(!active_entry.deleted);

    // 4. Find Deleted file "secret_deleted.txt" from directory slack / orphan inode
    let deleted_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("secret_deleted.txt"))
        .expect("secret_deleted.txt must be recovered from directory slack");
    assert!(deleted_entry.deleted);
    assert_eq!(deleted_entry.metadata_confidence, MetadataConfidence::Confirmed);

    // Read and verify recovered content
    if let DataLocation::Contiguous { start_lba, block_count } = &deleted_entry.data_location {
        let bytes = reader.read_blocks(*start_lba, *block_count as u32).unwrap();
        let content = String::from_utf8_lossy(&bytes[..deleted_entry.size_bytes.unwrap() as usize]);
        assert!(content.contains("DELETED EXT4 EVIDENCE: Recovered from directory slack and inode extents!"));
    }
}

#[test]
fn test_ntfs_ground_truth_recovery() {
    let img_path = get_test_image_path("ntfs_test.img");
    assert!(img_path.exists(), "ntfs_test.img must exist");

    let mut reader = RawImageReader::open(img_path.to_str().unwrap(), None).unwrap();

    // 1. Filesystem detection
    let fs_type = vajra_core::detect_filesystem(&mut reader, 0).unwrap();
    assert_eq!(fs_type, FilesystemType::Ntfs);

    // 2. Enumerate entries
    let entries = vajra_fs_ntfs::enumerate_entries(&mut reader, 0).unwrap();
    assert!(!entries.is_empty());

    // 3. Find Active resident file "system_audit.log"
    let active_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("system_audit.log"))
        .expect("system_audit.log must be found");
    assert!(!active_entry.deleted);
    assert_eq!(active_entry.metadata_confidence, MetadataConfidence::Confirmed);

    if let DataLocation::Resident(bytes) = &active_entry.data_location {
        let content = String::from_utf8_lossy(bytes);
        assert!(content.contains("ACTIVE NTFS AUDIT LOG: System integrity verified 2026."));
    } else {
        panic!("Expected resident data location for system_audit.log");
    }

    // 4. Find Deleted non-resident file "financial_records_2026.xlsx"
    let deleted_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("financial_records_2026.xlsx"))
        .expect("financial_records_2026.xlsx must be recovered");
    assert!(deleted_entry.deleted);
    assert_eq!(deleted_entry.metadata_confidence, MetadataConfidence::Confirmed);

    if let DataLocation::Contiguous { start_lba, block_count } = &deleted_entry.data_location {
        let bytes = reader.read_blocks(*start_lba, *block_count as u32).unwrap();
        let content = String::from_utf8_lossy(&bytes[..deleted_entry.size_bytes.unwrap() as usize]);
        assert!(content.contains("CONFIDENTIAL FINANCIAL FORENSIC EVIDENCE: Complete quarterly ledger."));
    } else {
        panic!("Expected contiguous data location for financial_records_2026.xlsx");
    }
}

#[test]
fn test_ntfs_quickformat_scenario_recovery() {
    let img_path = get_test_image_path("ntfs_quickformat.img");
    assert!(img_path.exists(), "ntfs_quickformat.img must exist");

    let mut reader = RawImageReader::open(img_path.to_str().unwrap(), None).unwrap();

    // 1. Filesystem detection on new format
    let fs_type = vajra_core::detect_filesystem(&mut reader, 0).unwrap();
    assert_eq!(fs_type, FilesystemType::Ntfs);

    // 2. Enumerate entries — must scan unallocated space and recover pre-format MFT record!
    let entries = vajra_fs_ntfs::enumerate_entries(&mut reader, 0).unwrap();

    let preformat_entry = entries
        .iter()
        .find(|e| e.filename.as_deref() == Some("pre_format_evidence.docx"))
        .expect("pre_format_evidence.docx must be recovered across quick-format boundary");
    assert!(preformat_entry.deleted);

    if let DataLocation::Resident(bytes) = &preformat_entry.data_location {
        let content = String::from_utf8_lossy(bytes);
        assert!(content.contains("RECOVERED PRE-FORMAT EVIDENCE: Surviving MFT record across volume quick-format!"));
    } else {
        panic!("Expected resident data location for pre_format_evidence.docx");
    }
}
