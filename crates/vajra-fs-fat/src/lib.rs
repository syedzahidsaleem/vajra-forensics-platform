//! # vajra-fs-fat
//!
//! High-performance FAT12, FAT16, and FAT32 filesystem analysis and Tier-1 recovery parser (§25).
//!
//! Recovers active files and deleted files (`0xE5` marked directory entries and LFN multi-entry sequences)
//! with exact original filenames, timestamps, file sizes, and cluster/extent mappings.
//!
//! # Safety
//! Operates strictly against [`vajra_core::ReadOnlyBlockSource`]. Syntactically incapable of issuing writes.

pub mod bpb;
pub mod dir_entry;
pub mod error;
pub mod fat_table;
pub mod parser;

pub use bpb::FatBpb;
pub use dir_entry::{dos_datetime_to_utc, parse_standard_entry, FatDirEntry, LfnAccumulator};
pub use error::FatError;
pub use fat_table::FatTable;
pub use parser::FatParser;

use vajra_core::{ReadOnlyBlockSource, RecoverableFileEntry};

/// Enumerates all active and recoverable deleted entries from a FAT filesystem (§25).
pub fn enumerate_entries(
    source: &mut dyn ReadOnlyBlockSource,
    partition_start_lba: u64,
) -> Result<Vec<RecoverableFileEntry>, FatError> {
    let mut parser = FatParser::new(source, partition_start_lba)?;
    parser.enumerate_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_datetime_conversion() {
        // Date: 2026-08-30 -> (2026-1980) = 46 (0x2E), Month = 8, Day = 30 (0x1E)
        // dos_date = (46 << 9) | (8 << 5) | 30 = 23552 | 256 | 30 = 23838
        let dos_date = (46 << 9) | (8 << 5) | 30;
        // Time: 14:30:10 -> Hour = 14, Min = 30, Sec = 10 / 2 = 5
        // dos_time = (14 << 11) | (30 << 5) | 5 = 28672 | 960 | 5 = 29637
        let dos_time = (14 << 11) | (30 << 5) | 5;

        let dt = dos_datetime_to_utc(dos_date, dos_time).unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-08-30T14:30:10+00:00");
    }

    #[test]
    fn test_lfn_accumulator_and_deleted_entry_recovery() {
        let mut lfn_acc = LfnAccumulator::new();

        // 2 LFN entries for "Forensic_Report_2026.docx" (26 chars total -> 2 chunks of 13 chars)
        // Chunk 1: "Forensic_Repo" (13 chars)
        // Chunk 2: "rt_2026.docx\0" (13 chars)

        // Chunk 2 (last chunk, seq 0x42): "rt_2026.docx\0"
        let mut chunk2 = [0u8; 32];
        chunk2[0] = 0x42; // last + seq 2
        chunk2[11] = 0x0F; // LFN attr
        let name2_utf16: Vec<u16> = "rt_2026.docx\0".encode_utf16().collect();
        for (i, &ch) in name2_utf16[0..5].iter().enumerate() {
            chunk2[1 + i * 2..3 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }
        for (i, &ch) in name2_utf16[5..11].iter().enumerate() {
            chunk2[14 + i * 2..16 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }
        for (i, &ch) in name2_utf16[11..13].iter().enumerate() {
            chunk2[28 + i * 2..30 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }

        // Chunk 1 (seq 0x01): "Forensic_Repo"
        let mut chunk1 = [0u8; 32];
        chunk1[0] = 0x01; // seq 1
        chunk1[11] = 0x0F; // LFN attr
        let name1_utf16: Vec<u16> = "Forensic_Repo".encode_utf16().collect();
        for (i, &ch) in name1_utf16[0..5].iter().enumerate() {
            chunk1[1 + i * 2..3 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }
        for (i, &ch) in name1_utf16[5..11].iter().enumerate() {
            chunk1[14 + i * 2..16 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }
        for (i, &ch) in name1_utf16[11..13].iter().enumerate() {
            chunk1[28 + i * 2..30 + i * 2].copy_from_slice(&ch.to_le_bytes());
        }

        // Feed chunks in reverse order (as on disk)
        lfn_acc.feed(&chunk2);
        lfn_acc.feed(&chunk1);

        let lfn_name = lfn_acc.finalize().unwrap();
        assert_eq!(lfn_name, "Forensic_Report_2026.docx");

        // Standard 8.3 entry marked as deleted (0xE5)
        let mut standard_entry = [0u8; 32];
        standard_entry[0] = 0xE5; // DELETED marker
        standard_entry[1..8].copy_from_slice(b"ORENS~1");
        standard_entry[8..11].copy_from_slice(b"DOC");
        standard_entry[11] = 0x20; // Archive
        standard_entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // Cluster Hi
        standard_entry[26..28].copy_from_slice(&105u16.to_le_bytes()); // Cluster Lo = 105
        standard_entry[28..32].copy_from_slice(&24576u32.to_le_bytes()); // 24 KB

        let parsed = parse_standard_entry(&standard_entry, Some(lfn_name)).unwrap();
        assert!(parsed.is_deleted);
        assert_eq!(parsed.display_name(), "Forensic_Report_2026.docx");
        assert_eq!(parsed.start_cluster, 105);
        assert_eq!(parsed.file_size, 24576);
    }
}
