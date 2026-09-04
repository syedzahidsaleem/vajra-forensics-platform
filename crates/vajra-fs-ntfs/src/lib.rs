//! # vajra-fs-ntfs
//!
//! High-performance NTFS filesystem analysis, MFT walking, and Tier-1 recovery engine (§25).
//!
//! Implements:
//! - Multi-sector update sequence fixup application (TSK `ntfs_fixup`)
//! - MFT record parsing: `$STANDARD_INFORMATION` (0x10), `$FILE_NAME` (0x30), `$DATA` (0x80)
//! - Resident byte payload extraction and non-resident variable-length runlist decoding
//! - `$Bitmap` cluster free/allocation cross-referencing for calibrated `MetadataConfidence`
//! - Quick-format surviving MFT record scanner across unallocated cluster space (§25)
//! - Basic `$LogFile` / `$UsnJrnl` change journal inspection and Volume Shadow Copy (VSS) presence detection
//!
//! # Safety
//! Operates strictly against [`vajra_core::ReadOnlyBlockSource`]. Syntactically incapable of issuing writes.

pub mod bitmap;
pub mod boot;
pub mod error;
pub mod journal;
pub mod mft;
pub mod parser;
pub mod vss;

pub use bitmap::NtfsBitmap;
pub use boot::NtfsBoot;
pub use error::NtfsError;
pub use journal::{parse_usn_records, UsnRecord};
pub use mft::{
    apply_mft_fixup, decode_data_runs, parse_mft_record, DataAttr, FileNameAttr, MftRecord,
    StandardInformationAttr,
};
pub use parser::NtfsParser;
pub use vss::VssInfo;

use vajra_core::{ReadOnlyBlockSource, RecoverableFileEntry};

/// Enumerates all active and recoverable deleted entries from an NTFS volume (§25).
pub fn enumerate_entries(
    source: &mut dyn ReadOnlyBlockSource,
    partition_start_lba: u64,
) -> Result<Vec<RecoverableFileEntry>, NtfsError> {
    let mut parser = NtfsParser::new(source, partition_start_lba)?;
    parser.enumerate_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mft_fixup_application() {
        let mut record = vec![0u8; 1024];
        // Magic 'FILE'
        record[0..4].copy_from_slice(b"FILE");
        // Update sequence offset = 48, count = 3 (1 signature + 2 replacements for 2 sectors)
        record[4..6].copy_from_slice(&48u16.to_le_bytes());
        record[6..8].copy_from_slice(&3u16.to_le_bytes());

        // Update sequence array at offset 48:
        // Sig = 0xAA55
        // Sector 1 replacement = 0x1122
        // Sector 2 replacement = 0x3344
        record[48..50].copy_from_slice(&0xAA55u16.to_le_bytes());
        record[50..52].copy_from_slice(&0x1122u16.to_le_bytes());
        record[52..54].copy_from_slice(&0x3344u16.to_le_bytes());

        // Sector 1 end (byte 510..512) and Sector 2 end (byte 1022..1024) have Sig 0xAA55
        record[510..512].copy_from_slice(&0xAA55u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xAA55u16.to_le_bytes());

        assert!(apply_mft_fixup(&mut record, 0).is_ok());

        // Verify replacements were restored
        let sec1_val = u16::from_le_bytes([record[510], record[511]]);
        let sec2_val = u16::from_le_bytes([record[1022], record[1023]]);
        assert_eq!(sec1_val, 0x1122);
        assert_eq!(sec2_val, 0x3344);
    }

    #[test]
    fn test_decode_data_runs() {
        let boot = NtfsBoot {
            partition_start_lba: 2048,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            total_sectors: 204800,
            mft_start_lcn: 4,
            mft_mirr_start_lcn: 2,
            mft_record_size: 1024,
            index_record_size: 4096,
            serial_number: 0x12345678,
        };

        // Runlist with 2 runs:
        // Run 1: header 0x21 (len_bytes = 1, off_bytes = 2) -> 16 clusters at LCN +100 (0x0064)
        // Run 2: header 0x21 (len_bytes = 1, off_bytes = 2) -> 32 clusters at LCN +50 (relative +50 -> LCN 150)
        // Terminator 0x00
        let runlist = vec![
            0x21, 16, 0x64, 0x00,
            0x21, 32, 0x32, 0x00,
            0x00,
        ];

        let extents = decode_data_runs(&runlist, &boot).unwrap();
        assert_eq!(extents.len(), 2);

        // Run 1: LCN 100 -> LBA = 2048 + (100 * 8) = 2848, block_count = 16 * 8 = 128
        assert_eq!(extents[0], (2848, 128));

        // Run 2: LCN 150 -> LBA = 2048 + (150 * 8) = 3248, block_count = 32 * 8 = 256
        assert_eq!(extents[1], (3248, 256));
    }
}
