//! NTFS $LogFile and $UsnJrnl change journal basic inspection (§25).
//!
//! Reference: SleuthKit `tsk/fs/usn_journal.c`.

use crate::mft::filetime_to_datetime;
use chrono::{DateTime, Utc};

// USN Reason Flags
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;

/// Parsed USN Journal record entry.
#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub usn: u64,
    pub mft_record_ref: u64,
    pub parent_mft_ref: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub reason: u32,
    pub filename: String,
    pub is_deletion: bool,
}

/// Parses USN change journal records from a `$UsnJrnl:$J` stream buffer.
pub fn parse_usn_records(buffer: &[u8]) -> Vec<UsnRecord> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset + 60 <= buffer.len() {
        let record_len = u32::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;

        if record_len < 60 || offset + record_len > buffer.len() {
            // Advance by 8 bytes or search for next valid record header
            offset += 8;
            continue;
        }

        let major_ver = u16::from_le_bytes([buffer[offset + 4], buffer[offset + 5]]);
        if major_ver != 2 && major_ver != 3 {
            offset += 8;
            continue;
        }

        let mft_ref = u64::from_le_bytes(buffer[offset + 8..offset + 16].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
        let parent_ref = u64::from_le_bytes(buffer[offset + 16..offset + 24].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
        let usn = u64::from_le_bytes(buffer[offset + 24..offset + 32].try_into().unwrap());
        let ft = u64::from_le_bytes(buffer[offset + 32..offset + 40].try_into().unwrap());
        let reason = u32::from_le_bytes(buffer[offset + 40..offset + 44].try_into().unwrap());

        let fn_len = u16::from_le_bytes([buffer[offset + 56], buffer[offset + 57]]) as usize;
        let fn_offset = u16::from_le_bytes([buffer[offset + 58], buffer[offset + 59]]) as usize;

        if offset + fn_offset + fn_len <= offset + record_len {
            let u16_chars: Vec<u16> = buffer[offset + fn_offset..offset + fn_offset + fn_len]
                .chunks_exact(2)
                .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                .collect();
            let filename = String::from_utf16_lossy(&u16_chars);

            let is_deletion = (reason & USN_REASON_FILE_DELETE) != 0;
            let timestamp = filetime_to_datetime(ft);

            records.push(UsnRecord {
                usn,
                mft_record_ref: mft_ref,
                parent_mft_ref: parent_ref,
                timestamp,
                reason,
                filename,
                is_deletion,
            });
        }

        offset += record_len;
    }

    records
}
