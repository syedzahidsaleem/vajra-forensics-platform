//! FAT directory entry (8.3 and Long Filename LFN) parsing (§25).
//!
//! Reference: SleuthKit `tsk/fs/fatfs_dent.cpp`, `tsk/fs/fatxxfs_dent.c`.

use chrono::{DateTime, TimeZone, Utc};

/// Parsed FAT directory entry with recovered metadata.
#[derive(Debug, Clone)]
pub struct FatDirEntry {
    pub name_83: String,
    pub lfn_name: Option<String>,
    pub is_deleted: bool,
    pub is_directory: bool,
    pub is_volume_label: bool,
    pub start_cluster: u32,
    pub file_size: u64,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub accessed_at: Option<DateTime<Utc>>,
}

impl FatDirEntry {
    /// Returns the best available filename (LFN if present, else 8.3).
    pub fn display_name(&self) -> String {
        if let Some(ref lfn) = self.lfn_name {
            if !lfn.trim().is_empty() {
                return lfn.clone();
            }
        }
        self.name_83.clone()
    }
}

/// Accumulator for Long Filename (LFN) 32-byte chunk entries preceding standard entries.
#[derive(Debug, Default)]
pub struct LfnAccumulator {
    chunks: Vec<(u8, String)>,
    is_deleted: bool,
}

impl LfnAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds an LFN chunk (32 bytes with attribute 0x0F).
    pub fn feed(&mut self, entry_bytes: &[u8]) {
        if entry_bytes.len() < 32 || entry_bytes[11] != 0x0F {
            return;
        }

        let seq_byte = entry_bytes[0];
        let is_del = seq_byte == 0xE5;
        let seq_num = seq_byte & 0x1F;

        if is_del {
            self.is_deleted = true;
        }

        // Extract 13 UTF-16LE characters from LFN fields:
        // name1: offset 1..11 (5 chars)
        // name2: offset 14..26 (6 chars)
        // name3: offset 28..32 (2 chars)
        let mut u16_chars = Vec::with_capacity(13);

        for i in 0..5 {
            let ch = u16::from_le_bytes([entry_bytes[1 + i * 2], entry_bytes[2 + i * 2]]);
            if ch == 0x0000 || ch == 0xFFFF {
                break;
            }
            u16_chars.push(ch);
        }
        if u16_chars.len() == 5 {
            for i in 0..6 {
                let ch = u16::from_le_bytes([entry_bytes[14 + i * 2], entry_bytes[15 + i * 2]]);
                if ch == 0x0000 || ch == 0xFFFF {
                    break;
                }
                u16_chars.push(ch);
            }
        }
        if u16_chars.len() == 11 {
            for i in 0..2 {
                let ch = u16::from_le_bytes([entry_bytes[28 + i * 2], entry_bytes[29 + i * 2]]);
                if ch == 0x0000 || ch == 0xFFFF {
                    break;
                }
                u16_chars.push(ch);
            }
        }

        let chunk_str = String::from_utf16_lossy(&u16_chars);
        self.chunks.push((seq_num, chunk_str));
    }

    /// Reconstructs the complete long filename and clears the accumulator.
    pub fn finalize(&mut self) -> Option<String> {
        if self.chunks.is_empty() {
            return None;
        }

        if self.is_deleted {
            // Deleted LFN chunks all have byte 0 = 0xE5 (seq_num destroyed).
            // Since they are written in reverse order on disk (last chunk first),
            // reversing the collected list restores chunk 1, chunk 2, ... chunk N order.
            self.chunks.reverse();
        } else {
            // Live LFN chunks have intact sequence numbers 1..=N
            self.chunks.sort_by_key(|&(seq, _)| seq);
        }

        let mut full_name = String::new();
        for (_, chunk) in &self.chunks {
            full_name.push_str(chunk);
        }

        self.chunks.clear();
        self.is_deleted = false;

        let trimmed = full_name.trim_matches('\0').trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    /// Clears any orphan LFN chunks.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.is_deleted = false;
    }
}

/// Parses a 32-byte standard directory entry.
pub fn parse_standard_entry(bytes: &[u8], lfn_name: Option<String>) -> Option<FatDirEntry> {
    if bytes.len() < 32 {
        return None;
    }

    let first_byte = bytes[0];
    if first_byte == 0x00 {
        // End of directory marker
        return None;
    }

    let is_deleted = first_byte == 0xE5;
    let attr = bytes[11];

    // Skip LFN entries (0x0F) in standard parser
    if attr == 0x0F {
        return None;
    }

    let is_directory = (attr & 0x10) != 0;
    let is_volume_label = (attr & 0x08) != 0;

    // Parse 8.3 name
    let mut name_part = bytes[0..8].to_vec();
    if is_deleted {
        // Replace 0xE5 with '_' or '?' placeholder to restore the rest of the 8.3 name
        name_part[0] = b'_';
    } else if name_part[0] == 0x05 {
        // Kanji lead byte replacement
        name_part[0] = 0xE5;
    }

    let base_name = String::from_utf8_lossy(&name_part).trim().to_string();
    let ext_part = String::from_utf8_lossy(&bytes[8..11]).trim().to_string();

    let name_83 = if is_directory || ext_part.is_empty() {
        base_name
    } else {
        format!("{}.{}", base_name, ext_part)
    };

    let start_cluster_hi = u16::from_le_bytes([bytes[20], bytes[21]]) as u32;
    let start_cluster_lo = u16::from_le_bytes([bytes[26], bytes[27]]) as u32;
    let start_cluster = (start_cluster_hi << 16) | start_cluster_lo;

    let file_size = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]) as u64;

    let crt_time = u16::from_le_bytes([bytes[14], bytes[15]]);
    let crt_date = u16::from_le_bytes([bytes[16], bytes[17]]);
    let created_at = dos_datetime_to_utc(crt_date, crt_time);

    let wrt_time = u16::from_le_bytes([bytes[22], bytes[23]]);
    let wrt_date = u16::from_le_bytes([bytes[24], bytes[25]]);
    let modified_at = dos_datetime_to_utc(wrt_date, wrt_time);

    let acc_date = u16::from_le_bytes([bytes[18], bytes[19]]);
    let accessed_at = dos_datetime_to_utc(acc_date, 0);

    Some(FatDirEntry {
        name_83,
        lfn_name,
        is_deleted,
        is_directory,
        is_volume_label,
        start_cluster,
        file_size,
        created_at,
        modified_at,
        accessed_at,
    })
}

/// Converts MS-DOS 16-bit Date and 16-bit Time to `DateTime<Utc>`.
pub fn dos_datetime_to_utc(dos_date: u16, dos_time: u16) -> Option<DateTime<Utc>> {
    if dos_date == 0 {
        return None;
    }

    let year = ((dos_date >> 9) & 0x7F) as i32 + 1980;
    let month = ((dos_date >> 5) & 0x0F) as u32;
    let day = (dos_date & 0x1F) as u32;

    let hour = ((dos_time >> 11) & 0x1F) as u32;
    let minute = ((dos_time >> 5) & 0x3F) as u32;
    let second = ((dos_time & 0x1F) * 2) as u32;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()
}
