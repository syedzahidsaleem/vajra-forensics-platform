//! NTFS Master File Table ($MFT) record and attribute parsing (§25).
//!
//! Reference: SleuthKit `tsk/fs/ntfs.c`, `tsk/fs/tsk_ntfs.h`.

use crate::boot::NtfsBoot;
use crate::error::NtfsError;
use chrono::{DateTime, TimeZone, Utc};
use vajra_core::DataLocation;

pub const MFT_MAGIC_FILE: &[u8; 4] = b"FILE";
pub const MFT_MAGIC_BAAD: &[u8; 4] = b"BAAD";

// Attribute Type Constants
pub const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_TYPE_FILE_NAME: u32 = 0x30;
pub const ATTR_TYPE_OBJECT_ID: u32 = 0x40;
pub const ATTR_TYPE_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const ATTR_TYPE_VOLUME_NAME: u32 = 0x60;
pub const ATTR_TYPE_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTR_TYPE_DATA: u32 = 0x80;
pub const ATTR_TYPE_INDEX_ROOT: u32 = 0x90;
pub const ATTR_TYPE_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_TYPE_BITMAP: u32 = 0xB0;

/// Parsed NTFS MFT record.
#[derive(Debug, Clone)]
pub struct MftRecord {
    pub record_num: u64,
    pub sequence_num: u16,
    pub is_in_use: bool,
    pub is_directory: bool,
    pub base_record_ref: u64,
    pub standard_info: Option<StandardInformationAttr>,
    pub file_names: Vec<FileNameAttr>,
    pub data_attributes: Vec<DataAttr>,
}

impl MftRecord {
    /// Returns the primary/best filename (prefers Win32 / POSIX over DOS 8.3).
    pub fn display_name(&self) -> Option<String> {
        // Namespace preference: 1 (Win32) or 3 (Win32 & DOS), then 0 (POSIX), then 2 (DOS)
        if let Some(fn_attr) = self.file_names.iter().find(|f| f.namespace == 1 || f.namespace == 3) {
            return Some(fn_attr.name.clone());
        }
        if let Some(fn_attr) = self.file_names.first() {
            return Some(fn_attr.name.clone());
        }
        None
    }

    /// Returns the primary unnamed `$DATA` stream.
    pub fn default_data_stream(&self) -> Option<&DataAttr> {
        self.data_attributes.iter().find(|d| d.name.is_empty())
    }
}

/// Parsed `$STANDARD_INFORMATION` attribute (0x10).
#[derive(Debug, Clone)]
pub struct StandardInformationAttr {
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub mft_modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub dos_flags: u32,
}

/// Parsed `$FILE_NAME` attribute (0x30).
#[derive(Debug, Clone)]
pub struct FileNameAttr {
    pub parent_mft_ref: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub mft_modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub allocated_size: u64,
    pub real_size: u64,
    pub namespace: u8,
    pub name: String,
}

/// Parsed `$DATA` attribute (0x80) — resident or non-resident.
#[derive(Debug, Clone)]
pub struct DataAttr {
    pub name: String,
    pub is_non_resident: bool,
    pub allocated_size: u64,
    pub real_size: u64,
    pub location: DataLocation,
}

/// Applies update sequence fixups to a raw MFT record buffer (TSK `ntfs_fixup`).
pub fn apply_mft_fixup(buffer: &mut [u8], record_num: u64) -> Result<(), NtfsError> {
    if buffer.len() < 48 {
        return Err(NtfsError::FixupFailed(record_num));
    }

    if &buffer[0..4] != MFT_MAGIC_FILE && &buffer[0..4] != MFT_MAGIC_BAAD {
        let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        return Err(NtfsError::InvalidMftMagic(magic));
    }

    let upd_off = u16::from_le_bytes([buffer[4], buffer[5]]) as usize;
    let upd_cnt = u16::from_le_bytes([buffer[6], buffer[7]]) as usize;

    if upd_cnt == 0 || upd_off + (upd_cnt * 2) > buffer.len() {
        return Err(NtfsError::FixupFailed(record_num));
    }

    let expected_sig = u16::from_le_bytes([buffer[upd_off], buffer[upd_off + 1]]);

    for i in 1..upd_cnt {
        let sector_end_offset = (i * 512) - 2;
        if sector_end_offset + 2 > buffer.len() {
            break;
        }

        let actual_sig = u16::from_le_bytes([
            buffer[sector_end_offset],
            buffer[sector_end_offset + 1],
        ]);

        if actual_sig != expected_sig {
            // Note: If record is deleted or partially corrupted, log/tolerate or flag
            return Err(NtfsError::FixupFailed(record_num));
        }

        let repl_offset = upd_off + (i * 2);
        let replacement = [buffer[repl_offset], buffer[repl_offset + 1]];
        buffer[sector_end_offset..sector_end_offset + 2].copy_from_slice(&replacement);
    }

    Ok(())
}

/// Parses an MFT record from fixed-up record bytes.
pub fn parse_mft_record(
    record_num: u64,
    record_bytes: &[u8],
    boot: &NtfsBoot,
) -> Result<MftRecord, NtfsError> {
    if record_bytes.len() < 48 {
        return Err(NtfsError::CorruptedAttribute(0, record_num));
    }

    let sequence_num = u16::from_le_bytes([record_bytes[16], record_bytes[17]]);
    let first_attr_off = u16::from_le_bytes([record_bytes[20], record_bytes[21]]) as usize;
    let flags = u16::from_le_bytes([record_bytes[22], record_bytes[23]]);
    let base_record_ref = u64::from_le_bytes([
        record_bytes[32], record_bytes[33], record_bytes[34], record_bytes[35],
        record_bytes[36], record_bytes[37], record_bytes[38], record_bytes[39],
    ]) & 0x0000_FFFF_FFFF_FFFF;

    let is_in_use = (flags & 0x01) != 0;
    let is_directory = (flags & 0x02) != 0;

    let mut standard_info = None;
    let mut file_names = Vec::new();
    let mut data_attributes = Vec::new();

    let mut attr_offset = first_attr_off;

    while attr_offset + 16 <= record_bytes.len() {
        let attr_type = u32::from_le_bytes([
            record_bytes[attr_offset],
            record_bytes[attr_offset + 1],
            record_bytes[attr_offset + 2],
            record_bytes[attr_offset + 3],
        ]);

        if attr_type == 0xFFFF_FFFF || attr_type == 0 {
            // End of attribute list marker
            break;
        }

        let attr_len = u32::from_le_bytes([
            record_bytes[attr_offset + 4],
            record_bytes[attr_offset + 5],
            record_bytes[attr_offset + 6],
            record_bytes[attr_offset + 7],
        ]) as usize;

        if attr_len < 16 || attr_offset + attr_len > record_bytes.len() {
            break;
        }

        let non_resident_flag = record_bytes[attr_offset + 8];
        let name_len = record_bytes[attr_offset + 9] as usize;
        let name_offset = u16::from_le_bytes([
            record_bytes[attr_offset + 10],
            record_bytes[attr_offset + 11],
        ]) as usize;

        let attr_name = if name_len > 0 && attr_offset + name_offset + (name_len * 2) <= record_bytes.len() {
            let u16_chars: Vec<u16> = (0..name_len)
                .map(|i| {
                    let pos = attr_offset + name_offset + (i * 2);
                    u16::from_le_bytes([record_bytes[pos], record_bytes[pos + 1]])
                })
                .collect();
            String::from_utf16_lossy(&u16_chars)
        } else {
            String::new()
        };

        if non_resident_flag == 0 {
            // --- RESIDENT ATTRIBUTE ---
            let value_len = u32::from_le_bytes([
                record_bytes[attr_offset + 16],
                record_bytes[attr_offset + 17],
                record_bytes[attr_offset + 18],
                record_bytes[attr_offset + 19],
            ]) as usize;
            let value_offset = u16::from_le_bytes([
                record_bytes[attr_offset + 20],
                record_bytes[attr_offset + 21],
            ]) as usize;

            let val_start = attr_offset + value_offset;
            let val_end = val_start + value_len;

            if val_end <= record_bytes.len() {
                let value_data = &record_bytes[val_start..val_end];

                match attr_type {
                    ATTR_TYPE_STANDARD_INFORMATION => {
                        if value_data.len() >= 36 {
                            let crt = filetime_to_datetime(u64::from_le_bytes(value_data[0..8].try_into().unwrap()));
                            let mod_t = filetime_to_datetime(u64::from_le_bytes(value_data[8..16].try_into().unwrap()));
                            let mft_mod = filetime_to_datetime(u64::from_le_bytes(value_data[16..24].try_into().unwrap()));
                            let acc = filetime_to_datetime(u64::from_le_bytes(value_data[24..32].try_into().unwrap()));
                            let dos_flags = u32::from_le_bytes(value_data[32..36].try_into().unwrap());

                            standard_info = Some(StandardInformationAttr {
                                created: crt,
                                modified: mod_t,
                                mft_modified: mft_mod,
                                accessed: acc,
                                dos_flags,
                            });
                        }
                    }
                    ATTR_TYPE_FILE_NAME => {
                        if value_data.len() >= 66 {
                            let parent_ref = u64::from_le_bytes(value_data[0..8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
                            let crt = filetime_to_datetime(u64::from_le_bytes(value_data[8..16].try_into().unwrap()));
                            let mod_t = filetime_to_datetime(u64::from_le_bytes(value_data[16..24].try_into().unwrap()));
                            let mft_mod = filetime_to_datetime(u64::from_le_bytes(value_data[24..32].try_into().unwrap()));
                            let acc = filetime_to_datetime(u64::from_le_bytes(value_data[32..40].try_into().unwrap()));
                            let alloc_sz = u64::from_le_bytes(value_data[40..48].try_into().unwrap());
                            let real_sz = u64::from_le_bytes(value_data[48..56].try_into().unwrap());
                            let fn_len = value_data[64] as usize;
                            let namespace = value_data[65];

                            if value_data.len() >= 66 + (fn_len * 2) {
                                let u16_chars: Vec<u16> = (0..fn_len)
                                    .map(|i| {
                                        let pos = 66 + (i * 2);
                                        u16::from_le_bytes([value_data[pos], value_data[pos + 1]])
                                    })
                                    .collect();
                                let fn_name = String::from_utf16_lossy(&u16_chars);

                                file_names.push(FileNameAttr {
                                    parent_mft_ref: parent_ref,
                                    created: crt,
                                    modified: mod_t,
                                    mft_modified: mft_mod,
                                    accessed: acc,
                                    allocated_size: alloc_sz,
                                    real_size: real_sz,
                                    namespace,
                                    name: fn_name,
                                });
                            }
                        }
                    }
                    ATTR_TYPE_DATA => {
                        data_attributes.push(DataAttr {
                            name: attr_name,
                            is_non_resident: false,
                            allocated_size: value_len as u64,
                            real_size: value_len as u64,
                            location: DataLocation::Resident(value_data.to_vec()),
                        });
                    }
                    _ => {}
                }
            }
        } else {
            // --- NON-RESIDENT ATTRIBUTE ---
            if attr_offset + 64 <= record_bytes.len() {
                let runlist_offset = u16::from_le_bytes([
                    record_bytes[attr_offset + 32],
                    record_bytes[attr_offset + 33],
                ]) as usize;
                let allocated_size = u64::from_le_bytes([
                    record_bytes[attr_offset + 40], record_bytes[attr_offset + 41],
                    record_bytes[attr_offset + 42], record_bytes[attr_offset + 43],
                    record_bytes[attr_offset + 44], record_bytes[attr_offset + 45],
                    record_bytes[attr_offset + 46], record_bytes[attr_offset + 47],
                ]);
                let real_size = u64::from_le_bytes([
                    record_bytes[attr_offset + 48], record_bytes[attr_offset + 49],
                    record_bytes[attr_offset + 50], record_bytes[attr_offset + 51],
                    record_bytes[attr_offset + 52], record_bytes[attr_offset + 53],
                    record_bytes[attr_offset + 54], record_bytes[attr_offset + 55],
                ]);

                if attr_offset + runlist_offset <= record_bytes.len() {
                    let runlist_bytes = &record_bytes[attr_offset + runlist_offset..attr_offset + attr_len];
                    if let Ok(extents) = decode_data_runs(runlist_bytes, boot) {
                        let location = if extents.is_empty() {
                            DataLocation::Unresolved
                        } else if extents.len() == 1 {
                            DataLocation::Contiguous {
                                start_lba: extents[0].0,
                                block_count: extents[0].1,
                            }
                        } else {
                            DataLocation::Fragmented(extents)
                        };

                        if attr_type == ATTR_TYPE_DATA {
                            data_attributes.push(DataAttr {
                                name: attr_name,
                                is_non_resident: true,
                                allocated_size,
                                real_size,
                                location,
                            });
                        }
                    }
                }
            }
        }

        attr_offset += attr_len;
    }

    Ok(MftRecord {
        record_num,
        sequence_num,
        is_in_use,
        is_directory,
        base_record_ref,
        standard_info,
        file_names,
        data_attributes,
    })
}

/// Decodes variable-length NTFS cluster runlists (TSK `ntfs_make_data_run`).
///
/// Returns a list of (start_lba, block_count) physical extents.
pub fn decode_data_runs(runlist: &[u8], boot: &NtfsBoot) -> Result<Vec<(u64, u64)>, NtfsError> {
    let mut extents = Vec::new();
    let mut offset = 0;
    let mut prev_lcn: i64 = 0;

    let sectors_per_clus = boot.sectors_per_cluster as u64;

    while offset < runlist.len() {
        let header = runlist[offset];
        if header == 0 {
            break; // 0x00 terminates runlist
        }

        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;

        offset += 1;
        if offset + len_bytes + off_bytes > runlist.len() {
            return Err(NtfsError::InvalidDataRun(offset));
        }

        // Decode length (unsigned)
        let mut cluster_count: u64 = 0;
        for i in 0..len_bytes {
            cluster_count |= (runlist[offset + i] as u64) << (i * 8);
        }
        offset += len_bytes;

        // Decode offset (signed delta relative to previous LCN)
        if off_bytes == 0 {
            // Sparse run (no clusters allocated on disk)
            // Extent with 0 start LBA
            offset += off_bytes;
            continue;
        }

        let mut lcn_delta: i64 = 0;
        for i in 0..off_bytes {
            lcn_delta |= (runlist[offset + i] as i64) << (i * 8);
        }
        // Sign extension if high bit is set
        if (runlist[offset + off_bytes - 1] & 0x80) != 0 {
            for i in off_bytes..8 {
                lcn_delta |= (0xFFi64) << (i * 8);
            }
        }
        offset += off_bytes;

        let current_lcn = prev_lcn + lcn_delta;
        prev_lcn = current_lcn;

        if current_lcn >= 0 && cluster_count > 0 {
            let start_lba = boot.lcn_to_lba(current_lcn as u64);
            let block_count = cluster_count * sectors_per_clus;
            extents.push((start_lba, block_count));
        }
    }

    Ok(extents)
}

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since Jan 1, 1601) to `DateTime<Utc>`.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    // 116444736000000000 is 100-ns intervals between 1601-01-01 and 1970-01-01
    const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;
    if filetime < FILETIME_UNIX_DIFF {
        return None;
    }
    let intervals_since_1970 = filetime - FILETIME_UNIX_DIFF;
    let secs = (intervals_since_1970 / 10_000_000) as i64;
    let nanos = ((intervals_since_1970 % 10_000_000) * 100) as u32;

    Utc.timestamp_opt(secs, nanos).single()
}
