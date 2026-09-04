//! OLE2 / Microsoft Compound File Binary (CFB) Structural Validator (§26.2, §28).
//!
//! Implements the legacy DOC/XLS/PPT container validator that §26.2 specifies as
//! *"Validate FAT/MiniFAT sector-chain consistency within the compound file structure"*.
//!
//! Reference: `[MS-CFB]` Compound File Binary File Format, plus Garfinkel (DFRWS 2007),
//! which uses MSOLE as its worked example of a format whose Sector Allocation Table
//! yields an exact `object_length` directly rather than requiring a footer search.
//!
//! # Validation order
//!
//! The checks are deliberately ordered so `V_EOF` (ran out of data) is never confused
//! with `V_ERR` (structurally impossible). Everything that can be decided from bytes
//! already in hand is decided first; the exact object length is derived from the FAT
//! before any chain is walked, so every subsequent access is provably in bounds.
//!
//! 1. 8-byte signature, byte-order mark, major version, reserved field.
//! 2. Sector shift / mini-sector shift / mini-stream cutoff geometry.
//! 3. Header counter sanity (directory sector count, FAT sector count, DIFAT count).
//! 4. DIFAT collection — the header's 109 entries plus the DIFAT sector chain, with
//!    loop detection and bounds checking.
//! 5. FAT assembly from the collected FAT sector list.
//! 6. Exact object length from the highest allocated FAT entry → `V_OK.object_length`.
//! 7. FAT self-consistency: every FAT sector marked `FATSECT`, every DIFAT sector
//!    marked `DIFSECT`, every regular entry within FAT bounds.
//! 8. Directory chain walk with loop detection, then per-entry validation
//!    (root entry, object types, name lengths, sibling/child bounds, stream chains).
//! 9. MiniFAT chain walk and mini-stream chain walk where present.
//!
//! Flags: `err_is_prefix: false`, `appended_data_ignored: true`, `no_zblocks: false`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};
use std::collections::HashSet;

/// OLE2 / CFB 8-byte magic signature at offset 0x00.
pub const OLE2_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

// --- [MS-CFB] reserved sector identifiers -----------------------------------
/// Largest sector id that refers to an actual sector (`MAXREGSECT`).
const MAXREGSECT: u32 = 0xFFFF_FFFA;
/// Sector is part of the DIFAT.
const DIFSECT: u32 = 0xFFFF_FFFC;
/// Sector is part of the FAT.
const FATSECT: u32 = 0xFFFF_FFFD;
/// Terminator of a sector chain.
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// Unallocated sector.
const FREESECT: u32 = 0xFFFF_FFFF;
/// "No directory entry" sentinel used by sibling/child pointers.
const NOSTREAM: u32 = 0xFFFF_FFFF;

// --- Header geometry --------------------------------------------------------
const HEADER_LEN: usize = 512;
const DIR_ENTRY_LEN: usize = 128;
const DIFAT_HEADER_ENTRIES: usize = 109;
const DIFAT_HEADER_OFFSET: usize = 0x4C;
const REQUIRED_MINI_SECTOR_SHIFT: u16 = 6;
const REQUIRED_MINI_STREAM_CUTOFF: u32 = 4096;
const BYTE_ORDER_LITTLE_ENDIAN: u16 = 0xFFFE;

// --- Directory entry object types ------------------------------------------
const OBJ_UNALLOCATED: u8 = 0x00;
const OBJ_STORAGE: u8 = 0x01;
const OBJ_STREAM: u8 = 0x02;
const OBJ_ROOT: u8 = 0x05;

/// Implausibility bound on the declared FAT sector count.
///
/// 8192 FAT sectors addresses ~537 MB at 512-byte sectors and ~34 GB at 4096-byte
/// sectors — comfortably above the 100 MB `max_size_bytes` this format is registered
/// with in `config/signatures.json`. A larger declared count in a carved candidate is
/// a corrupted header, not a real compound file, and is rejected rather than trusted
/// (an unbounded count would otherwise drive an unbounded allocation).
const MAX_PLAUSIBLE_FAT_SECTORS: u32 = 8192;

/// Implausibility bound on the declared DIFAT sector count, same reasoning.
const MAX_PLAUSIBLE_DIFAT_SECTORS: u32 = 8192;

#[inline]
fn u16_le(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off + 1]])
}

#[inline]
fn u32_le(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

#[inline]
fn u64_le(d: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Byte offset of a sector's payload. Sector 0 begins immediately after the
/// header sector, so sector `n` starts at `(n + 1) * sector_size`.
#[inline]
fn sector_offset(sector: u32, sector_size: usize) -> u64 {
    (sector as u64 + 1) * sector_size as u64
}

/// Number of sectors needed to hold `size` bytes.
#[inline]
fn sectors_for(size: u64, sector_size: usize) -> u64 {
    size.div_ceil(sector_size as u64)
}

#[derive(Debug, Default, Clone)]
pub struct Ole2Validator;

impl StructuralValidator for Ole2Validator {
    fn file_type(&self) -> &'static str {
        "ole2"
    }

    fn flags(&self) -> ValidatorFlags {
        // Reasoned engineering rationale (§26.2 states all three of these directly
        // for MSOLE, so these values are cited from the blueprint, not assumed):
        // - err_is_prefix: false — MSOLE has no sequential-scan property. The FAT is
        //   a random-access allocation table, not a stream parsed front-to-back, so a
        //   failure at one offset says nothing about whether a longer candidate parses.
        //   §26.2: "false for MSOLE, which has no such sequential-scan property, so
        //   length must be found by binary search instead."
        // - appended_data_ignored: true — the Sector Allocation Table gives the object's
        //   exact extent, so every standard CFB reader stops at the last allocated
        //   sector and ignores trailing bytes. This is what makes `object_length` exact
        //   below, and what lets the carver keep the sector-padded tail of a candidate.
        // - no_zblocks: false — a compound file legitimately contains all-zero sectors
        //   (unallocated sectors inside the allocated range, zero-padded stream tails,
        //   and the zero remainder of the header sector in v4). §26.2: "MSOLE frequently
        //   does [contain all-null sectors]". Enabling the zero-block early reject here
        //   would discard genuine evidence, so it stays off.
        ValidatorFlags {
            err_is_prefix: false,
            appended_data_ignored: true,
            no_zblocks: false,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        // --- 1. Header presence -------------------------------------------------
        if data.len() < HEADER_LEN {
            return ValidationResult::Eof {
                partial_length: data.len() as u64,
            };
        }

        // --- 2. Signature -------------------------------------------------------
        if data[0..8] != OLE2_SIGNATURE {
            return ValidationResult::Err(
                "Invalid OLE2/CFB 8-byte signature (expected D0 CF 11 E0 A1 B1 1A E1)".to_string(),
            );
        }

        // --- 3. Byte order, version, reserved ----------------------------------
        let byte_order = u16_le(data, 0x1C);
        if byte_order != BYTE_ORDER_LITTLE_ENDIAN {
            return ValidationResult::Err(format!(
                "Invalid OLE2 byte-order mark 0x{:04X} (expected 0xFFFE little-endian)",
                byte_order
            ));
        }

        let major_version = u16_le(data, 0x1A);
        if major_version != 3 && major_version != 4 {
            return ValidationResult::Err(format!(
                "Unsupported OLE2 major version {} (expected 3 or 4)",
                major_version
            ));
        }

        // [MS-CFB] 2.2: the 6 reserved bytes MUST be zero. A non-zero value here is a
        // reliable, cheap corruption signal in carved candidates.
        if data[0x22..0x28].iter().any(|&b| b != 0) {
            return ValidationResult::Err(
                "OLE2 header reserved field (offset 0x22..0x28) is non-zero".to_string(),
            );
        }

        // --- 4. Sector geometry -------------------------------------------------
        let sector_shift = u16_le(data, 0x1E);
        let expected_shift = if major_version == 3 { 9 } else { 12 };
        if sector_shift != expected_shift {
            return ValidationResult::Err(format!(
                "Invalid OLE2 sector shift {} for major version {} (expected {})",
                sector_shift, major_version, expected_shift
            ));
        }
        let sector_size = 1usize << sector_shift;

        let mini_sector_shift = u16_le(data, 0x20);
        if mini_sector_shift != REQUIRED_MINI_SECTOR_SHIFT {
            return ValidationResult::Err(format!(
                "Invalid OLE2 mini-sector shift {} (specification requires 6 / 64-byte mini sectors)",
                mini_sector_shift
            ));
        }
        let mini_sector_size = 1usize << mini_sector_shift;

        let mini_stream_cutoff = u32_le(data, 0x38);
        if mini_stream_cutoff != REQUIRED_MINI_STREAM_CUTOFF {
            return ValidationResult::Err(format!(
                "Invalid OLE2 mini-stream cutoff {} (specification requires 4096)",
                mini_stream_cutoff
            ));
        }

        // --- 5. Header counters -------------------------------------------------
        let num_dir_sectors = u32_le(data, 0x28);
        if major_version == 3 && num_dir_sectors != 0 {
            return ValidationResult::Err(format!(
                "OLE2 v3 header declares {} directory sectors (must be 0 for version 3)",
                num_dir_sectors
            ));
        }

        let num_fat_sectors = u32_le(data, 0x2C);
        if num_fat_sectors == 0 {
            return ValidationResult::Err(
                "OLE2 header declares 0 FAT sectors (a compound file always has at least one)"
                    .to_string(),
            );
        }
        if num_fat_sectors > MAX_PLAUSIBLE_FAT_SECTORS {
            return ValidationResult::Err(format!(
                "OLE2 header declares an implausible {} FAT sectors (bound: {})",
                num_fat_sectors, MAX_PLAUSIBLE_FAT_SECTORS
            ));
        }

        let first_dir_sector = u32_le(data, 0x30);
        if first_dir_sector > MAXREGSECT {
            return ValidationResult::Err(format!(
                "OLE2 first directory sector is reserved id 0x{:08X}, not a regular sector",
                first_dir_sector
            ));
        }

        let first_minifat_sector = u32_le(data, 0x3C);
        let num_minifat_sectors = u32_le(data, 0x40);
        let first_difat_sector = u32_le(data, 0x44);
        let num_difat_sectors = u32_le(data, 0x48);

        if num_difat_sectors > MAX_PLAUSIBLE_DIFAT_SECTORS {
            return ValidationResult::Err(format!(
                "OLE2 header declares an implausible {} DIFAT sectors (bound: {})",
                num_difat_sectors, MAX_PLAUSIBLE_DIFAT_SECTORS
            ));
        }
        if num_difat_sectors == 0 && first_difat_sector != ENDOFCHAIN {
            return ValidationResult::Err(format!(
                "OLE2 header declares 0 DIFAT sectors but first DIFAT sector is 0x{:08X} (expected ENDOFCHAIN)",
                first_difat_sector
            ));
        }
        if num_minifat_sectors == 0 && first_minifat_sector != ENDOFCHAIN {
            return ValidationResult::Err(format!(
                "OLE2 header declares 0 MiniFAT sectors but first MiniFAT sector is 0x{:08X} (expected ENDOFCHAIN)",
                first_minifat_sector
            ));
        }

        // --- 6. DIFAT collection ------------------------------------------------
        // The DIFAT is the list of sector ids that hold the FAT itself. The first 109
        // entries live in the header; any remainder lives in a chain of DIFAT sectors.
        let entries_per_sector = sector_size / 4;
        let mut fat_sector_ids: Vec<u32> = Vec::new();
        let mut difat_sector_ids: Vec<u32> = Vec::new();

        for i in 0..DIFAT_HEADER_ENTRIES {
            if fat_sector_ids.len() == num_fat_sectors as usize {
                break;
            }
            let entry = u32_le(data, DIFAT_HEADER_OFFSET + i * 4);
            if entry == FREESECT || entry == ENDOFCHAIN {
                break;
            }
            if entry > MAXREGSECT {
                return ValidationResult::Err(format!(
                    "OLE2 header DIFAT slot {} holds reserved id 0x{:08X}, not a regular sector",
                    i, entry
                ));
            }
            fat_sector_ids.push(entry);
        }

        // Walk the DIFAT sector chain for any FAT sector ids beyond the header's 109.
        if fat_sector_ids.len() < num_fat_sectors as usize {
            if first_difat_sector > MAXREGSECT {
                return ValidationResult::Err(format!(
                    "OLE2 declares {} FAT sectors but only {} fit in the header DIFAT and no DIFAT chain is present",
                    num_fat_sectors,
                    fat_sector_ids.len()
                ));
            }

            let mut visited: HashSet<u32> = HashSet::new();
            let mut current = first_difat_sector;

            while current != ENDOFCHAIN && fat_sector_ids.len() < num_fat_sectors as usize {
                if current > MAXREGSECT {
                    return ValidationResult::Err(format!(
                        "OLE2 DIFAT chain contains reserved sector id 0x{:08X}",
                        current
                    ));
                }
                if !visited.insert(current) {
                    return ValidationResult::Err(format!(
                        "OLE2 DIFAT chain loops at sector {}",
                        current
                    ));
                }
                if visited.len() > num_difat_sectors as usize {
                    return ValidationResult::Err(format!(
                        "OLE2 DIFAT chain is longer than the {} DIFAT sectors declared in the header",
                        num_difat_sectors
                    ));
                }

                let start = sector_offset(current, sector_size);
                let end = start + sector_size as u64;
                if end > data.len() as u64 {
                    return ValidationResult::Eof {
                        partial_length: data.len() as u64,
                    };
                }
                let start = start as usize;
                difat_sector_ids.push(current);

                // The last u32 of a DIFAT sector is the next DIFAT sector pointer.
                for i in 0..entries_per_sector - 1 {
                    if fat_sector_ids.len() == num_fat_sectors as usize {
                        break;
                    }
                    let entry = u32_le(data, start + i * 4);
                    if entry == FREESECT || entry == ENDOFCHAIN {
                        break;
                    }
                    if entry > MAXREGSECT {
                        return ValidationResult::Err(format!(
                            "OLE2 DIFAT sector {} slot {} holds reserved id 0x{:08X}",
                            current, i, entry
                        ));
                    }
                    fat_sector_ids.push(entry);
                }

                current = u32_le(data, start + (entries_per_sector - 1) * 4);
            }
        }

        if fat_sector_ids.len() != num_fat_sectors as usize {
            return ValidationResult::Err(format!(
                "OLE2 DIFAT yields {} FAT sector ids but the header declares {}",
                fat_sector_ids.len(),
                num_fat_sectors
            ));
        }

        // --- 7. FAT assembly ----------------------------------------------------
        // Read only the FAT sectors that actually exist in the candidate. Anything
        // referenced beyond the data we hold is truncation (V_EOF), not corruption.
        let mut fat: Vec<u32> = Vec::with_capacity(fat_sector_ids.len() * entries_per_sector);
        for &fs in &fat_sector_ids {
            let start = sector_offset(fs, sector_size);
            let end = start + sector_size as u64;
            if end > data.len() as u64 {
                return ValidationResult::Eof {
                    partial_length: data.len() as u64,
                };
            }
            let start = start as usize;
            for i in 0..entries_per_sector {
                fat.push(u32_le(data, start + i * 4));
            }
        }

        // --- 8. Exact object length from the allocation table -------------------
        // Garfinkel 2007: an MSOLE file's Sector Allocation Table gives the object
        // length directly. The last sector the file occupies is the highest FAT index
        // that is not FREESECT; the file is that sector plus the header sector.
        let last_allocated = match fat.iter().rposition(|&e| e != FREESECT) {
            Some(i) => i,
            None => {
                return ValidationResult::Err(
                    "OLE2 FAT contains no allocated sectors (every entry is FREESECT)".to_string(),
                )
            }
        };
        let object_length = (last_allocated as u64 + 2) * sector_size as u64;

        if (data.len() as u64) < object_length {
            // Header and FAT are coherent, but the object's own allocation table says
            // the file is longer than the bytes we hold: truncated, not corrupt.
            return ValidationResult::Eof {
                partial_length: data.len() as u64,
            };
        }

        // --- 9. FAT self-consistency -------------------------------------------
        for &fs in &fat_sector_ids {
            if fs as usize >= fat.len() {
                return ValidationResult::Err(format!(
                    "OLE2 FAT sector {} lies outside the {}-entry FAT it belongs to",
                    fs,
                    fat.len()
                ));
            }
            if fat[fs as usize] != FATSECT {
                return ValidationResult::Err(format!(
                    "OLE2 FAT sector {} is not marked FATSECT in the FAT (found 0x{:08X})",
                    fs, fat[fs as usize]
                ));
            }
        }
        for &ds in &difat_sector_ids {
            if ds as usize >= fat.len() {
                return ValidationResult::Err(format!(
                    "OLE2 DIFAT sector {} lies outside the {}-entry FAT",
                    ds,
                    fat.len()
                ));
            }
            if fat[ds as usize] != DIFSECT {
                return ValidationResult::Err(format!(
                    "OLE2 DIFAT sector {} is not marked DIFSECT in the FAT (found 0x{:08X})",
                    ds, fat[ds as usize]
                ));
            }
        }
        for (idx, &entry) in fat.iter().enumerate() {
            if entry <= MAXREGSECT && entry as usize >= fat.len() {
                return ValidationResult::Err(format!(
                    "OLE2 FAT entry {} points to sector {} beyond the {}-entry FAT",
                    idx,
                    entry,
                    fat.len()
                ));
            }
        }

        // --- 10. Directory chain ------------------------------------------------
        let dir_sectors = match walk_chain(&fat, first_dir_sector, "directory", None) {
            Ok(c) => c,
            Err(result) => return result,
        };
        if dir_sectors.is_empty() {
            return ValidationResult::Err(
                "OLE2 directory chain is empty (no directory sectors allocated)".to_string(),
            );
        }
        if major_version == 4 && dir_sectors.len() != num_dir_sectors as usize {
            return ValidationResult::Err(format!(
                "OLE2 v4 directory chain has {} sectors but the header declares {}",
                dir_sectors.len(),
                num_dir_sectors
            ));
        }

        let entries_per_dir_sector = sector_size / DIR_ENTRY_LEN;
        let total_entries = dir_sectors.len() * entries_per_dir_sector;

        let mut root_start_sector: Option<u32> = None;
        let mut root_stream_size: u64 = 0;
        let mut seen_root = false;

        for (sector_idx, &dir_sector) in dir_sectors.iter().enumerate() {
            let base = sector_offset(dir_sector, sector_size);
            if base + sector_size as u64 > data.len() as u64 {
                return ValidationResult::Err(format!(
                    "OLE2 directory sector {} lies beyond the object length derived from the FAT",
                    dir_sector
                ));
            }
            let base = base as usize;

            for e in 0..entries_per_dir_sector {
                let off = base + e * DIR_ENTRY_LEN;
                let dir_index = sector_idx * entries_per_dir_sector + e;

                let name_len = u16_le(data, off + 0x40);
                let obj_type = data[off + 0x42];
                let color = data[off + 0x43];
                let left = u32_le(data, off + 0x44);
                let right = u32_le(data, off + 0x48);
                let child = u32_le(data, off + 0x4C);
                let start_sector = u32_le(data, off + 0x74);
                let stream_size = u64_le(data, off + 0x78);

                match obj_type {
                    // Unallocated entries carry no constraints worth enforcing; real
                    // writers differ on whether they zero the whole entry.
                    OBJ_UNALLOCATED => continue,
                    OBJ_STORAGE | OBJ_STREAM | OBJ_ROOT => {}
                    other => {
                        return ValidationResult::Err(format!(
                            "OLE2 directory entry {} has invalid object type 0x{:02X}",
                            dir_index, other
                        ))
                    }
                }

                if name_len == 0 || name_len > 64 || name_len % 2 != 0 {
                    return ValidationResult::Err(format!(
                        "OLE2 directory entry {} has invalid name length {} (expected an even value in 2..=64)",
                        dir_index, name_len
                    ));
                }
                if color > 1 {
                    return ValidationResult::Err(format!(
                        "OLE2 directory entry {} has invalid red/black colour flag {}",
                        dir_index, color
                    ));
                }
                for (label, sib) in [
                    ("left sibling", left),
                    ("right sibling", right),
                    ("child", child),
                ] {
                    if sib != NOSTREAM && sib as usize >= total_entries {
                        return ValidationResult::Err(format!(
                            "OLE2 directory entry {} {} id {} is beyond the {} directory entries present",
                            dir_index, label, sib, total_entries
                        ));
                    }
                }

                if dir_index == 0 {
                    if obj_type != OBJ_ROOT {
                        return ValidationResult::Err(format!(
                            "OLE2 directory entry 0 has object type 0x{:02X} (must be 0x05, the root entry)",
                            obj_type
                        ));
                    }
                    seen_root = true;
                    root_start_sector = Some(start_sector);
                    root_stream_size = stream_size;
                } else if obj_type == OBJ_ROOT {
                    return ValidationResult::Err(format!(
                        "OLE2 directory entry {} is a second root entry (only entry 0 may be root)",
                        dir_index
                    ));
                }

                // [MS-CFB]: in version 3 the high dword of the stream size must be zero.
                if major_version == 3 && (stream_size >> 32) != 0 {
                    return ValidationResult::Err(format!(
                        "OLE2 v3 directory entry {} declares a stream size above 4 GiB (high dword must be zero)",
                        dir_index
                    ));
                }

                // Regular (non-mini) stream payloads are chained through the FAT.
                if obj_type == OBJ_STREAM && stream_size >= REQUIRED_MINI_STREAM_CUTOFF as u64 {
                    let needed = sectors_for(stream_size, sector_size) as usize;
                    if let Err(result) = walk_chain(
                        &fat,
                        start_sector,
                        &format!("stream (directory entry {})", dir_index),
                        Some(needed),
                    ) {
                        return result;
                    }
                }
            }
        }

        if !seen_root {
            return ValidationResult::Err("OLE2 directory contains no root entry".to_string());
        }

        // --- 11. MiniFAT and the mini stream ------------------------------------
        if num_minifat_sectors > 0 {
            if first_minifat_sector > MAXREGSECT {
                return ValidationResult::Err(format!(
                    "OLE2 declares {} MiniFAT sectors but the first MiniFAT sector is reserved id 0x{:08X}",
                    num_minifat_sectors, first_minifat_sector
                ));
            }
            let minifat_chain = match walk_chain(
                &fat,
                first_minifat_sector,
                "MiniFAT",
                Some(num_minifat_sectors as usize),
            ) {
                Ok(c) => c,
                Err(result) => return result,
            };

            // The mini stream itself is a normal FAT chain hanging off the root entry.
            let root_start = root_start_sector.unwrap_or(ENDOFCHAIN);
            if root_stream_size == 0 {
                return ValidationResult::Err(format!(
                    "OLE2 declares {} MiniFAT sectors but the root entry's mini stream is empty",
                    num_minifat_sectors
                ));
            }
            let mini_stream_sectors = sectors_for(root_stream_size, sector_size) as usize;
            if let Err(result) =
                walk_chain(&fat, root_start, "mini stream", Some(mini_stream_sectors))
            {
                return result;
            }

            // Cross-check: the MiniFAT must be able to address every mini sector the
            // mini stream provides. A MiniFAT far too small for its own mini stream is
            // an inconsistency no real writer produces.
            let minifat_entries = minifat_chain.len() * entries_per_sector;
            let mini_sectors_available = (root_stream_size as usize).div_ceil(mini_sector_size);
            if minifat_entries < mini_sectors_available {
                return ValidationResult::Err(format!(
                    "OLE2 MiniFAT holds {} entries but the mini stream spans {} mini sectors",
                    minifat_entries, mini_sectors_available
                ));
            }
        } else if let Some(root_start) = root_start_sector {
            // No MiniFAT: the root entry must not claim a mini stream.
            if root_stream_size > 0 && root_start > MAXREGSECT {
                return ValidationResult::Err(format!(
                    "OLE2 root entry declares a {}-byte mini stream but no MiniFAT and no valid start sector",
                    root_stream_size
                ));
            }
        }

        ValidationResult::Ok {
            object_length: Some(object_length),
        }
    }
}

/// Walks a FAT sector chain with loop detection and bounds checking.
///
/// Returns the ordered list of sector ids, or the `ValidationResult` the caller should
/// return. `expected_sectors`, when supplied, is enforced exactly — a chain that is
/// shorter or longer than the declared size implies is a structural inconsistency.
fn walk_chain(
    fat: &[u32],
    start: u32,
    label: &str,
    expected_sectors: Option<usize>,
) -> Result<Vec<u32>, ValidationResult> {
    let mut chain: Vec<u32> = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut current = start;

    while current != ENDOFCHAIN {
        if current > MAXREGSECT {
            return Err(ValidationResult::Err(format!(
                "OLE2 {} chain contains reserved sector id 0x{:08X} (expected a regular sector or ENDOFCHAIN)",
                label, current
            )));
        }
        if current as usize >= fat.len() {
            return Err(ValidationResult::Err(format!(
                "OLE2 {} chain references sector {} beyond the {}-entry FAT",
                label,
                current,
                fat.len()
            )));
        }
        if !visited.insert(current) {
            return Err(ValidationResult::Err(format!(
                "OLE2 {} chain loops back to sector {}",
                label, current
            )));
        }
        chain.push(current);

        if let Some(max) = expected_sectors {
            if chain.len() > max {
                return Err(ValidationResult::Err(format!(
                    "OLE2 {} chain is longer than the {} sectors its declared size implies",
                    label, max
                )));
            }
        }

        current = fat[current as usize];
    }

    if let Some(expected) = expected_sectors {
        if chain.len() != expected {
            return Err(ValidationResult::Err(format!(
                "OLE2 {} chain has {} sectors but its declared size implies {}",
                label,
                chain.len(),
                expected
            )));
        }
    }

    Ok(chain)
}
