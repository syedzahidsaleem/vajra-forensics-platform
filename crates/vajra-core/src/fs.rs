//! Shared filesystem domain types, output structures, and signature detection (§25).
//!
//! Provides:
//! - [`RecoverableFileEntry`]: The canonical cross-filesystem output structure consumed by Tier-1 recovery and Tier-2 carving engines.
//! - [`DataLocation`]: Block/cluster mapping enum (Resident, Contiguous, Fragmented, Unresolved).
//! - [`MetadataConfidence`]: Calibrated confidence level based on metadata integrity and cluster allocation status.
//! - [`FilesystemType`]: Supported filesystem classifications.
//! - [`detect_filesystem`]: Robust filesystem signature detector evaluating specific boot/superblock headers.

use crate::error::IoError;
use crate::traits::ReadOnlyBlockSource;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Supported filesystem classifications for partition detection and parser dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilesystemType {
    /// Microsoft New Technology File System (MFT, $LogFile, USN Journal)
    Ntfs,
    /// Fourth Extended Filesystem (Linux ext4/ext3/ext2, extent trees, inode table)
    Ext4,
    /// File Allocation Table 12-bit (Legacy floppy/small media)
    Fat12,
    /// File Allocation Table 16-bit (Legacy DOS/small flash media)
    Fat16,
    /// File Allocation Table 32-bit (Standard SD / USB removable media)
    Fat32,
    /// Extended File Allocation Table (Modern SDXC / flash media)
    ExFat,
    /// Apple File System (APFS container / volume)
    Apfs,
    /// Hierarchical File System Plus (Legacy macOS)
    HfsPlus,
    /// Unidentified or unsupported filesystem signature
    Unknown,
}

impl std::fmt::Display for FilesystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ntfs => write!(f, "NTFS"),
            Self::Ext4 => write!(f, "ext4"),
            Self::Fat12 => write!(f, "FAT12"),
            Self::Fat16 => write!(f, "FAT16"),
            Self::Fat32 => write!(f, "FAT32"),
            Self::ExFat => write!(f, "exFAT"),
            Self::Apfs => write!(f, "APFS"),
            Self::HfsPlus => write!(f, "HFS+"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Metadata confidence level evaluating survival and allocation status (§25, §29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MetadataConfidence {
    /// Low confidence: Incomplete metadata, unreferenced records, or high corruption.
    Low,
    /// Reconstructed: Recovered from transactional journal/log replay or directory slack.
    Reconstructed,
    /// Partial: Metadata is valid, but some cluster/extent data blocks have been reallocated.
    Partial,
    /// Confirmed: Metadata is 100% intact, and cluster bitmap confirms data blocks are still unallocated or active.
    Confirmed,
}

impl std::fmt::Display for MetadataConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low (Unreferenced/Damaged)"),
            Self::Reconstructed => write!(f, "Reconstructed (Journal/Slack Replay)"),
            Self::Partial => write!(f, "Partial (Metadata Intact, Blocks Overwritten)"),
            Self::Confirmed => write!(f, "Confirmed (Metadata Intact & Blocks Free)"),
        }
    }
}

/// Data block location mapping on the underlying block source (§25).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataLocation {
    /// Resident data: small payload embedded directly inside filesystem metadata (e.g. NTFS resident $DATA attribute).
    Resident(Vec<u8>),
    /// Contiguous allocation: single run of consecutive blocks.
    Contiguous { start_lba: u64, block_count: u64 },
    /// Fragmented allocation: list of (start_lba, block_count) extents/runs.
    Fragmented(Vec<(u64, u64)>),
    /// Metadata was recovered, but data cluster pointers are missing or zeroed (e.g. wiped ext4 inode).
    Unresolved,
}

/// Canonical recoverable file entry produced by Tier-1 filesystem parsers (§25).
///
/// Consumed uniformly by the Recovery Engine and Tier-2 Carving Engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverableFileEntry {
    /// Record or Inode identifier (e.g. MFT record number, inode number, cluster index).
    pub id: u64,
    /// Full original filesystem path if reconstructible, or None.
    pub original_path: Option<String>,
    /// Filename (extracted from MFT $FILE_NAME, ext4 dir entry, or FAT 8.3/LFN).
    pub filename: Option<String>,
    /// Logical file size in bytes.
    pub size_bytes: Option<u64>,
    /// File creation timestamp (UTC).
    pub created: Option<DateTime<Utc>>,
    /// Last modification timestamp (UTC).
    pub modified: Option<DateTime<Utc>>,
    /// Last access timestamp (UTC).
    pub accessed: Option<DateTime<Utc>>,
    /// True if the entry represents a deleted/unallocated file; False if active/live.
    pub deleted: bool,
    /// Physical/logical location of the file's data blocks.
    pub data_location: DataLocation,
    /// Calibrated confidence assessment of metadata validity.
    pub metadata_confidence: MetadataConfidence,
    /// Originating filesystem type.
    pub source_filesystem: FilesystemType,
}

/// Detects the filesystem type on a block source at a specified partition start offset (§25).
///
/// Evaluates strong signatures with strict priority to avoid false positives:
/// 1. NTFS: Boot sector offset 3..11 contains `b"NTFS    "`.
/// 2. ext4 / ext3 / ext2: Superblock at byte offset 1024 + 0x38 (byte 1080) has magic `0xEF53`.
/// 3. APFS: Container superblock magic `b"NXSB"` at offset 32.
/// 4. exFAT: Boot sector offset 3..11 contains `b"EXFAT   "`.
/// 5. FAT32 / FAT16 / FAT12: Requires BOTH boot signature `0x55, 0xAA` at 510..512 AND valid BPB geometry.
pub fn detect_filesystem(
    source: &mut dyn ReadOnlyBlockSource,
    partition_start_lba: u64,
) -> Result<FilesystemType, IoError> {
    let sector_buf = source.read_blocks(partition_start_lba, 1)?;
    if sector_buf.len() < 512 {
        return Ok(FilesystemType::Unknown);
    }

    // 1. Check NTFS OEM ID at boot sector offset 3..11
    if sector_buf.len() >= 11 && &sector_buf[3..11] == b"NTFS    " {
        return Ok(FilesystemType::Ntfs);
    }

    // 2. Check exFAT OEM ID at boot sector offset 3..11
    if sector_buf.len() >= 11 && &sector_buf[3..11] == b"EXFAT   " {
        return Ok(FilesystemType::ExFat);
    }

    // 3. Check ext4 Superblock at byte offset 1024 (LBA 2 for 512B sectors)
    // Superblock magic 0xEF53 is at offset 0x38 (56 bytes) inside the superblock.
    if let Ok(sb_blocks) = source.read_blocks(partition_start_lba + 2, 2) {
        if sb_blocks.len() >= 0x3A {
            let magic = u16::from_le_bytes([sb_blocks[0x38], sb_blocks[0x39]]);
            if magic == 0xEF53 {
                return Ok(FilesystemType::Ext4);
            }
        }
    }

    // 4. Check APFS Container Superblock (magic "NXSB" at byte offset 32)
    if sector_buf.len() >= 36 && &sector_buf[32..36] == b"NXSB" {
        return Ok(FilesystemType::Apfs);
    }

    // 5. Check FAT12 / FAT16 / FAT32
    // Must have boot sector signature 0x55, 0xAA at bytes 510..512
    if sector_buf[510] == 0x55 && sector_buf[511] == 0xAA {
        // Validate jump instruction at byte 0 (0xEB xx 0x90 or 0xE9 xx xx)
        let is_jump_valid = sector_buf[0] == 0xEB || sector_buf[0] == 0xE9;

        // Parse BPB geometry fields
        let bytes_per_sector = u16::from_le_bytes([sector_buf[11], sector_buf[12]]);
        let sectors_per_cluster = sector_buf[13];
        let reserved_sectors = u16::from_le_bytes([sector_buf[14], sector_buf[15]]);
        let num_fats = sector_buf[16];

        let valid_bytes_per_sec = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096);
        let valid_spc = sectors_per_cluster.is_power_of_two() && sectors_per_cluster <= 128;
        let valid_fats = num_fats == 1 || num_fats == 2;
        let valid_reserved = reserved_sectors > 0;

        if is_jump_valid && valid_bytes_per_sec && valid_spc && valid_fats && valid_reserved {
            // Check for explicit FAT32 string at offset 82..90
            if sector_buf.len() >= 90 && &sector_buf[82..90] == b"FAT32   " {
                return Ok(FilesystemType::Fat32);
            }
            // Check for FAT16 / FAT12 strings at offset 54..62
            if sector_buf.len() >= 62 {
                if &sector_buf[54..62] == b"FAT16   " {
                    return Ok(FilesystemType::Fat16);
                }
                if &sector_buf[54..62] == b"FAT12   " {
                    return Ok(FilesystemType::Fat12);
                }
            }

            // Cluster count calculation fallback
            let root_entries = u16::from_le_bytes([sector_buf[17], sector_buf[18]]);
            let total_sectors_16 = u16::from_le_bytes([sector_buf[19], sector_buf[20]]);
            let total_sectors_32 = u32::from_le_bytes([
                sector_buf[32], sector_buf[33], sector_buf[34], sector_buf[35],
            ]);
            let total_sectors = if total_sectors_16 != 0 {
                total_sectors_16 as u32
            } else {
                total_sectors_32
            };

            let fat_size_16 = u16::from_le_bytes([sector_buf[22], sector_buf[23]]) as u32;
            let fat_size_32 = u32::from_le_bytes([
                sector_buf[36], sector_buf[37], sector_buf[38], sector_buf[39],
            ]);
            let fat_size = if fat_size_16 != 0 {
                fat_size_16
            } else {
                fat_size_32
            };

            let root_dir_sectors = (((root_entries * 32) + (bytes_per_sector - 1))
                / bytes_per_sector) as u32;
            let data_sectors = total_sectors.saturating_sub(
                reserved_sectors as u32 + (num_fats as u32 * fat_size) + root_dir_sectors,
            );
            let total_clusters = data_sectors / sectors_per_cluster as u32;

            if fat_size_16 == 0 || total_clusters >= 65525 {
                return Ok(FilesystemType::Fat32);
            } else if total_clusters >= 4085 {
                return Ok(FilesystemType::Fat16);
            } else if total_clusters > 0 {
                return Ok(FilesystemType::Fat12);
            }
        }
    }

    Ok(FilesystemType::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBlockSource {
        data: Vec<u8>,
        block_size: usize,
    }

    impl MockBlockSource {
        fn new(size_bytes: usize) -> Self {
            Self {
                data: vec![0u8; size_bytes],
                block_size: 512,
            }
        }
    }

    impl ReadOnlyBlockSource for MockBlockSource {
        fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
            let offset = (lba as usize) * self.block_size;
            let total_bytes = (count as usize) * self.block_size;
            if offset >= self.data.len() {
                return Ok(vec![0u8; total_bytes]);
            }
            let end = (offset + total_bytes).min(self.data.len());
            let mut out = self.data[offset..end].to_vec();
            if out.len() < total_bytes {
                out.resize(total_bytes, 0);
            }
            Ok(out)
        }

        fn total_blocks(&self) -> u64 {
            (self.data.len() / self.block_size) as u64
        }

        fn block_size(&self) -> u32 {
            self.block_size as u32
        }

        fn media_type(&self) -> crate::MediaType {
            crate::MediaType::ForensicImage
        }

        fn is_write_blocked(&self) -> bool {
            true
        }

        fn write_blocker_info(&self) -> Option<crate::WriteBlockerMetadata> {
            None
        }

        fn device_fingerprint(&self) -> crate::DeviceFingerprint {
            crate::DeviceFingerprint::compute(
                "Mock",
                "MockFS",
                "SN-MOCK",
                self.data.len() as u64,
                "Mock",
                &[0u8; 512],
            )
        }
    }

    #[test]
    fn test_detect_ntfs_signature() {
        let mut source = MockBlockSource::new(1024 * 1024);
        source.data[3..11].copy_from_slice(b"NTFS    ");
        source.data[510] = 0x55;
        source.data[511] = 0xAA;

        let fs = detect_filesystem(&mut source, 0).unwrap();
        assert_eq!(fs, FilesystemType::Ntfs);
    }

    #[test]
    fn test_detect_ext4_signature_and_no_fat_misidentification() {
        let mut source = MockBlockSource::new(1024 * 1024);
        // Even if LBA 0 has 0x55, 0xAA (e.g. MBR or boot loader)
        source.data[510] = 0x55;
        source.data[511] = 0xAA;
        // Ext4 superblock at 1024 bytes (LBA 2), offset 0x38 (byte 1080)
        source.data[1024 + 0x38] = 0x53;
        source.data[1024 + 0x39] = 0xEF;

        let fs = detect_filesystem(&mut source, 0).unwrap();
        assert_eq!(fs, FilesystemType::Ext4);
    }

    #[test]
    fn test_detect_fat32_signature() {
        let mut source = MockBlockSource::new(1024 * 1024);
        source.data[0] = 0xEB; // Jump
        source.data[11..13].copy_from_slice(&512u16.to_le_bytes()); // Bytes per sector
        source.data[13] = 8; // Sectors per cluster
        source.data[14..16].copy_from_slice(&32u16.to_le_bytes()); // Reserved sectors
        source.data[16] = 2; // Number of FATs
        source.data[82..90].copy_from_slice(b"FAT32   ");
        source.data[510] = 0x55;
        source.data[511] = 0xAA;

        let fs = detect_filesystem(&mut source, 0).unwrap();
        assert_eq!(fs, FilesystemType::Fat32);
    }

    #[test]
    fn test_generic_mbr_not_misidentified_as_fat() {
        let mut source = MockBlockSource::new(1024 * 1024);
        // Generic MBR with 0x55, 0xAA but no valid BPB jump or BPB fields
        source.data[510] = 0x55;
        source.data[511] = 0xAA;

        let fs = detect_filesystem(&mut source, 0).unwrap();
        assert_eq!(fs, FilesystemType::Unknown);
    }
}
