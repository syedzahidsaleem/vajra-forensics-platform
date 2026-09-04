//! Linux software RAID (mdadm) Superblock Parser and Auto-Detector (§15 Part III, §16).

use crate::error::RaidError;
use crate::layout::{ParityLayout, RaidGeometry, RaidLevel};
use vajra_core::traits::ReadOnlyBlockSource;

pub const MD_SB_MAGIC: u32 = 0xa9280c09;

#[derive(Debug, Clone)]
pub struct MdadmSuperblock {
    pub major_version: u32,
    pub minor_version: u32,
    pub set_uuid: [u8; 16],
    pub set_name: String,
    pub level: RaidLevel,
    pub layout: ParityLayout,
    pub chunk_size_sectors: u32,
    pub raid_disks: u32,
    pub data_offset_sectors: u64,
    pub data_size_sectors: u64,
    pub dev_number: u32,
}

impl MdadmSuperblock {
    /// Attempts to parse an mdadm 1.x superblock from a 4096-byte buffer.
    pub fn parse_v1(buf: &[u8], minor_hint: u32) -> Result<Self, RaidError> {
        if buf.len() < 256 {
            return Err(RaidError::CorruptedSuperblock {
                member_idx: 0,
                reason: "Buffer too short for mdadm superblock".to_string(),
            });
        }

        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != MD_SB_MAGIC {
            return Err(RaidError::SuperblockNotFound);
        }

        let major_version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if major_version != 1 {
            return Err(RaidError::CorruptedSuperblock {
                member_idx: 0,
                reason: format!("Unsupported mdadm major version: {}", major_version),
            });
        }

        let mut set_uuid = [0u8; 16];
        set_uuid.copy_from_slice(&buf[16..32]);

        let set_name_bytes = &buf[32..64];
        let set_name = String::from_utf8_lossy(set_name_bytes)
            .trim_matches(char::from(0))
            .to_string();

        let raw_level = i32::from_le_bytes(buf[72..76].try_into().unwrap());
        let level = match raw_level {
            0 => RaidLevel::Raid0,
            5 => RaidLevel::Raid5,
            6 => RaidLevel::Raid6,
            other => {
                return Err(RaidError::InvalidGeometry(format!(
                    "Unsupported RAID level in superblock: {}",
                    other
                )))
            }
        };

        let raw_layout = u32::from_le_bytes(buf[76..80].try_into().unwrap());
        let layout = match raw_layout {
            0 => ParityLayout::LeftAsymmetric,
            1 => ParityLayout::RightAsymmetric,
            2 => ParityLayout::LeftSymmetric,
            3 => ParityLayout::RightSymmetric,
            _ => ParityLayout::LeftSymmetric,
        };

        let chunk_size_sectors = u32::from_le_bytes(buf[88..92].try_into().unwrap());
        let raid_disks = u32::from_le_bytes(buf[92..96].try_into().unwrap());

        let data_offset_sectors = u64::from_le_bytes(buf[128..136].try_into().unwrap());
        let data_size_sectors = u64::from_le_bytes(buf[136..144].try_into().unwrap());
        let dev_number = u32::from_le_bytes(buf[160..164].try_into().unwrap());

        Ok(Self {
            major_version,
            minor_version: minor_hint,
            set_uuid,
            set_name,
            level,
            layout,
            chunk_size_sectors,
            raid_disks,
            data_offset_sectors,
            data_size_sectors,
            dev_number,
        })
    }

    /// Converts this superblock into a `RaidGeometry`.
    pub fn to_geometry(&self, sector_size: u32, member_capacity_sectors: u64) -> Result<RaidGeometry, RaidError> {
        RaidGeometry::new(
            self.level,
            self.layout,
            self.raid_disks as usize,
            self.chunk_size_sectors * sector_size,
            sector_size,
            self.data_offset_sectors,
            member_capacity_sectors,
        )
    }
}

/// Probes a block source for an mdadm superblock across standard offsets (1.2, 1.1, 1.0).
pub fn detect_mdadm_superblock(source: &mut dyn ReadOnlyBlockSource) -> Result<MdadmSuperblock, RaidError> {
    let block_size = source.block_size() as u64;
    let total_blocks = source.total_blocks();

    // 1. Probe mdadm 1.2: offset 4096 bytes (LBA 8 for 512B sectors)
    let lba_12 = 4096 / block_size;
    if total_blocks > lba_12 + 8 {
        if let Ok(data) = source.read_blocks(lba_12, (4096 / block_size) as u32) {
            if let Ok(sb) = MdadmSuperblock::parse_v1(&data, 2) {
                return Ok(sb);
            }
        }
    }

    // 2. Probe mdadm 1.1: offset 0
    if total_blocks >= 8 {
        if let Ok(data) = source.read_blocks(0, (4096 / block_size) as u32) {
            if let Ok(sb) = MdadmSuperblock::parse_v1(&data, 1) {
                return Ok(sb);
            }
        }
    }

    // 3. Probe mdadm 1.0: 8KB to 12KB before end of disk
    if total_blocks > (12288 / block_size) {
        let lba_10 = total_blocks - (8192 / block_size);
        if let Ok(data) = source.read_blocks(lba_10, (4096 / block_size) as u32) {
            if let Ok(sb) = MdadmSuperblock::parse_v1(&data, 0) {
                return Ok(sb);
            }
        }
    }

    Err(RaidError::SuperblockNotFound)
}

/// Helper to serialize an mdadm 1.2 superblock into a buffer (used for synthetic tests and formatting).
pub fn write_mdadm_1_2_superblock(buf: &mut [u8], sb: &MdadmSuperblock) {
    if buf.len() < 256 {
        return;
    }
    buf[0..4].copy_from_slice(&MD_SB_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&sb.major_version.to_le_bytes());
    buf[16..32].copy_from_slice(&sb.set_uuid);

    let name_bytes = sb.set_name.as_bytes();
    let copy_len = name_bytes.len().min(32);
    buf[32..32 + copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let raw_level: i32 = match sb.level {
        RaidLevel::Raid0 => 0,
        RaidLevel::Raid5 => 5,
        RaidLevel::Raid6 => 6,
    };
    buf[72..76].copy_from_slice(&raw_level.to_le_bytes());

    let raw_layout: u32 = match sb.layout {
        ParityLayout::LeftAsymmetric => 0,
        ParityLayout::RightAsymmetric => 1,
        ParityLayout::LeftSymmetric => 2,
        ParityLayout::RightSymmetric => 3,
    };
    buf[76..80].copy_from_slice(&raw_layout.to_le_bytes());

    buf[88..92].copy_from_slice(&sb.chunk_size_sectors.to_le_bytes());
    buf[92..96].copy_from_slice(&sb.raid_disks.to_le_bytes());

    buf[128..136].copy_from_slice(&sb.data_offset_sectors.to_le_bytes());
    buf[136..144].copy_from_slice(&sb.data_size_sectors.to_le_bytes());
    buf[160..164].copy_from_slice(&sb.dev_number.to_le_bytes());
}

