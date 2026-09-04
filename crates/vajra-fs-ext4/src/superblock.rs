//! ext4 Superblock parsing (§25).
//!
//! Reference: SleuthKit `tsk/fs/ext2fs.c`, `tsk_ext2fs.h`.

use crate::error::Ext4Error;

pub const EXT4_SUPERBLOCK_OFFSET_BYTES: u64 = 1024;
pub const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;

// Feature Flags
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

/// Parsed ext4 superblock metadata.
#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    pub partition_start_lba: u64,
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub group_desc_size: u16,
    pub block_groups_count: u32,
    pub first_data_block: u32,
    pub is_64bit: bool,
    pub has_extents: bool,
    pub volume_name: String,
    pub last_mount_time: u32,
    pub last_write_time: u32,
}

impl Ext4Superblock {
    /// Parses the superblock from the 1024-byte superblock data buffer.
    pub fn parse(partition_start_lba: u64, sb_bytes: &[u8]) -> Result<Self, Ext4Error> {
        if sb_bytes.len() < 1024 {
            return Err(Ext4Error::InvalidSuperblockMagic(0, partition_start_lba));
        }

        let magic = u16::from_le_bytes([sb_bytes[0x38], sb_bytes[0x39]]);
        if magic != EXT4_SUPERBLOCK_MAGIC {
            return Err(Ext4Error::InvalidSuperblockMagic(magic, partition_start_lba));
        }

        let inodes_count = u32::from_le_bytes([sb_bytes[0x00], sb_bytes[0x01], sb_bytes[0x02], sb_bytes[0x03]]);
        let blocks_count_lo = u32::from_le_bytes([sb_bytes[0x04], sb_bytes[0x05], sb_bytes[0x06], sb_bytes[0x07]]);
        let log_block_size = u32::from_le_bytes([sb_bytes[0x18], sb_bytes[0x19], sb_bytes[0x1A], sb_bytes[0x1B]]);
        let block_size = 1024u32 << log_block_size;

        let blocks_per_group = u32::from_le_bytes([sb_bytes[0x20], sb_bytes[0x21], sb_bytes[0x22], sb_bytes[0x23]]);
        let inodes_per_group = u32::from_le_bytes([sb_bytes[0x28], sb_bytes[0x29], sb_bytes[0x2A], sb_bytes[0x2B]]);
        let first_data_block = u32::from_le_bytes([sb_bytes[0x14], sb_bytes[0x15], sb_bytes[0x16], sb_bytes[0x17]]);

        let inode_size = u16::from_le_bytes([sb_bytes[0x58], sb_bytes[0x59]]);
        let inode_size = if inode_size == 0 { 128 } else { inode_size };

        let feature_incompat = u32::from_le_bytes([sb_bytes[0x60], sb_bytes[0x61], sb_bytes[0x62], sb_bytes[0x63]]);
        let is_64bit = (feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
        let has_extents = (feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS) != 0;

        let blocks_count_hi = if is_64bit && sb_bytes.len() >= 0x154 {
            u32::from_le_bytes([sb_bytes[0x150], sb_bytes[0x151], sb_bytes[0x152], sb_bytes[0x153]])
        } else {
            0
        };
        let blocks_count = ((blocks_count_hi as u64) << 32) | (blocks_count_lo as u64);

        let group_desc_size = if is_64bit && sb_bytes.len() >= 0xFE {
            let desc_sz = u16::from_le_bytes([sb_bytes[0xFE], sb_bytes[0xFF]]);
            if desc_sz >= 64 { desc_sz } else { 64 }
        } else {
            32
        };

        let block_groups_count = if blocks_per_group > 0 {
            ((blocks_count.saturating_sub(first_data_block as u64) + blocks_per_group as u64 - 1)
                / blocks_per_group as u64) as u32
        } else {
            1
        };

        let volume_name = String::from_utf8_lossy(&sb_bytes[0x78..0x88])
            .trim_matches('\0')
            .trim()
            .to_string();
        let last_mount_time = u32::from_le_bytes([sb_bytes[0x2C], sb_bytes[0x2D], sb_bytes[0x2E], sb_bytes[0x2F]]);
        let last_write_time = u32::from_le_bytes([sb_bytes[0x30], sb_bytes[0x31], sb_bytes[0x32], sb_bytes[0x33]]);

        Ok(Self {
            partition_start_lba,
            inodes_count,
            blocks_count,
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            group_desc_size,
            block_groups_count,
            first_data_block,
            is_64bit,
            has_extents,
            volume_name,
            last_mount_time,
            last_write_time,
        })
    }

    /// Converts an ext4 filesystem block number to physical LBA.
    pub fn block_to_lba(&self, block_num: u64) -> u64 {
        let sectors_per_block = (self.block_size / 512) as u64;
        self.partition_start_lba + (block_num * sectors_per_block)
    }
}
