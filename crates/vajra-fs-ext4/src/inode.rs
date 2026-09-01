//! ext4 Inode parsing and Extent Tree / Indirect Block mapping (§25).
//!
//! Reference: SleuthKit `tsk/fs/ext2fs.c`, `tsk_ext2fs.h`.

use crate::error::Ext4Error;
use crate::superblock::Ext4Superblock;
use chrono::{DateTime, TimeZone, Utc};
use vajra_core::ReadOnlyBlockSource;

pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT4_INODE_EXTENTS_FLAG: u32 = 0x0008_0000;

/// Parsed ext4 inode.
#[derive(Debug, Clone)]
pub struct Ext4Inode {
    pub inum: u64,
    pub mode: u16,
    pub uid: u32,
    pub size: u64,
    pub atime: Option<DateTime<Utc>>,
    pub ctime: Option<DateTime<Utc>>,
    pub mtime: Option<DateTime<Utc>>,
    pub dtime: Option<DateTime<Utc>>,
    pub gid: u32,
    pub links_count: u16,
    pub blocks_count: u64,
    pub flags: u32,
    pub is_deleted: bool,
    pub is_directory: bool,
    pub is_regular_file: bool,
    pub block_data: [u8; 60],
}

impl Ext4Inode {
    /// Parse an inode from raw bytes.
    pub fn parse(inum: u64, raw: &[u8]) -> Self {
        let mode = u16::from_le_bytes([raw[0], raw[1]]);
        let uid_lo = u16::from_le_bytes([raw[2], raw[3]]) as u32;
        let size_lo = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as u64;
        let atime_sec = i32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let ctime_sec = i32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let mtime_sec = i32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
        let dtime_sec = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]);
        let gid_lo = u16::from_le_bytes([raw[24], raw[25]]) as u32;
        let links_count = u16::from_le_bytes([raw[26], raw[27]]);
        let blocks_lo = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
        let flags = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);

        let is_directory = (mode & 0xF000) == 0x4000;
        let is_regular_file = (mode & 0xF000) == 0x8000;

        let size_hi = if is_regular_file && raw.len() >= 0x70 {
            u32::from_le_bytes([raw[0x6C], raw[0x6D], raw[0x6E], raw[0x6F]]) as u64
        } else {
            0
        };
        let size = (size_hi << 32) | size_lo;

        let atime = Utc.timestamp_opt(atime_sec as i64, 0).single();
        let ctime = Utc.timestamp_opt(ctime_sec as i64, 0).single();
        let mtime = Utc.timestamp_opt(mtime_sec as i64, 0).single();
        let dtime = if dtime_sec > 0 {
            Utc.timestamp_opt(dtime_sec as i64, 0).single()
        } else {
            None
        };

        let is_deleted = dtime.is_some() || links_count == 0;

        let mut block_data = [0u8; 60];
        if raw.len() >= 40 + 60 {
            block_data.copy_from_slice(&raw[40..100]);
        }

        Self {
            inum,
            mode,
            uid: uid_lo,
            size,
            atime,
            ctime,
            mtime,
            dtime,
            gid: gid_lo,
            links_count,
            blocks_count: blocks_lo,
            flags,
            is_deleted,
            is_directory,
            is_regular_file,
            block_data,
        }
    }

    /// Resolves data block extents for this inode.
    ///
    /// Returns a list of (start_block_number, block_count) pairs on the filesystem.
    pub fn get_block_extents(
        &self,
        source: &mut dyn ReadOnlyBlockSource,
        sb: &Ext4Superblock,
    ) -> Result<Vec<(u64, u64)>, Ext4Error> {
        if (self.flags & EXT4_INODE_EXTENTS_FLAG) != 0 {
            // Modern ext4 Extent Tree
            self.parse_extent_tree(&self.block_data, source, sb, 0)
        } else {
            // Legacy direct/indirect block pointers
            self.parse_indirect_blocks(source, sb)
        }
    }

    /// Recursively parses extent tree nodes.
    fn parse_extent_tree(
        &self,
        node_bytes: &[u8],
        source: &mut dyn ReadOnlyBlockSource,
        sb: &Ext4Superblock,
        depth_level: u16,
    ) -> Result<Vec<(u64, u64)>, Ext4Error> {
        if depth_level > 5 {
            return Err(Ext4Error::ExtentDepthExceeded(depth_level));
        }
        if node_bytes.len() < 12 {
            return Ok(Vec::new());
        }

        let magic = u16::from_le_bytes([node_bytes[0], node_bytes[1]]);
        if magic != EXT4_EXTENT_MAGIC {
            return Err(Ext4Error::InvalidExtentMagic(magic, self.inum));
        }

        let entries_count = u16::from_le_bytes([node_bytes[2], node_bytes[3]]) as usize;
        let depth = u16::from_le_bytes([node_bytes[6], node_bytes[7]]);

        let mut extents = Vec::new();

        if depth == 0 {
            // Leaf node: contains ext4_extent structures (12 bytes each)
            for i in 0..entries_count {
                let offset = 12 + (i * 12);
                if offset + 12 > node_bytes.len() {
                    break;
                }
                let len = u16::from_le_bytes([node_bytes[offset + 4], node_bytes[offset + 5]]);
                // len <= 32768: initialized; len > 32768: unwritten extent
                let actual_len = if len <= 32768 { len as u64 } else { (len - 32768) as u64 };

                let start_hi = u16::from_le_bytes([node_bytes[offset + 6], node_bytes[offset + 7]]) as u64;
                let start_lo = u32::from_le_bytes([
                    node_bytes[offset + 8],
                    node_bytes[offset + 9],
                    node_bytes[offset + 10],
                    node_bytes[offset + 11],
                ]) as u64;
                let start_block = (start_hi << 32) | start_lo;

                if start_block > 0 && actual_len > 0 {
                    extents.push((start_block, actual_len));
                }
            }
        } else {
            // Index node: contains ext4_extent_idx structures (12 bytes each)
            let sectors_per_block = (sb.block_size / 512) as u32;
            for i in 0..entries_count {
                let offset = 12 + (i * 12);
                if offset + 12 > node_bytes.len() {
                    break;
                }
                let leaf_lo = u32::from_le_bytes([
                    node_bytes[offset + 4],
                    node_bytes[offset + 5],
                    node_bytes[offset + 6],
                    node_bytes[offset + 7],
                ]) as u64;
                let leaf_hi = u16::from_le_bytes([node_bytes[offset + 8], node_bytes[offset + 9]]) as u64;
                let child_block = (leaf_hi << 32) | leaf_lo;

                if child_block > 0 {
                    let child_lba = sb.block_to_lba(child_block);
                    let child_data = source.read_blocks(child_lba, sectors_per_block)?;
                    let sub_extents = self.parse_extent_tree(&child_data, source, sb, depth_level + 1)?;
                    extents.extend(sub_extents);
                }
            }
        }

        Ok(extents)
    }

    /// Legacy indirect block pointers parsing.
    fn parse_indirect_blocks(
        &self,
        _source: &mut dyn ReadOnlyBlockSource,
        _sb: &Ext4Superblock,
    ) -> Result<Vec<(u64, u64)>, Ext4Error> {
        let mut extents = Vec::new();
        // 12 Direct blocks
        for i in 0..12 {
            let offset = i * 4;
            let block = u32::from_le_bytes([
                self.block_data[offset],
                self.block_data[offset + 1],
                self.block_data[offset + 2],
                self.block_data[offset + 3],
            ]) as u64;
            if block > 0 {
                extents.push((block, 1));
            }
        }
        Ok(extents)
    }
}
