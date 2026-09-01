//! ext4 Block Group Descriptor parsing (§25).
//!
//! Reference: SleuthKit `tsk/fs/ext2fs.c`, `tsk_ext2fs.h`.

use crate::error::Ext4Error;
use crate::superblock::Ext4Superblock;
use vajra_core::ReadOnlyBlockSource;

/// Parsed Block Group Descriptor.
#[derive(Debug, Clone)]
pub struct BlockGroupDescriptor {
    pub group_num: u32,
    pub block_bitmap_block: u64,
    pub inode_bitmap_block: u64,
    pub inode_table_block: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
}

impl BlockGroupDescriptor {
    /// Loads all Block Group Descriptors from the filesystem.
    pub fn load_all(
        source: &mut dyn ReadOnlyBlockSource,
        sb: &Ext4Superblock,
    ) -> Result<Vec<Self>, Ext4Error> {
        let desc_table_block = if sb.block_size == 1024 { 2 } else { 1 };
        let desc_size = sb.group_desc_size as usize;
        let total_desc_bytes = sb.block_groups_count as usize * desc_size;
        let blocks_to_read = ((total_desc_bytes + sb.block_size as usize - 1) / sb.block_size as usize) as u32;

        let sectors_per_block = (sb.block_size / 512) as u32;
        let lba = sb.block_to_lba(desc_table_block);
        let data = source.read_blocks(lba, blocks_to_read * sectors_per_block)?;

        let mut descriptors = Vec::with_capacity(sb.block_groups_count as usize);

        for group_idx in 0..sb.block_groups_count {
            let offset = group_idx as usize * desc_size;
            if offset + desc_size > data.len() {
                break;
            }
            let chunk = &data[offset..offset + desc_size];

            let block_bitmap_lo = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            let inode_bitmap_lo = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
            let inode_table_lo = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as u64;
            let free_blocks_lo = u16::from_le_bytes([chunk[12], chunk[13]]) as u32;
            let free_inodes_lo = u16::from_le_bytes([chunk[14], chunk[15]]) as u32;

            let (block_bitmap_block, inode_bitmap_block, inode_table_block, free_blocks_count, free_inodes_count) =
                if sb.is_64bit && desc_size >= 64 {
                    let block_bitmap_hi = u32::from_le_bytes([chunk[32], chunk[33], chunk[34], chunk[35]]) as u64;
                    let inode_bitmap_hi = u32::from_le_bytes([chunk[36], chunk[37], chunk[38], chunk[39]]) as u64;
                    let inode_table_hi = u32::from_le_bytes([chunk[40], chunk[41], chunk[42], chunk[43]]) as u64;
                    let free_blocks_hi = u16::from_le_bytes([chunk[44], chunk[45]]) as u32;
                    let free_inodes_hi = u16::from_le_bytes([chunk[46], chunk[47]]) as u32;

                    (
                        (block_bitmap_hi << 32) | block_bitmap_lo,
                        (inode_bitmap_hi << 32) | inode_bitmap_lo,
                        (inode_table_hi << 32) | inode_table_lo,
                        (free_blocks_hi << 16) | free_blocks_lo,
                        (free_inodes_hi << 16) | free_inodes_lo,
                    )
                } else {
                    (
                        block_bitmap_lo,
                        inode_bitmap_lo,
                        inode_table_lo,
                        free_blocks_lo,
                        free_inodes_lo,
                    )
                };

            descriptors.push(BlockGroupDescriptor {
                group_num: group_idx,
                block_bitmap_block,
                inode_bitmap_block,
                inode_table_block,
                free_blocks_count,
                free_inodes_count,
            });
        }

        Ok(descriptors)
    }
}
