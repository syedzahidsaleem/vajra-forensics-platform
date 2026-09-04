//! ext4 block allocation bitmap checking (§25).
//!
//! Evaluates whether data blocks of unlinked inodes remain unallocated (free)
//! in the block group bitmaps to accurately assign `MetadataConfidence::Confirmed`
//! vs `MetadataConfidence::Partial`.

use crate::error::Ext4Error;
use crate::group_desc::BlockGroupDescriptor;
use crate::superblock::Ext4Superblock;
use vajra_core::{MetadataConfidence, ReadOnlyBlockSource};

/// In-memory view of ext4 block group allocation bitmaps.
#[derive(Debug, Clone)]
pub struct Ext4BlockBitmap {
    group_bitmaps: Vec<Vec<u8>>,
    blocks_per_group: u32,
    first_data_block: u64,
}

impl Ext4BlockBitmap {
    /// Loads all block allocation bitmaps from all block groups.
    pub fn load_all(
        source: &mut dyn ReadOnlyBlockSource,
        sb: &Ext4Superblock,
        groups: &[BlockGroupDescriptor],
    ) -> Result<Self, Ext4Error> {
        let sectors_per_block = (sb.block_size / 512) as u32;
        let mut group_bitmaps = Vec::with_capacity(groups.len());

        for bg in groups {
            let lba = sb.block_to_lba(bg.block_bitmap_block);
            let bitmap_bytes = source.read_blocks(lba, sectors_per_block)?;
            group_bitmaps.push(bitmap_bytes);
        }

        Ok(Self {
            group_bitmaps,
            blocks_per_group: sb.blocks_per_group,
            first_data_block: sb.first_data_block as u64,
        })
    }

    /// Checks if a filesystem block number is currently free/unallocated (bit == 0).
    pub fn is_block_free(&self, block_num: u64) -> bool {
        if block_num < self.first_data_block {
            return false;
        }
        let rel_block = block_num - self.first_data_block;
        let group_idx = (rel_block / self.blocks_per_group as u64) as usize;
        let bit_in_group = (rel_block % self.blocks_per_group as u64) as usize;

        if group_idx >= self.group_bitmaps.len() {
            return false;
        }

        let bitmap = &self.group_bitmaps[group_idx];
        let byte_idx = bit_in_group / 8;
        let bit_offset = bit_in_group % 8;

        if byte_idx < bitmap.len() {
            (bitmap[byte_idx] & (1 << bit_offset)) == 0
        } else {
            false
        }
    }

    /// Evaluates metadata confidence based on whether all extent blocks remain unallocated.
    pub fn evaluate_extents_confidence(&self, extents: &[(u64, u64)]) -> MetadataConfidence {
        if extents.is_empty() {
            return MetadataConfidence::Low;
        }

        let mut all_free = true;
        let mut any_free = false;

        for &(start_block, count) in extents {
            for b in 0..count {
                if self.is_block_free(start_block + b) {
                    any_free = true;
                } else {
                    all_free = false;
                }
            }
        }

        if all_free {
            MetadataConfidence::Confirmed
        } else if any_free {
            MetadataConfidence::Partial
        } else {
            MetadataConfidence::Low
        }
    }
}
