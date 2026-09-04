//! FAT allocation table reading and cluster chain traversal (§25).
//!
//! Reference: SleuthKit `tsk/fs/fatxxfs.c`, `tsk_fatxxfs.h`.

use crate::bpb::FatBpb;
use crate::error::FatError;
use vajra_core::{FilesystemType, ReadOnlyBlockSource};

/// In-memory view of FAT allocation table entries.
pub struct FatTable {
    bpb: FatBpb,
    fat_bytes: Vec<u8>,
}

impl FatTable {
    /// Read the primary FAT table from the block source.
    pub fn load(source: &mut dyn ReadOnlyBlockSource, bpb: &FatBpb) -> Result<Self, FatError> {
        let fat_lba = bpb.fat_table_lba(0);
        let blocks_to_read = bpb.fat_size_sectors;
        let fat_bytes = source.read_blocks(fat_lba, blocks_to_read)?;

        Ok(Self {
            bpb: bpb.clone(),
            fat_bytes,
        })
    }

    /// Read the next cluster in the chain for a given cluster.
    pub fn get_next_cluster(&self, cluster: u32) -> Result<Option<u32>, FatError> {
        match self.bpb.fat_type {
            FilesystemType::Fat32 => {
                let offset = (cluster as usize) * 4;
                if offset + 4 > self.fat_bytes.len() {
                    return Ok(None);
                }
                let raw_val = u32::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                    self.fat_bytes[offset + 2],
                    self.fat_bytes[offset + 3],
                ]);
                let val = raw_val & 0x0FFF_FFFF;

                // 0x00000000 = free, 0x0FFFFFF7 = bad, >= 0x0FFFFFF8 = EOF
                if val == 0 || val == 0x0FFF_FFF7 {
                    Ok(None)
                } else if val >= 0x0FFF_FFF8 {
                    Ok(None) // End of cluster chain
                } else {
                    Ok(Some(val))
                }
            }
            FilesystemType::Fat16 => {
                let offset = (cluster as usize) * 2;
                if offset + 2 > self.fat_bytes.len() {
                    return Ok(None);
                }
                let val = u16::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                ]) as u32;

                if val == 0 || val == 0xFFF7 || val >= 0xFFF8 {
                    Ok(None)
                } else {
                    Ok(Some(val))
                }
            }
            FilesystemType::Fat12 => {
                let offset = (cluster * 3) / 2;
                let offset = offset as usize;
                if offset + 2 > self.fat_bytes.len() {
                    return Ok(None);
                }
                let raw = u16::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                ]);
                let val = if cluster % 2 == 0 {
                    (raw & 0x0FFF) as u32
                } else {
                    ((raw >> 4) & 0x0FFF) as u32
                };

                if val == 0 || val == 0x0FF7 || val >= 0x0FF8 {
                    Ok(None)
                } else {
                    Ok(Some(val))
                }
            }
            _ => Ok(None),
        }
    }

    /// Checks if a cluster is marked as free/unallocated (0x00000000).
    pub fn is_cluster_free(&self, cluster: u32) -> bool {
        match self.bpb.fat_type {
            FilesystemType::Fat32 => {
                let offset = (cluster as usize) * 4;
                if offset + 4 > self.fat_bytes.len() {
                    return false;
                }
                let val = u32::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                    self.fat_bytes[offset + 2],
                    self.fat_bytes[offset + 3],
                ]) & 0x0FFF_FFFF;
                val == 0
            }
            FilesystemType::Fat16 => {
                let offset = (cluster as usize) * 2;
                if offset + 2 > self.fat_bytes.len() {
                    return false;
                }
                let val = u16::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                ]);
                val == 0
            }
            FilesystemType::Fat12 => {
                let offset = ((cluster * 3) / 2) as usize;
                if offset + 2 > self.fat_bytes.len() {
                    return false;
                }
                let raw = u16::from_le_bytes([
                    self.fat_bytes[offset],
                    self.fat_bytes[offset + 1],
                ]);
                let val = if cluster % 2 == 0 {
                    raw & 0x0FFF
                } else {
                    (raw >> 4) & 0x0FFF
                };
                val == 0
            }
            _ => false,
        }
    }

    /// Follows a cluster chain from `start_cluster` and returns all clusters in order.
    pub fn follow_chain(&self, start_cluster: u32) -> Result<Vec<u32>, FatError> {
        let mut chain = Vec::new();
        if start_cluster < 2 {
            return Ok(chain);
        }

        let mut current = start_cluster;
        let mut visited = std::collections::HashSet::new();

        while current >= 2 {
            if !visited.insert(current) {
                return Err(FatError::ChainLoop(current));
            }
            chain.push(current);

            match self.get_next_cluster(current)? {
                Some(next) => current = next,
                None => break,
            }
        }

        Ok(chain)
    }
}
