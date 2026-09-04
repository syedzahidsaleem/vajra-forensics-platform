//! BIOS Parameter Block (BPB) parsing and FAT volume geometry calculations (§25).
//!
//! Reference: SleuthKit `tsk/fs/fatfs.c`, `tsk_fatfs.h`.

use crate::error::FatError;
use vajra_core::FilesystemType;

/// Parsed FAT volume geometry and BIOS Parameter Block.
#[derive(Debug, Clone)]
pub struct FatBpb {
    pub partition_start_lba: u64,
    pub oem_name: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub total_sectors: u32,
    pub fat_size_sectors: u32,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub fat_type: FilesystemType,
    pub total_clusters: u32,
    pub first_data_lba: u64,
    pub root_dir_lba: u64,
    pub root_dir_sectors: u32,
}

impl FatBpb {
    /// Parse the BPB from the boot sector buffer.
    pub fn parse(partition_start_lba: u64, sector: &[u8]) -> Result<Self, FatError> {
        if sector.len() < 512 {
            return Err(FatError::InvalidBootSector(partition_start_lba));
        }

        // Validate boot sector signature 0x55, 0xAA
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(FatError::InvalidBootSector(partition_start_lba));
        }

        let oem_name = String::from_utf8_lossy(&sector[3..11]).trim().to_string();
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(FatError::UnsupportedSectorSize(bytes_per_sector));
        }

        let sectors_per_cluster = sector[13];
        if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster > 128 || sectors_per_cluster == 0 {
            return Err(FatError::InvalidSectorsPerCluster(sectors_per_cluster));
        }

        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        let root_entry_count = u16::from_le_bytes([sector[17], sector[18]]);

        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };

        let fat_size_16 = u16::from_le_bytes([sector[22], sector[23]]) as u32;
        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let fat_size_sectors = if fat_size_16 != 0 {
            fat_size_16
        } else {
            fat_size_32
        };

        let root_cluster = if fat_size_16 == 0 && sector.len() >= 48 {
            u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]])
        } else {
            0
        };

        let fs_info_sector = if fat_size_16 == 0 && sector.len() >= 50 {
            u16::from_le_bytes([sector[48], sector[49]])
        } else {
            0
        };

        let root_dir_sectors = ((root_entry_count as u32 * 32) + (bytes_per_sector as u32 - 1))
            / bytes_per_sector as u32;
        let fat_total_sectors = num_fats as u32 * fat_size_sectors;
        let data_sectors = total_sectors.saturating_sub(
            reserved_sectors as u32 + fat_total_sectors + root_dir_sectors,
        );
        let total_clusters = data_sectors / sectors_per_cluster as u32;

        let fat_type = if (fat_size_16 == 0 && root_cluster >= 2) || total_clusters >= 65525 {
            FilesystemType::Fat32
        } else if total_clusters >= 4085 {
            FilesystemType::Fat16
        } else {
            FilesystemType::Fat12
        };

        let root_dir_lba = partition_start_lba + reserved_sectors as u64 + fat_total_sectors as u64;
        let first_data_lba = root_dir_lba + root_dir_sectors as u64;

        Ok(Self {
            partition_start_lba,
            oem_name,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entry_count,
            total_sectors,
            fat_size_sectors,
            root_cluster,
            fs_info_sector,
            fat_type,
            total_clusters,
            first_data_lba,
            root_dir_lba,
            root_dir_sectors,
        })
    }

    /// Computes the starting physical LBA for a given cluster number.
    pub fn cluster_to_lba(&self, cluster: u32) -> Result<u64, FatError> {
        if cluster < 2 {
            return Err(FatError::ClusterOutOfBounds(cluster, self.total_clusters + 2));
        }
        let cluster_offset = (cluster - 2) as u64 * self.sectors_per_cluster as u64;
        Ok(self.first_data_lba + cluster_offset)
    }

    /// Starting LBA of FAT table index `fat_idx` (0-indexed).
    pub fn fat_table_lba(&self, fat_idx: u8) -> u64 {
        self.partition_start_lba + self.reserved_sectors as u64 + (fat_idx as u64 * self.fat_size_sectors as u64)
    }

    /// Size in bytes of a cluster.
    pub fn cluster_size_bytes(&self) -> u64 {
        self.sectors_per_cluster as u64 * self.bytes_per_sector as u64
    }
}
