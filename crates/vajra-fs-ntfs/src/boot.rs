//! NTFS $Boot sector parsing and volume geometry calculations (§25).
//!
//! Reference: SleuthKit `tsk/fs/ntfs.c`, `tsk_ntfs.h`.

use crate::error::NtfsError;

pub const NTFS_BOOT_MAGIC: &[u8; 8] = b"NTFS    ";

/// Parsed NTFS boot sector ($Boot) information.
#[derive(Debug, Clone)]
pub struct NtfsBoot {
    pub partition_start_lba: u64,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_start_lcn: u64,
    pub mft_mirr_start_lcn: u64,
    pub mft_record_size: u32,
    pub index_record_size: u32,
    pub serial_number: u64,
}

impl NtfsBoot {
    /// Parse the NTFS boot sector from sector bytes.
    pub fn parse(partition_start_lba: u64, sector: &[u8]) -> Result<Self, NtfsError> {
        if sector.len() < 512 {
            return Err(NtfsError::InvalidBootSector(partition_start_lba));
        }

        if &sector[3..11] != NTFS_BOOT_MAGIC || sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(NtfsError::InvalidBootSector(partition_start_lba));
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        let sectors_per_cluster = sector[13];
        let total_sectors = u64::from_le_bytes([
            sector[40], sector[41], sector[42], sector[43],
            sector[44], sector[45], sector[46], sector[47],
        ]);
        let mft_start_lcn = u64::from_le_bytes([
            sector[48], sector[49], sector[50], sector[51],
            sector[52], sector[53], sector[54], sector[55],
        ]);
        let mft_mirr_start_lcn = u64::from_le_bytes([
            sector[56], sector[57], sector[58], sector[59],
            sector[60], sector[61], sector[62], sector[63],
        ]);

        // Clusters per MFT record: if > 0, clusters; if < 0, 2^(-val) bytes
        let clusters_per_mft = sector[64] as i8;
        let mft_record_size = if clusters_per_mft > 0 {
            (clusters_per_mft as u32) * (sectors_per_cluster as u32) * (bytes_per_sector as u32)
        } else {
            1u32 << (-clusters_per_mft as u32)
        };

        let clusters_per_idx = sector[68] as i8;
        let index_record_size = if clusters_per_idx > 0 {
            (clusters_per_idx as u32) * (sectors_per_cluster as u32) * (bytes_per_sector as u32)
        } else {
            1u32 << (-clusters_per_idx as u32)
        };

        let serial_number = u64::from_le_bytes([
            sector[72], sector[73], sector[74], sector[75],
            sector[76], sector[77], sector[78], sector[79],
        ]);

        Ok(Self {
            partition_start_lba,
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_start_lcn,
            mft_mirr_start_lcn,
            mft_record_size,
            index_record_size,
            serial_number,
        })
    }

    /// Converts an NTFS cluster LCN to a physical LBA on the underlying storage source.
    pub fn lcn_to_lba(&self, lcn: u64) -> u64 {
        let sectors_per_clus = self.sectors_per_cluster as u64;
        self.partition_start_lba + (lcn * sectors_per_clus)
    }

    /// Size in bytes of a cluster.
    pub fn cluster_size_bytes(&self) -> u64 {
        (self.sectors_per_cluster as u64) * (self.bytes_per_sector as u64)
    }
}
