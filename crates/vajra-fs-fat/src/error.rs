//! FAT filesystem error types (§25).

use thiserror::Error;
use vajra_core::IoError;

#[derive(Debug, Error)]
pub enum FatError {
    #[error("I/O error during FAT parsing: {0}")]
    Io(#[from] IoError),

    #[error("Invalid or missing FAT boot sector / BPB signature at LBA {0}")]
    InvalidBootSector(u64),

    #[error("Unsupported FAT sector size: {0} bytes (expected 512, 1024, 2048, or 4096)")]
    UnsupportedSectorSize(u16),

    #[error("Invalid sectors per cluster: {0}")]
    InvalidSectorsPerCluster(u8),

    #[error("Corrupted FAT directory entry at offset {0}")]
    CorruptedDirectoryEntry(u64),

    #[error("Cluster index out of bounds: cluster {0} (max valid cluster: {1})")]
    ClusterOutOfBounds(u32, u32),

    #[error("FAT chain loop detected at cluster {0}")]
    ChainLoop(u32),
}
