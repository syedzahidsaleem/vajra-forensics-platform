//! ext4 filesystem error types (§25).

use thiserror::Error;
use vajra_core::IoError;

#[derive(Debug, Error)]
pub enum Ext4Error {
    #[error("I/O error during ext4 parsing: {0}")]
    Io(#[from] IoError),

    #[error("Invalid ext4 superblock magic 0x{0:04X} at LBA {1} (expected 0xEF53)")]
    InvalidSuperblockMagic(u16, u64),

    #[error("Corrupted block group descriptor for group {0}")]
    CorruptedGroupDescriptor(u32),

    #[error("Invalid extent tree header magic 0x{0:04X} in inode {1}")]
    InvalidExtentMagic(u16, u64),

    #[error("Extent tree depth exceeded maximum recursion limit ({0})")]
    ExtentDepthExceeded(u16),

    #[error("Inode number {0} out of bounds (total inodes: {1})")]
    InodeOutOfBounds(u64, u64),

    #[error("Corrupted ext4 directory entry in block {0}")]
    CorruptedDirectoryEntry(u64),
}
