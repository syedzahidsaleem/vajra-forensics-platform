//! NTFS filesystem error types (§25).

use thiserror::Error;
use vajra_core::IoError;

#[derive(Debug, Error)]
pub enum NtfsError {
    #[error("I/O error during NTFS parsing: {0}")]
    Io(#[from] IoError),

    #[error("Invalid NTFS boot sector signature at LBA {0}")]
    InvalidBootSector(u64),

    #[error("Corrupted MFT record header magic: 0x{0:08X} (expected 'FILE' or 'BAAD')")]
    InvalidMftMagic(u32),

    #[error("MFT update sequence fixup failed for record {0}")]
    FixupFailed(u64),

    #[error("Corrupted attribute header at offset {0} in MFT record {1}")]
    CorruptedAttribute(usize, u64),

    #[error("Invalid non-resident data runlist at offset {0}")]
    InvalidDataRun(usize),

    #[error("MFT record index {0} out of bounds")]
    MftRecordOutOfBounds(u64),
}
