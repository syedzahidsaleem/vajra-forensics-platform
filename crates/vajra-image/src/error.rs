//! Error types for forensic image container formats (§19).

use thiserror::Error;

/// Error variants encountered when reading or writing forensic images.
#[derive(Debug, Error)]
pub enum ImageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid image header in '{path}': {reason}")]
    InvalidHeader { path: String, reason: String },

    #[error("Corrupt image data: {0}")]
    CorruptImage(String),

    #[error("LBA out of bounds: requested LBA {requested_lba}, total blocks {total_blocks}")]
    OutOfBounds { requested_lba: u64, total_blocks: u64 },

    #[error("Unsupported image format: {0}")]
    UnsupportedFormat(String),

    #[error("E01 / EWF parsing error: {0}")]
    EwfError(String),

    #[error("CRC32 / Adler32 integrity check failed at chunk {chunk_index}: expected {expected:#x}, found {found:#x}")]
    IntegrityCheckFailed {
        chunk_index: u64,
        expected: u32,
        found: u32,
    },
}
