//! Error types for the File Carving and Recovery Engine (`vajra-carve`).

use thiserror::Error;

/// Specific error conditions encountered during recovery and carving operations.
#[derive(Debug, Error)]
pub enum CarveError {
    #[error("I/O error during carving: {0}")]
    Io(#[from] vajra_core::IoError),

    #[error("Filesystem parser error: {0}")]
    Filesystem(String),

    #[error("Signature database error: {0}")]
    SignatureDb(String),

    #[error("Validation error for candidate {0}: {1}")]
    Validation(String, String),

    #[error("Fragment reconstruction failed: {0}")]
    Reconstruction(String),

    #[error("Image or block source error: {0}")]
    BlockSource(String),
}
