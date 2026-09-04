//! Error types for selective file/folder erasure (§36).

use thiserror::Error;
use vajra_core::error::IoError;

#[derive(Debug, Error)]
pub enum FileEraseError {
    #[error("File extent resolution failed: {0}")]
    ExtentResolutionFailed(String),

    #[error("Block I/O error during overwrite: {0}")]
    Io(#[from] IoError),

    #[error("Metadata zeroing error: {0}")]
    MetadataZeroingFailed(String),

    #[error("Free-after-overwrite allocation update failed: {0}")]
    AllocationUpdateFailed(String),

    #[error("Residual artifact scan error: {0}")]
    ScanError(String),

    #[error("Unsupported filesystem for direct structure erasure: {0}")]
    UnsupportedFilesystem(String),
}
