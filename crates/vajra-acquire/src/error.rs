//! Error types for evidence acquisition and imaging pipeline (§19, §20).

use thiserror::Error;

/// Error variants returned by the Acquisition Engine.
#[derive(Debug, Error)]
pub enum AcquisitionError {
    #[error("I/O error during acquisition: {0}")]
    Io(#[from] std::io::Error),

    #[error("Source device read error at LBA {lba} (count {count}): {source}")]
    DeviceReadError {
        lba: u64,
        count: u32,
        #[source]
        source: vajra_core::IoError,
    },

    #[error("Image container error: {0}")]
    ImageError(#[from] vajra_image::ImageError),

    #[error("Post-acquisition verification hash mismatch: rolling SHA-256 was '{acquisition_hash}', but re-read verification SHA-256 was '{verification_hash}'")]
    VerificationHashMismatch {
        acquisition_hash: String,
        verification_hash: String,
    },

    #[error("Device mismatch on resume: expected source fingerprint '{expected_fingerprint}', but attached device has '{actual_fingerprint}'")]
    DeviceMismatchOnResume {
        expected_fingerprint: String,
        actual_fingerprint: String,
    },

    #[error("Insufficient storage space on target volume: required {required_bytes} bytes, but only {available_bytes} bytes are available")]
    InsufficientStorageSpace {
        required_bytes: u64,
        available_bytes: u64,
    },

    #[error("Database error: {0}")]
    DatabaseError(#[from] vajra_case_db::DbError),

    #[error("Audit log error: {0}")]
    AuditError(#[from] vajra_audit::AuditError),

    #[error("Chain of custody error: {0}")]
    CustodyError(#[from] vajra_custody::CustodyError),

    #[error("Checkpoint not found for operation '{0}'")]
    CheckpointNotFound(String),

    #[error("Acquisition was cancelled by operator")]
    Cancelled,

    #[error("Unsupported acquisition configuration: {0}")]
    UnsupportedConfiguration(String),
}
