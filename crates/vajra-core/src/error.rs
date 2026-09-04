//! Error types for the Vajra platform.
//!
//! Provides the canonical `IoError` used across all device, imaging, and carving crates.


/// Primary error type for storage I/O and device operations.
///
/// Implements `thiserror::Error` for structured context and error chaining.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    #[error("Device not found: {path}")]
    DeviceNotFound { path: String },

    #[error("Read failure at LBA {lba} (requested {count} blocks): {details}")]
    ReadFailureAtLba {
        lba: u64,
        count: u32,
        details: String,
    },

    #[error("Write failure at LBA {lba} (requested {count} blocks): {details}")]
    WriteFailureAtLba {
        lba: u64,
        count: u32,
        details: String,
    },

    #[error("Unsupported operation '{operation}': {reason}")]
    UnsupportedOperation {
        operation: String,
        reason: String,
    },

    #[error("Device disconnected: {device_id}")]
    DeviceDisconnected { device_id: String },

    #[error("Permission denied accessing device: {details}. Elevated administrator privileges required.")]
    PermissionDenied { details: String },

    #[error("Buffer alignment error: buffer at address {address:#x} is not aligned to {required_alignment} bytes")]
    BufferAlignmentError {
        address: usize,
        required_alignment: usize,
    },

    #[error("Invalid parameter: {message}")]
    InvalidParameter { message: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Device error: {0}")]
    Other(String),
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IoError::DeviceNotFound { path: p1 }, IoError::DeviceNotFound { path: p2 }) => p1 == p2,
            (
                IoError::ReadFailureAtLba { lba: l1, count: c1, details: d1 },
                IoError::ReadFailureAtLba { lba: l2, count: c2, details: d2 },
            ) => l1 == l2 && c1 == c2 && d1 == d2,
            (
                IoError::WriteFailureAtLba { lba: l1, count: c1, details: d1 },
                IoError::WriteFailureAtLba { lba: l2, count: c2, details: d2 },
            ) => l1 == l2 && c1 == c2 && d1 == d2,
            (
                IoError::UnsupportedOperation { operation: o1, reason: r1 },
                IoError::UnsupportedOperation { operation: o2, reason: r2 },
            ) => o1 == o2 && r1 == r2,
            (IoError::DeviceDisconnected { device_id: d1 }, IoError::DeviceDisconnected { device_id: d2 }) => d1 == d2,
            (IoError::PermissionDenied { details: d1 }, IoError::PermissionDenied { details: d2 }) => d1 == d2,
            (
                IoError::BufferAlignmentError { address: a1, required_alignment: r1 },
                IoError::BufferAlignmentError { address: a2, required_alignment: r2 },
            ) => a1 == a2 && r1 == r2,
            (IoError::InvalidParameter { message: m1 }, IoError::InvalidParameter { message: m2 }) => m1 == m2,
            (IoError::Other(o1), IoError::Other(o2)) => o1 == o2,
            _ => false,
        }
    }
}
