//! Error types for sanitization engine and confirmation gate (§43).

use thiserror::Error;
use vajra_core::error::IoError;

#[derive(Debug, Error)]
pub enum GateError {
    #[error("REFUSED: Target device '{0}' is the primary OS/system disk. Destructive operations are strictly prohibited.")]
    SystemDiskRefusal(String),

    #[error("REFUSED: Target device '{0}' has an active hardware/software write-blocker attached.")]
    WriteBlockerRefusal(String),

    #[error("REFUSED: Serial number confirmation mismatch. Expected '{expected}', received '{received}'.")]
    SerialMismatch {
        expected: String,
        received: String,
    },

    #[error("REFUSED: Initial operator confirmation was not affirmative.")]
    InitialConfirmationRejected,

    #[error("REFUSED: Pre-execution reconfirmation was rejected immediately prior to operation.")]
    PreExecConfirmationRejected,

    #[error("REFUSED: Confirmation gate token expired or invalidated.")]
    TokenExpired,
}

#[derive(Debug, Error)]
pub enum EraseError {
    #[error("Gate authorization error: {0}")]
    Gate(#[from] GateError),

    #[error("Block device I/O error: {0}")]
    Io(#[from] IoError),

    #[error("Hardware command failure: {0} (code: {1:?})")]
    HardwareCommandFailed(String, Option<u32>),

    #[error("Sanitization verification failed: {0}")]
    VerificationFailed(String),

    #[error("Device disconnected or unresponsive during sanitization")]
    DeviceDisconnected,

    #[error("Operation cancelled by operator")]
    Cancelled,
}
