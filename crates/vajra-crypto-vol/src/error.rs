//! Error definitions for encrypted volume unlock and decryption (§16, §57).

use thiserror::Error;
use vajra_core::error::IoError;

#[derive(Debug, Error)]
pub enum CryptoVolError {
    #[error("I/O error on encrypted block source: {0}")]
    Io(#[from] IoError),

    #[error("Unsupported encrypted volume format: {0}")]
    UnsupportedFormat(String),

    #[error("Corrupted or invalid volume header: {0}")]
    InvalidHeader(String),

    #[error("Authentication failed: invalid passphrase or recovery key provided ({0})")]
    AuthenticationFailed(String),

    #[error("No active keyslot matched the provided credentials")]
    NoMatchingKeySlot,

    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    #[error("Sector decryption failed at LBA {lba}: {reason}")]
    DecryptionError { lba: u64, reason: String },

    #[error("Feature not supported: {0}")]
    NotSupported(String),
}
