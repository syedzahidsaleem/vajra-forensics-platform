//! Dual-phase integrity hashing engine (§19).
//!
//! Provides:
//! - Phase 1: Streaming rolling SHA-256 calculation computed concurrently with acquisition writing.
//! - Phase 2: Independent re-read verification pass over the finalized image file.

use crate::error::AcquisitionError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Rolling SHA-256 hasher updated during the acquisition copy loop.
#[derive(Debug, Default)]
pub struct AcquisitionHasher {
    hasher: Sha256,
    bytes_hashed: u64,
}

impl AcquisitionHasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_hashed: 0,
        }
    }

    /// Feed a newly written block/chunk into the rolling hash.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_hashed += data.len() as u64;
    }

    /// Returns total bytes hashed so far.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    /// Finalize and return the hex-encoded SHA-256 digest.
    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

/// Performs the mandatory independent Phase 2 re-read verification pass (§19).
///
/// Re-opens the generated image file on disk, streams all bytes from offset 0 to EOF,
/// computes the full SHA-256 digest, and strictly verifies it against `expected_sha256`.
pub fn verify_image_file<P: AsRef<Path>>(
    image_path: P,
    expected_sha256: &str,
) -> Result<String, AcquisitionError> {
    let path = image_path.as_ref();
    let mut file = File::open(path).map_err(|e| {
        AcquisitionError::Io(std::io::Error::other(
            format!("Failed to open image file '{}' for verification: {}", path.display(), e),
        ))
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer for fast verification streaming

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let verification_hash = hex::encode(hasher.finalize());

    if !verification_hash.eq_ignore_ascii_case(expected_sha256) {
        return Err(AcquisitionError::VerificationHashMismatch {
            acquisition_hash: expected_sha256.to_string(),
            verification_hash,
        });
    }

    Ok(verification_hash)
}
