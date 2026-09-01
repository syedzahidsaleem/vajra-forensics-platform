//! Local File & Extent Overwriting Primitive (§36).
//!
//! Provides cryptographically secure pseudorandom overwrite passes (ChaCha20)
//! and strict file sync/flush operations.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::FileEraseError;

/// [DESTRUCTIVE OPERATION (§43)]
/// Overwrites a local file on the filesystem with multi-pass CSPRNG patterns, flushes to disk,
/// truncates, and safely removes it.
pub fn erase_local_file_destructive(file_path: impl AsRef<Path>, passes: u32) -> Result<u64, FileEraseError> {
    let path = file_path.as_ref();
    if !path.exists() {
        return Err(FileEraseError::ExtentResolutionFailed(format!(
            "Target file '{}' does not exist",
            path.display()
        )));
    }

    let file_len = std::fs::metadata(path)
        .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?
        .len();

    if file_len > 0 {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;

        let mut rng = ChaCha20Rng::from_entropy();
        let chunk_size = 64 * 1024; // 64 KB
        let mut buffer = vec![0u8; chunk_size];

        for p in 1..=passes.max(1) {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;

            let mut remaining = file_len;
            while remaining > 0 {
                let to_write = (remaining as usize).min(chunk_size);
                let active_buf = &mut buffer[..to_write];

                if p == passes {
                    // Final pass: zero fill (NIST Clear)
                    active_buf.fill(0x00);
                } else if p % 2 == 1 {
                    rng.fill_bytes(active_buf);
                } else {
                    active_buf.fill(0xFF);
                }

                file.write_all(active_buf)
                    .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;
                remaining -= to_write as u64;
            }

            // Sync after every pass
            file.sync_all()
                .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;
        }

        // Truncate to 0 bytes
        file.set_len(0)
            .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;
        file.sync_all()
            .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;
    }

    // Remove file from filesystem directory
    std::fs::remove_file(path)
        .map_err(|e| FileEraseError::ExtentResolutionFailed(e.to_string()))?;

    Ok(file_len)
}
