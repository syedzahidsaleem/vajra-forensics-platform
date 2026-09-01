//! # vajra-crypto-vol
//!
//! Lawful encrypted volume (LUKS1, LUKS2, BitLocker, FileVault) unlock and sector decryption engine (§16, §57).
//!
//! Exposes decrypted views of underlying block sources as standard `ReadOnlyBlockSource` instances.
//! Strictly enforces lawful-credentials-only policy with zero credential bypass or guessing.

pub mod bitlocker;
pub mod cipher;
pub mod error;
pub mod filevault;
pub mod luks;
pub mod volume;

pub use bitlocker::{unlock_bitlocker, BitLockerAlgorithm, BitLockerHeader};
pub use cipher::{Aes128XtsCipher, Aes256XtsCipher, AesCbcCipher, SectorCipher};
pub use error::CryptoVolError;
pub use filevault::{detect_filevault, unlock_filevault, FileVaultInfo};
pub use luks::{unlock_luks, Luks1Header, Luks2Header};
pub use volume::EncryptedVolume;

use vajra_core::traits::ReadOnlyBlockSource;

/// Automatic detection and unlock router for any supported encrypted volume format (§57).
pub fn auto_unlock<T: ReadOnlyBlockSource>(
    mut source: T,
    credential: &str,
) -> Result<EncryptedVolume<T>, CryptoVolError> {
    let block_size = source.block_size() as u64;
    let total_blocks = source.total_blocks();
    let header_sectors = (8192 / block_size).min(total_blocks).max(1) as u32;
    let buf = source.read_blocks(0, header_sectors)?;

    // 1. Check for LUKS (LUKS1 / LUKS2)
    if buf.len() >= 6 && &buf[0..6] == b"LUKS\xba\xbe" {
        let (cipher, payload_offset) = luks::unlock_luks(&mut source, credential)?;
        return Ok(EncryptedVolume::new(source, cipher, payload_offset, "LUKS"));
    }

    // 2. Check for BitLocker
    if buf.len() >= 11 && &buf[3..11] == b"-FVE-FS-" {
        let (cipher, payload_offset) = bitlocker::unlock_bitlocker(&mut source, credential)?;
        return Ok(EncryptedVolume::new(source, cipher, payload_offset, "BitLocker"));
    }

    // 3. Check for FileVault
    if let Ok(Some(_info)) = filevault::detect_filevault(&mut source) {
        let (cipher, payload_offset) = filevault::unlock_filevault(&mut source, credential)?;
        return Ok(EncryptedVolume::new(source, cipher, payload_offset, "FileVault"));
    }

    Err(CryptoVolError::UnsupportedFormat(
        "No supported encrypted volume header (LUKS, BitLocker, FileVault) recognized at LBA 0".to_string(),
    ))
}
