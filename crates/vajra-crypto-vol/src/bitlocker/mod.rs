//! BitLocker (Full Volume Encryption) Module (§16, §57).

pub mod fve;

pub use fve::{BitLockerAlgorithm, BitLockerHeader};

use crate::cipher::SectorCipher;
use crate::error::CryptoVolError;
use vajra_core::traits::ReadOnlyBlockSource;

/// Detects and unlocks a BitLocker encrypted volume using a password or 48-digit recovery key (§57).
pub fn unlock_bitlocker(
    source: &mut dyn ReadOnlyBlockSource,
    credential: &str,
) -> Result<(Box<dyn SectorCipher>, u64), CryptoVolError> {
    let buf = source.read_blocks(0, 1)?;

    if buf.len() >= 11 && &buf[3..11] == b"-FVE-FS-" {
        let header = BitLockerHeader::parse(&buf)?;
        let cipher = header.unlock(credential)?;
        return Ok((cipher, header.payload_offset_sectors));
    }

    Err(CryptoVolError::InvalidHeader(
        "No BitLocker '-FVE-FS-' signature detected in volume boot record".to_string(),
    ))
}
