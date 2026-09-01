//! LUKS (LUKS1 and LUKS2) Unified Module (§16, §57).

pub mod luks1;
pub mod luks2;

pub use luks1::Luks1Header;
pub use luks2::Luks2Header;

use crate::cipher::SectorCipher;
use crate::error::CryptoVolError;
use vajra_core::traits::ReadOnlyBlockSource;

/// Detects and unlocks a LUKS1 or LUKS2 encrypted block source using a passphrase (§57).
pub fn unlock_luks(
    source: &mut dyn ReadOnlyBlockSource,
    passphrase: &str,
) -> Result<(Box<dyn SectorCipher>, u64), CryptoVolError> {
    let block_size = source.block_size() as u64;
    let total_blocks = source.total_blocks();
    let header_sectors = (8192 / block_size).min(total_blocks).max(1) as u32;

    let buf = source.read_blocks(0, header_sectors)?;

    if buf.len() >= 6 && &buf[0..6] == b"LUKS\xba\xbe" {
        let version = u16::from_be_bytes(buf[6..8].try_into().unwrap());
        if version == 1 {
            let luks1 = Luks1Header::parse(&buf)?;
            return luks1.unlock(source, passphrase);
        } else if version == 2 {
            let luks2 = Luks2Header::parse(&buf)?;
            return luks2.unlock(source, passphrase);
        }
    }

    Err(CryptoVolError::InvalidHeader(
        "No valid LUKS1 or LUKS2 signature detected at LBA 0".to_string(),
    ))
}
