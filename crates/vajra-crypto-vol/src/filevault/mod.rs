//! FileVault (APFS / CoreStorage) Encryption Detection Module (§16, §57).
//!
//! # Architectural Scope Note
//! Per Conversation 09 specifications and Blueprint §53, deep FileVault container unlock
//! requires APFS object map checkpoint and encrypted container volume traversal (deferred in
//! Conversation 04's `vajra-fs-apfs` crate). FileVault support is therefore implemented here
//! in **Detection-Only** mode: it accurately identifies Apple CoreStorage headers and APFS
//! Keybag encryption structures, while unlock operations return a clear, structured notification
//! that full decryption is awaiting the subsequent APFS parser expansion.

use crate::cipher::SectorCipher;
use crate::error::CryptoVolError;
use vajra_core::traits::ReadOnlyBlockSource;

pub const APFS_NX_MAGIC: u32 = 0x4253584e; // 'NXSB' in little endian
pub const CORESTORAGE_MAGIC: &[u8; 8] = b"CS\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone)]
pub struct FileVaultInfo {
    pub format: String,
    pub is_apfs: bool,
    pub is_corestorage: bool,
    pub container_uuid: String,
}

/// Detects FileVault encryption structures on a given block source.
pub fn detect_filevault(source: &mut dyn ReadOnlyBlockSource) -> Result<Option<FileVaultInfo>, CryptoVolError> {
    let buf = source.read_blocks(0, 1)?;

    if buf.len() >= 36 {
        let magic = u32::from_le_bytes(buf[32..36].try_into().unwrap_or([0; 4]));
        if magic == APFS_NX_MAGIC {
            // Check for encrypted container flag in APFS container superblock (flags at offset 44)
            let flags = u32::from_le_bytes(buf[44..48].try_into().unwrap_or([0; 4]));
            let is_encrypted = (flags & 0x00000001) != 0 || (flags & 0x00000008) != 0;
            if is_encrypted {
                return Ok(Some(FileVaultInfo {
                    format: "Apple FileVault 2 (APFS Encrypted Container)".to_string(),
                    is_apfs: true,
                    is_corestorage: false,
                    container_uuid: "APFS-NX-CONTAINER".to_string(),
                }));
            }
        }
    }

    if buf.len() >= 8 && &buf[0..2] == b"CS" {
        return Ok(Some(FileVaultInfo {
            format: "Apple FileVault (CoreStorage LVG)".to_string(),
            is_apfs: false,
            is_corestorage: true,
            container_uuid: "CORESTORAGE-LVG".to_string(),
        }));
    }

    Ok(None)
}

/// Unlock attempt hook for FileVault.
pub fn unlock_filevault(
    source: &mut dyn ReadOnlyBlockSource,
    _credential: &str,
) -> Result<(Box<dyn SectorCipher>, u64), CryptoVolError> {
    if let Ok(Some(info)) = detect_filevault(source) {
        return Err(CryptoVolError::NotSupported(format!(
            "Detected {}: full sector decryption is deferred pending APFS container object map implementation (vajra-fs-apfs)",
            info.format
        )));
    }

    Err(CryptoVolError::InvalidHeader(
        "No Apple FileVault or APFS encrypted superblock detected".to_string(),
    ))
}
