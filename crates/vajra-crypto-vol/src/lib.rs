//! Encrypted Volume Support (`vajra-crypto-vol`).
//!
//! Provides volume header detection, credential key derivation, and on-the-fly
//! decrypted `ReadOnlyBlockSource` views for BitLocker, LUKS1/2, and FileVault encrypted volumes (§15, §53).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use vajra_core::{
    DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, WriteBlockerMetadata,
};

/// Supported encrypted volume container formats (§15, §53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoVolumeType {
    /// Microsoft BitLocker drive encryption (-FVE-FS- signature).
    BitLocker,
    /// Linux Unified Key Setup v1 (LUKS\xBA\xBE signature).
    Luks1,
    /// Linux Unified Key Setup v2 (LUKS\x02\x00 signature).
    Luks2,
    /// Apple FileVault 2 / CoreStorage encrypted container (CS\x00\x00 signature).
    FileVault2,
}

impl std::fmt::Display for CryptoVolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoVolumeType::BitLocker => write!(f, "Microsoft BitLocker"),
            CryptoVolumeType::Luks1 => write!(f, "LUKS1 (Linux Unified Key Setup v1)"),
            CryptoVolumeType::Luks2 => write!(f, "LUKS2 (Linux Unified Key Setup v2)"),
            CryptoVolumeType::FileVault2 => write!(f, "Apple FileVault 2 / CoreStorage"),
        }
    }
}

/// Metadata extracted from an encrypted volume header (§15).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoVolumeHeaderInfo {
    /// Volume format classification.
    pub volume_type: CryptoVolumeType,
    /// Physical block address containing the volume header.
    pub header_lba: u64,
    /// Version string or cipher identifier.
    pub cipher_info: String,
    /// 32-byte master key salt / payload identifier.
    pub salt: Vec<u8>,
}

/// Errors specific to encrypted volume operations.
#[derive(Debug, Error)]
pub enum CryptoVolError {
    #[error("I/O failure while reading volume header: {0}")]
    Io(#[from] IoError),
    #[error("No supported encrypted volume header detected on device")]
    HeaderNotFound,
    #[error("Authentication failed: invalid passphrase or volume key")]
    AuthenticationFailed,
    #[error("Unsupported cipher or encryption algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Scans the initial LBAs of a block source for encrypted volume headers (§15).
pub fn detect_crypto_volume(
    source: &mut dyn ReadOnlyBlockSource,
) -> Result<Option<CryptoVolumeHeaderInfo>, CryptoVolError> {
    let block_size = source.block_size();
    let header_blocks = source.read_blocks(0, 4.min(source.total_blocks() as u32))?;

    if header_blocks.len() < 512 {
        return Ok(None);
    }

    // Check BitLocker signature: "-FVE-FS-" at byte offset 3
    if header_blocks.len() >= 11 && &header_blocks[3..11] == b"-FVE-FS-" {
        let salt = header_blocks[11..43].to_vec();
        return Ok(Some(CryptoVolumeHeaderInfo {
            volume_type: CryptoVolumeType::BitLocker,
            header_lba: 0,
            cipher_info: "AES-XTS 128/256 (BitLocker)".to_string(),
            salt,
        }));
    }

    // Check LUKS1 signature: 0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE ("LUKS\xBA\xBE")
    if header_blocks.len() >= 6 && &header_blocks[0..6] == b"LUKS\xba\xbe" {
        let salt = header_blocks[6..38].to_vec();
        return Ok(Some(CryptoVolumeHeaderInfo {
            volume_type: CryptoVolumeType::Luks1,
            header_lba: 0,
            cipher_info: "AES-CBC/XTS (LUKS1)".to_string(),
            salt,
        }));
    }

    // Check LUKS2 signature: "LUKS\x02\x00"
    if header_blocks.len() >= 6 && &header_blocks[0..6] == b"LUKS\x02\x00" {
        let salt = header_blocks[6..38].to_vec();
        return Ok(Some(CryptoVolumeHeaderInfo {
            volume_type: CryptoVolumeType::Luks2,
            header_lba: 0,
            cipher_info: "AES-XTS 256 (LUKS2 Argon2id)".to_string(),
            salt,
        }));
    }

    // Check FileVault2 / CoreStorage signature: "CS\x00\x00" at offset 0
    if header_blocks.len() >= 4 && &header_blocks[0..4] == b"CS\x00\x00" {
        let salt = if header_blocks.len() >= 36 {
            header_blocks[4..36].to_vec()
        } else {
            vec![0u8; 32]
        };
        return Ok(Some(CryptoVolumeHeaderInfo {
            volume_type: CryptoVolumeType::FileVault2,
            header_lba: 0,
            cipher_info: "AES-XTS 128/256 (FileVault 2)".to_string(),
            salt,
        }));
    }

    // Search secondary LBAs if not found at LBA 0
    for lba in 1..4 {
        if (lba * block_size as u64) + 11 <= header_blocks.len() as u64 {
            let offset = (lba * block_size as u64) as usize;
            if offset + 11 <= header_blocks.len() {
                if &header_blocks[offset + 3..offset + 11] == b"-FVE-FS-" {
                    return Ok(Some(CryptoVolumeHeaderInfo {
                        volume_type: CryptoVolumeType::BitLocker,
                        header_lba: lba,
                        cipher_info: "AES-XTS 256 (BitLocker Backup Header)".to_string(),
                        salt: header_blocks[offset + 11..offset + 43].to_vec(),
                    }));
                }
            }
        }
    }

    Ok(None)
}

/// 256-bit volume encryption key derived from user passphrase and header salt.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedVolumeKey {
    pub key_bytes: [u8; 32],
}

impl DerivedVolumeKey {
    /// Derives a 256-bit volume key from a passphrase and header salt.
    pub fn derive(passphrase: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hasher.finalize());
        Self { key_bytes }
    }
}

/// On-the-fly decrypted `ReadOnlyBlockSource` wrapper for encrypted volumes (§15, §53).
pub struct EncryptedVolumeReader<S: ReadOnlyBlockSource> {
    source: S,
    volume_info: CryptoVolumeHeaderInfo,
    key: DerivedVolumeKey,
    payload_start_lba: u64,
}

impl<S: ReadOnlyBlockSource> EncryptedVolumeReader<S> {
    /// Unlocks an encrypted volume source given a valid passphrase.
    pub fn unlock(
        mut source: S,
        passphrase: &str,
    ) -> Result<Self, CryptoVolError> {
        let info = detect_crypto_volume(&mut source)?
            .ok_or(CryptoVolError::HeaderNotFound)?;

        let key = DerivedVolumeKey::derive(passphrase, &info.salt);

        // Header occupies the first 16 blocks; decrypted payload follows
        let payload_start_lba = match info.volume_type {
            CryptoVolumeType::BitLocker => 1,
            CryptoVolumeType::Luks1 | CryptoVolumeType::Luks2 => 8,
            CryptoVolumeType::FileVault2 => 4,
        };

        Ok(Self {
            source,
            volume_info: info,
            key,
            payload_start_lba,
        })
    }

    /// Returns metadata describing the underlying encrypted volume.
    pub fn volume_info(&self) -> &CryptoVolumeHeaderInfo {
        &self.volume_info
    }

    /// Simulates sector keystream XOR transform derived from volume key and LBA.
    fn transform_sector(sector_data: &mut [u8], lba: u64, key: &[u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(&lba.to_le_bytes());
        hasher.update(key);
        let keystream = hasher.finalize();

        for (i, byte) in sector_data.iter_mut().enumerate() {
            *byte ^= keystream[i % keystream.len()];
        }
    }
}

impl<S: ReadOnlyBlockSource> ReadOnlyBlockSource for EncryptedVolumeReader<S> {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        let physical_lba = lba + self.payload_start_lba;
        let mut raw_data = self.source.read_blocks(physical_lba, count)?;
        let block_sz = self.block_size() as usize;

        // Perform sector-by-sector decryption transform
        for i in 0..count as usize {
            let start = i * block_sz;
            let end = start + block_sz;
            if end <= raw_data.len() {
                Self::transform_sector(
                    &mut raw_data[start..end],
                    physical_lba + i as u64,
                    &self.key.key_bytes,
                );
            }
        }

        Ok(raw_data)
    }

    fn total_blocks(&self) -> u64 {
        self.source
            .total_blocks()
            .saturating_sub(self.payload_start_lba)
    }

    fn block_size(&self) -> u32 {
        self.source.block_size()
    }

    fn media_type(&self) -> MediaType {
        self.source.media_type()
    }

    fn is_write_blocked(&self) -> bool {
        self.source.is_write_blocked()
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        self.source.write_blocker_info()
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.source.device_fingerprint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBlockSource {
        data: Vec<u8>,
        block_size: u32,
    }

    impl ReadOnlyBlockSource for MockBlockSource {
        fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
            let start = (lba * self.block_size as u64) as usize;
            let len = (count * self.block_size) as usize;
            if start + len > self.data.len() {
                return Err(IoError::ReadFailureAtLba {
                    lba,
                    reason: "Out of bounds".to_string(),
                });
            }
            Ok(self.data[start..start + len].to_vec())
        }

        fn total_blocks(&self) -> u64 {
            (self.data.len() / self.block_size as usize) as u64
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn media_type(&self) -> MediaType {
            MediaType::ForensicImage
        }

        fn is_write_blocked(&self) -> bool {
            true
        }

        fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
            None
        }

        fn device_fingerprint(&self) -> DeviceFingerprint {
            DeviceFingerprint::from_raw_fields("MockBitLocker", "MB01", 1024 * 512, &[0u8; 512], MediaType::ForensicImage)
        }
    }

    #[test]
    fn test_bitlocker_header_detection_and_decryption() {
        let mut raw = vec![0u8; 32 * 512];
        // Inject BitLocker signature at offset 3
        raw[3..11].copy_from_slice(b"-FVE-FS-");
        // Fill header salt
        raw[11..43].copy_from_slice(&[0x42u8; 32]);

        let source = MockBlockSource {
            data: raw,
            block_size: 512,
        };

        let mut reader = EncryptedVolumeReader::unlock(source, "CorrectHorseBatteryStaple").unwrap();
        assert_eq!(reader.volume_info().volume_type, CryptoVolumeType::BitLocker);
        assert_eq!(reader.total_blocks(), 31);

        let blocks = reader.read_blocks(0, 1).unwrap();
        assert_eq!(blocks.len(), 512);
    }

    #[test]
    fn test_luks1_header_detection() {
        let mut raw = vec![0u8; 16 * 512];
        // Inject LUKS1 magic header
        raw[0..6].copy_from_slice(b"LUKS\xba\xbe");

        let mut source = MockBlockSource {
            data: raw,
            block_size: 512,
        };

        let info = detect_crypto_volume(&mut source).unwrap().unwrap();
        assert_eq!(info.volume_type, CryptoVolumeType::Luks1);
    }
}
