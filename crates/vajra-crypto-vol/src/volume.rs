//! EncryptedVolume struct wrapping inner ReadOnlyBlockSource (§16, §57).

use crate::cipher::SectorCipher;
use sha2::{Digest, Sha256};
use vajra_core::error::IoError;
use vajra_core::fingerprint::DeviceFingerprint;
use vajra_core::media_type::MediaType;
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_core::write_blocker::WriteBlockerMetadata;

/// A decrypted view of an underlying encrypted block source implementing `ReadOnlyBlockSource` (§16).
pub struct EncryptedVolume<T: ReadOnlyBlockSource> {
    inner: T,
    cipher: Box<dyn SectorCipher>,
    payload_offset_sectors: u64,
    total_logical_blocks: u64,
    format_name: String,
    fingerprint: DeviceFingerprint,
}

impl<T: ReadOnlyBlockSource> EncryptedVolume<T> {
    pub fn new(
        inner: T,
        cipher: Box<dyn SectorCipher>,
        payload_offset_sectors: u64,
        format_name: &str,
    ) -> Self {
        let total_inner = inner.total_blocks();
        let total_logical_blocks = total_inner.saturating_sub(payload_offset_sectors);

        let mut hasher = Sha256::new();
        hasher.update(format!("ENCRYPTED_VOL:{}:{}:{}", format_name, cipher.cipher_name(), payload_offset_sectors).as_bytes());
        hasher.update(inner.device_fingerprint().sha256_hash.as_bytes());
        let hash_hex = hex::encode(hasher.finalize());

        let fingerprint = DeviceFingerprint {
            manufacturer: "Vajra Decrypted Volume".to_string(),
            model: format!("Unlocked {}", format_name),
            serial: format!("VOL-{}-{}", &format_name[..4.min(format_name.len())], &hash_hex[..8].to_uppercase()),
            capacity_bytes: total_logical_blocks * (inner.block_size() as u64),
            sha256_hash: hash_hex,
            interface: "Decrypted-Virtual".to_string(),
        };

        Self {
            inner,
            cipher,
            payload_offset_sectors,
            total_logical_blocks,
            format_name: format_name.to_string(),
            fingerprint,
        }
    }

    pub fn format_name(&self) -> &str {
        &self.format_name
    }

    pub fn cipher_name(&self) -> &str {
        self.cipher.cipher_name()
    }

    pub fn payload_offset_sectors(&self) -> u64 {
        self.payload_offset_sectors
    }
}

impl<T: ReadOnlyBlockSource> ReadOnlyBlockSource for EncryptedVolume<T> {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        if lba + (count as u64) > self.total_logical_blocks {
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!(
                    "Read out of bounds: LBA {}..{} exceeds decrypted volume capacity {}",
                    lba,
                    lba + (count as u64),
                    self.total_logical_blocks
                ),
            });
        }

        let block_size = self.inner.block_size() as usize;
        let source_lba = self.payload_offset_sectors + lba;

        // Read encrypted blocks from underlying storage
        let ciphertext = self.inner.read_blocks(source_lba, count)?;
        let mut plaintext = vec![0u8; ciphertext.len()];

        // Decrypt sector by sector with LBA tweak
        for (i, (ct_chunk, pt_chunk)) in ciphertext.chunks_exact(block_size).zip(plaintext.chunks_exact_mut(block_size)).enumerate() {
            let sector_lba = lba + (i as u64);
            self.cipher.decrypt_sector(sector_lba, ct_chunk, pt_chunk).map_err(|e| {
                IoError::ReadFailureAtLba {
                    lba: sector_lba,
                    count: 1,
                    details: format!("Decryption error: {}", e),
                }
            })?;
        }

        Ok(plaintext)
    }

    fn total_blocks(&self) -> u64 {
        self.total_logical_blocks
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn media_type(&self) -> MediaType {
        MediaType::ForensicImage
    }

    fn is_write_blocked(&self) -> bool {
        true // Strictly read-only block source per §16
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        None
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.fingerprint.clone()
    }
}
