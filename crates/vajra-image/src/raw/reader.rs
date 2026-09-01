//! Raw / DD flat forensic image reader (§19).

use crate::error::ImageError;
use crate::metadata::{ImageFormat, ImageMetadata, StoredHashes};
use crate::traits::ForensicImageReader;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use vajra_core::{DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, WriteBlockerMetadata};

/// Flat byte-for-byte RAW/DD forensic disk image reader.
pub struct RawImageReader {
    path: PathBuf,
    file: File,
    metadata: ImageMetadata,
    fingerprint: DeviceFingerprint,
}

impl RawImageReader {
    /// Opens a RAW forensic disk image from the filesystem.
    ///
    /// # Arguments
    /// * `path` - Absolute or relative path to the image file.
    /// * `block_size` - Optional logical block size (defaults to 512 bytes).
    pub fn open<P: AsRef<Path>>(path: P, block_size: Option<u32>) -> Result<Self, ImageError> {
        let path_buf = path.as_ref().to_path_buf();
        let mut file = File::open(&path_buf)?;
        let file_len = file.metadata()?.len();

        let bsize = block_size.unwrap_or(512);
        if bsize == 0 {
            return Err(ImageError::InvalidHeader {
                path: path_buf.display().to_string(),
                reason: "Block size cannot be zero".to_string(),
            });
        }

        let total_blocks = file_len.div_ceil(bsize as u64);

        // Read LBA 0 boundary sample for deterministic fingerprinting (§23)
        let mut lba0 = vec![0u8; bsize.min(4096) as usize];
        file.seek(SeekFrom::Start(0))?;
        let bytes_read = file.read(&mut lba0)?;
        lba0.truncate(bytes_read);

        // Derive deterministic serial from LBA 0 content + file length
        let mut hasher = Sha256::new();
        hasher.update(&lba0);
        hasher.update(file_len.to_le_bytes());
        let digest_hex = hex::encode(hasher.finalize());
        let serial = format!("RAW-{}", &digest_hex[..16]);

        let file_name = path_buf
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "image.raw".to_string());
        let model = format!("RAW Forensic Image ({})", file_name);

        let fingerprint = DeviceFingerprint::compute(
            "Vajra Forensic Image",
            &model,
            &serial,
            file_len,
            "Local File",
            &lba0,
        );

        let metadata = ImageMetadata {
            format: ImageFormat::Raw,
            capacity_bytes: file_len,
            block_size: bsize,
            total_blocks,
            case_metadata: HashMap::new(),
            stored_hashes: StoredHashes::default(),
        };

        Ok(Self {
            path: path_buf,
            file,
            metadata,
            fingerprint,
        })
    }

    /// Path to the backing image file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ReadOnlyBlockSource for RawImageReader {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        let bsize = self.metadata.block_size as u64;
        let total_b = self.metadata.total_blocks;

        if lba >= total_b && total_b > 0 {
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("Requested LBA {} exceeds total blocks {}", lba, total_b),
            });
        }

        let offset = lba.checked_mul(bsize).ok_or_else(|| IoError::ReadFailureAtLba {
            lba,
            count,
            details: "LBA offset overflow".to_string(),
        })?;

        let bytes_to_read = (count as u64)
            .checked_mul(bsize)
            .ok_or_else(|| IoError::ReadFailureAtLba {
                lba,
                count,
                details: "Byte count overflow".to_string(),
            })? as usize;

        let mut buffer = vec![0u8; bytes_to_read];

        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("Failed to seek to offset {}: {}", offset, e),
            })?;

        let bytes_actually_read = self
            .file
            .read(&mut buffer)
            .map_err(|e| IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("Failed to read {} bytes at offset {}: {}", bytes_to_read, offset, e),
            })?;

        if bytes_actually_read < bytes_to_read {
            for byte in &mut buffer[bytes_actually_read..] {
                *byte = 0;
            }
        }

        Ok(buffer)
    }

    fn total_blocks(&self) -> u64 {
        self.metadata.total_blocks
    }

    fn block_size(&self) -> u32 {
        self.metadata.block_size
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
        self.fingerprint.clone()
    }
}

impl ForensicImageReader for RawImageReader {
    fn image_metadata(&self) -> &ImageMetadata {
        &self.metadata
    }

    fn read_image_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, ImageError> {
        self.read_blocks(lba, count)
            .map_err(|e| match e {
                IoError::ReadFailureAtLba { lba, .. } => ImageError::OutOfBounds {
                    requested_lba: lba,
                    total_blocks: self.metadata.total_blocks,
                },
                other => ImageError::Io(std::io::Error::other(other.to_string())),
            })
    }
}
