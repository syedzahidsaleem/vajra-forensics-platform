//! Expert Witness Format (E01 / EWF) forensic image reader (§19).
//!
//! Uses pure-Rust `ewf` reader to parse E01 images, extract embedded case
//! metadata, verify chunk CRCs, and wrap the disk image in [`ReadOnlyBlockSource`].

use crate::error::ImageError;
use crate::metadata::{ImageFormat, ImageMetadata, StoredHashes};
use crate::traits::ForensicImageReader;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use vajra_core::{DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, WriteBlockerMetadata};

/// Pure-Rust reader for Expert Witness Format (.E01 / .Ex01) forensic disk images.
pub struct E01ImageReader {
    path: PathBuf,
    reader: ewf::EwfReader,
    metadata: ImageMetadata,
    fingerprint: DeviceFingerprint,
}

impl E01ImageReader {
    /// Opens an E01 forensic disk image from the filesystem.
    /// Automatically handles multi-segment sets (.E01, .E02, etc.).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ImageError> {
        let path_buf = path.as_ref().to_path_buf();
        let mut ewf_reader = ewf::EwfReader::open(&path_buf)
            .map_err(|e| ImageError::EwfError(format!("Failed to open E01 image '{}': {}", path_buf.display(), e)))?;

        let bsize = 512u32;
        let total_bytes = ewf_reader.total_size();
        let total_sectors = total_bytes.div_ceil(bsize as u64);

        let ewf_meta = ewf_reader.metadata();
        let mut case_meta = HashMap::new();
        if let Some(ref c) = ewf_meta.case_number {
            case_meta.insert("CaseNumber".to_string(), c.clone());
        }
        if let Some(ref e) = ewf_meta.evidence_number {
            case_meta.insert("EvidenceNumber".to_string(), e.clone());
        }
        if let Some(ref ex) = ewf_meta.examiner {
            case_meta.insert("Examiner".to_string(), ex.clone());
        }
        if let Some(ref d) = ewf_meta.description {
            case_meta.insert("Description".to_string(), d.clone());
        }
        if let Some(ref n) = ewf_meta.notes {
            case_meta.insert("Notes".to_string(), n.clone());
        }

        let ewf_hashes = ewf_reader.stored_hashes();
        let stored_hashes = StoredHashes {
            md5: ewf_hashes.md5.map(hex::encode),
            sha1: ewf_hashes.sha1.map(hex::encode),
            sha256: None,
        };

        // Read LBA 0 for fingerprint
        let mut lba0 = vec![0u8; bsize.min(4096) as usize];
        let _ = ewf_reader.seek(SeekFrom::Start(0));
        let bytes_read = ewf_reader.read(&mut lba0).unwrap_or(0);
        lba0.truncate(bytes_read);

        let serial = if let Some(ref md5) = stored_hashes.md5 {
            format!("E01-{}", &md5[..16.min(md5.len())])
        } else if let Some(ref sha1) = stored_hashes.sha1 {
            format!("E01-{}", &sha1[..16.min(sha1.len())])
        } else {
            let file_name = path_buf.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            format!("E01-{}", file_name)
        };

        let file_name = path_buf
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "image.e01".to_string());
        let model = format!("E01 Forensic Image ({})", file_name);

        let fingerprint = DeviceFingerprint::compute(
            "Expert Witness Format",
            &model,
            &serial,
            total_bytes,
            "Local E01 Image",
            &lba0,
        );

        let metadata = ImageMetadata {
            format: ImageFormat::E01,
            capacity_bytes: total_bytes,
            block_size: bsize,
            total_blocks: total_sectors,
            case_metadata: case_meta,
            stored_hashes,
        };

        Ok(Self {
            path: path_buf,
            reader: ewf_reader,
            metadata,
            fingerprint,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ReadOnlyBlockSource for E01ImageReader {
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

        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("Failed to seek to offset {}: {}", offset, e),
            })?;

        let bytes_actually_read = self
            .reader
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

impl ForensicImageReader for E01ImageReader {
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
