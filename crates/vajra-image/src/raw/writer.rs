//! Raw / DD flat forensic image writer (§19).

use crate::error::ImageError;
use crate::metadata::{ImageFormat, ImageMetadata, StoredHashes};
use crate::traits::ForensicImageWriter;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Sequential RAW / DD flat byte stream writer.
pub struct RawImageWriter {
    path: PathBuf,
    writer: BufWriter<File>,
    block_size: u32,
    bytes_written: u64,
    highest_lba: u64,
}

impl RawImageWriter {
    /// Creates or truncates a RAW image file for writing.
    pub fn create<P: AsRef<Path>>(path: P, block_size: u32) -> Result<Self, ImageError> {
        let path_buf = path.as_ref().to_path_buf();
        if block_size == 0 {
            return Err(ImageError::InvalidHeader {
                path: path_buf.display().to_string(),
                reason: "Block size cannot be zero".to_string(),
            });
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_buf)?;

        let writer = BufWriter::with_capacity(1024 * 1024, file); // 1 MB buffer for high throughput

        Ok(Self {
            path: path_buf,
            writer,
            block_size,
            bytes_written: 0,
            highest_lba: 0,
        })
    }

    /// Opens an existing image file in append/resume mode.
    pub fn open_for_resume<P: AsRef<Path>>(path: P, block_size: u32) -> Result<Self, ImageError> {
        let path_buf = path.as_ref().to_path_buf();
        if block_size == 0 {
            return Err(ImageError::InvalidHeader {
                path: path_buf.display().to_string(),
                reason: "Block size cannot be zero".to_string(),
            });
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path_buf)?;

        let file_len = file.metadata()?.len();
        let writer = BufWriter::with_capacity(1024 * 1024, file);

        let highest_lba = file_len / block_size as u64;

        Ok(Self {
            path: path_buf,
            writer,
            block_size,
            bytes_written: file_len,
            highest_lba,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ForensicImageWriter for RawImageWriter {
    fn write_image_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), ImageError> {
        let offset = lba * self.block_size as u64;
        self.writer.seek(SeekFrom::Start(offset))?;
        self.writer.write_all(data)?;

        let end_offset = offset + data.len() as u64;
        if end_offset > self.bytes_written {
            self.bytes_written = end_offset;
            self.highest_lba = end_offset / self.block_size as u64;
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<ImageMetadata, ImageError> {
        self.writer.flush()?;

        let total_blocks = self.bytes_written.div_ceil(self.block_size as u64);

        Ok(ImageMetadata {
            format: ImageFormat::Raw,
            capacity_bytes: self.bytes_written,
            block_size: self.block_size,
            total_blocks,
            case_metadata: HashMap::new(),
            stored_hashes: StoredHashes::default(),
        })
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}
