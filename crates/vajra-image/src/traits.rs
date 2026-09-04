//! Common traits for reading and writing forensic disk image containers (§19).

use crate::error::ImageError;
use crate::metadata::ImageMetadata;
use vajra_core::ReadOnlyBlockSource;

/// Common interface for reading forensic images (RAW/DD, E01).
///
/// Implemented types automatically plug into the Vajra recovery pipeline
/// by also implementing [`ReadOnlyBlockSource`].
pub trait ForensicImageReader: ReadOnlyBlockSource {
    /// Return the parsed structural metadata for this image.
    fn image_metadata(&self) -> &ImageMetadata;

    /// Read raw blocks starting at logical block address `lba`.
    fn read_image_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, ImageError>;
}

/// Common interface for writing forensic disk image containers.
pub trait ForensicImageWriter: Send {
    /// Write contiguous block data starting at `lba`.
    fn write_image_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), ImageError>;

    /// Finalize container structures, write trailing metadata/hashes, and flush to disk.
    fn finalize(&mut self) -> Result<ImageMetadata, ImageError>;

    /// Return total bytes written so far.
    fn bytes_written(&self) -> u64;
}
