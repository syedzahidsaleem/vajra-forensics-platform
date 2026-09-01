//! # vajra-image
//!
//! Pure format layer for reading and writing forensic disk image containers (§19).
//!
//! Supports:
//! - **RAW / DD**: Flat byte-for-byte disk images with high-performance unbuffered/buffered streaming.
//! - **E01 (Expert Witness Format)**: Pure-Rust read support via `ewf` for `.E01` and `.Ex01` images,
//!   extracting volume geometry, embedded case metadata, and stored hashes.
//! - **AFF4**: Module stub documenting future scope (§53).
//!
//! All image reader implementations implement [`vajra_core::ReadOnlyBlockSource`], enabling
//! seamless integration into downstream filesystem parsers and carving engines.

pub mod aff4;
pub mod e01;
pub mod error;
pub mod metadata;
pub mod raw;
pub mod traits;

pub use e01::E01ImageReader;
pub use error::ImageError;
pub use metadata::{ImageFormat, ImageMetadata, StoredHashes};
pub use raw::{RawImageReader, RawImageWriter};
pub use traits::{ForensicImageReader, ForensicImageWriter};
