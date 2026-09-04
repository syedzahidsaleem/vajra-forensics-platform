//! Metadata structures for forensic disk images (§19).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported forensic image container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageFormat {
    /// Raw / DD flat byte stream (.raw, .dd, .img, .bin).
    Raw,
    /// Expert Witness Format (E01 / Ex01 / L01).
    E01,
    /// Advanced Forensic Format 4 (AFF4) - Deferred to Future Scope (§53).
    Aff4,
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => write!(f, "RAW"),
            Self::E01 => write!(f, "E01"),
            Self::Aff4 => write!(f, "AFF4"),
        }
    }
}

/// Stored integrity hashes extracted from container headers (e.g. E01).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

/// Descriptive metadata extracted from or written to a forensic image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub format: ImageFormat,
    pub capacity_bytes: u64,
    pub block_size: u32,
    pub total_blocks: u64,
    pub case_metadata: HashMap<String, String>,
    pub stored_hashes: StoredHashes,
}
