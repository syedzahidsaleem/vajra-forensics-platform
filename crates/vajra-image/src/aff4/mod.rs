//! Advanced Forensic Format 4 (AFF4) module (§19).
//!
//! AFF4 is a container-based forensic format designed for sparse/segmented acquisitions.
//! Per §19 and §53, AFF4 support is staged for Future Scope / Advanced MVP.

use crate::error::ImageError;

/// Stub function for AFF4 opening.
pub fn open_aff4_not_implemented() -> Result<(), ImageError> {
    Err(ImageError::UnsupportedFormat(
        "AFF4 format support is deferred to Future Scope (§19, §53)".to_string(),
    ))
}
