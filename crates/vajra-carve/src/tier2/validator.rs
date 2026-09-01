//! Garfinkel Structural Validator Framework (§26.2).
//!
//! Implements the fast object validation framework from Simson Garfinkel's seminal paper:
//! *"Carving contiguous and fragmented files with fast object validation"* (DFRWS 2007).
//!
//! Return values:
//! - `V_OK`: Object is structurally valid and complete, with optional determinable byte length.
//! - `V_EOF`: Ran out of input data before completing structure without encountering a corruption error (e.g. truncated scan data).
//! - `V_ERR`: Structural syntax error, invalid checksum, or bitstream decode failure.
//!
//! Flags:
//! - `err_is_prefix`: If true, a failure during sequential parsing cannot be corrected by appending more data (e.g. JPEG Huffman decode).
//! - `appended_data_ignored`: If true, trailing extraneous bytes after the complete object are ignored, enabling binary-search length bounding.
//! - `no_zblocks`: If true, the format cannot legitimately contain all-zero 512-byte blocks (early rejection filter).

use std::fmt;

/// Result of structural validation (§26.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Object is structurally valid.
    /// `object_length` is the exact byte length if determinable from internal format headers.
    Ok { object_length: Option<u64> },

    /// Reached end of data without error, but object is truncated / incomplete.
    Eof { partial_length: u64 },

    /// Structural corruption, invalid checksum, or syntax error.
    Err(String),
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }

    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof { .. })
    }

    pub fn is_err(&self) -> bool {
        matches!(self, Self::Err(_))
    }

    /// Converts validation result to a normalized 0.0–1.0 structural confidence score.
    pub fn to_confidence(&self) -> f32 {
        match self {
            Self::Ok { .. } => 1.0,
            Self::Eof { .. } => 0.5,
            Self::Err(_) => 0.0,
        }
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok { object_length: Some(len) } => write!(f, "V_OK (Length: {} bytes)", len),
            Self::Ok { object_length: None } => write!(f, "V_OK (Length: Unbounded)"),
            Self::Eof { partial_length } => write!(f, "V_EOF (Truncated at {} bytes)", partial_length),
            Self::Err(msg) => write!(f, "V_ERR ({})", msg),
        }
    }
}

/// Validator configuration flags defining carving search strategy (§26.2, Garfinkel 2007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorFlags {
    /// Sequential parse error cannot be cured by appending more data.
    pub err_is_prefix: bool,

    /// Trailing bytes after object end are ignored by standard parsers.
    pub appended_data_ignored: bool,

    /// Object cannot contain all-null (0x00) 512-byte blocks.
    pub no_zblocks: bool,
}

/// Trait implemented by format-specific structural validators (§26.2).
pub trait StructuralValidator: Send + Sync {
    /// Executes structural validation against candidate byte slice.
    fn validate(&self, data: &[u8]) -> ValidationResult;

    /// Returns strategy flags for this file format.
    fn flags(&self) -> ValidatorFlags;

    /// Returns the canonical file type name (e.g. "jpeg", "png", "pdf").
    fn file_type(&self) -> &'static str;
}
