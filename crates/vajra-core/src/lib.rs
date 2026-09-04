//! # vajra-core
//!
//! Core traits, domain types, and error definitions for the Vajra Offline-First
//! Digital Forensics and Secure Data Sanitization Platform.
//!
//! This crate contains zero device I/O or platform-specific syscalls. It defines:
//! - [`ReadOnlyBlockSource`] and [`WritableBlockSource`] traits (§16)
//! - [`MediaType`] storage classification enum (§16)
//! - [`IoError`] canonical error type (§16)
//! - [`DeviceFingerprint`] deterministic identity fingerprint (§23)
//! - [`WriteBlockerMetadata`] write-blocker detection records (§24)
//! - [`SanitizeMethod`] sanitization command specifications (§35)

pub mod error;
pub mod fingerprint;
pub mod fs;
pub mod media_type;
pub mod operation;
pub mod sanitize;
pub mod traits;
pub mod write_blocker;

pub use error::IoError;
pub use fingerprint::DeviceFingerprint;
pub use fs::{
    detect_filesystem, DataLocation, FilesystemType, MetadataConfidence, RecoverableFileEntry,
};
pub use media_type::MediaType;
pub use operation::{OperationResult, OperationType};
pub use sanitize::SanitizeMethod;
pub use traits::{ReadOnlyBlockSource, WritableBlockSource};
pub use write_blocker::{WriteBlockerDetectionMethod, WriteBlockerMetadata};
