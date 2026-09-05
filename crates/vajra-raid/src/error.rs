//! Error types for RAID array reconstruction and diagnostics (§15 Part III, §16).

use thiserror::Error;
use vajra_core::error::IoError;

#[derive(Debug, Error)]
pub enum RaidError {
    #[error("I/O error on RAID member: {0}")]
    Io(#[from] IoError),

    #[error("Invalid RAID geometry or layout: {0}")]
    InvalidGeometry(String),

    #[error("Superblock not found on provided member drives")]
    SuperblockNotFound,

    #[error("Corrupted RAID superblock on member #{member_idx}: {reason}")]
    CorruptedSuperblock { member_idx: usize, reason: String },

    #[error("Unrecoverable degraded state: {0}")]
    UnrecoverableDegraded(String),

    #[error("Member drive mismatch: {0}")]
    MemberMismatch(String),

    #[error("Invalid chunk size: {0} bytes (must be power of 2 and sector-aligned)")]
    InvalidChunkSize(u32),

    #[error("Member count mismatch: expected {expected}, provided {found}")]
    MemberCountMismatch { expected: usize, found: usize },

    #[error("Insufficient surviving members for RAID level {level:?}: {surviving} of {total} present")]
    InsufficientMembers {
        level: String,
        surviving: usize,
        total: usize,
    },
}
