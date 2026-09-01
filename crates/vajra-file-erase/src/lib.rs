//! Module 2: Secure File & Folder Erasure (§36).
//!
//! Provides filesystem-aware selective file deletion, free-after-overwrite crash safety,
//! and the five-state Residual Artifact Scanner (§7.2, §36).

pub mod error;
pub mod file_eraser;
pub mod local_eraser;
pub mod scanner;

pub use error::FileEraseError;
pub use file_eraser::{
    erase_data_extents_destructive, execute_file_erasure_pipeline_destructive,
    zero_metadata_record_destructive, FileErasureReport,
};
pub use local_eraser::erase_local_file_destructive;
pub use scanner::{ResidualArtifactScanner, ResidualScanResult};
