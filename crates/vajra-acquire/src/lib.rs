//! # vajra-acquire
//!
//! Evidence Acquisition, Imaging Orchestration, Bad-Sector Handling, and Integrity Hashing (§19, §20).
//!
//! # Architecture & Guarantees
//! - **Type-Safety Split (§16)**: All source device access is typed against [`vajra_core::ReadOnlyBlockSource`].
//!   It is syntactically and structurally impossible to issue a write against source media during acquisition.
//! - **Flowchart Bad-Sector Recovery (§20)**: Retries with backoff, block size reduction to single-sector resolution,
//!   and non-ambiguous placeholder substitution (`b"VAJRA_BAD_SECTOR"`).
//! - **Single Source of Truth**: [`BadSectorMap`] is the single authoritative source of truth for unreadable sectors.
//! - **Dual-Phase Integrity Hashing (§19)**: Streaming rolling SHA-256 calculation followed by an independent
//!   re-read verification pass over the finalized image file.
//! - **Resumability (NFR-1)**: Persistent checkpointing via [`vajra_case_db::CaseDb`] with hardware fingerprint validation.
//! - **Evidence Vault, Audit Chain, and Custody Ledger Integration**: Full end-to-end recording.

pub mod bad_sector;
pub mod checkpoint;
pub mod engine;
pub mod error;
pub mod hasher;
pub mod mock;
pub mod profile;

pub use bad_sector::{BadSectorMap, BadSectorStrategy, UnreadableRange, DEFAULT_BAD_SECTOR_MARKER};
pub use checkpoint::AcquisitionCheckpoint;
pub use engine::{AcquisitionConfig, AcquisitionEngine, AcquisitionProgressHook, AcquisitionResult};
pub use error::AcquisitionError;
pub use hasher::{verify_image_file, AcquisitionHasher};
pub use mock::{InjectedFault, SimulatedFaultyBlockSource};
pub use profile::AcquisitionProfile;
