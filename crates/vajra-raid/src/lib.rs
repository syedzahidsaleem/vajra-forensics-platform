//! # vajra-raid
//!
//! Advanced software RAID reconstruction and degraded data recovery engine (§15 Part III, §16).
//!
//! Exposes assembled multi-disk RAID 0, RAID 5, and RAID 6 volumes as standard `ReadOnlyBlockSource` instances.
//! Provides on-the-fly XOR and Galois Field GF(2^8) Reed-Solomon syndromic reconstruction for failed members.

pub mod array;
pub mod error;
pub mod galois;
pub mod layout;
pub mod superblock;

pub use array::RaidArray;
pub use error::RaidError;
pub use galois::GaloisField;
pub use layout::{DiskBlockLocation, ParityLayout, RaidGeometry, RaidLevel};
pub use superblock::{detect_mdadm_superblock, write_mdadm_1_2_superblock, MdadmSuperblock};
