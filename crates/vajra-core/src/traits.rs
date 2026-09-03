//! Canonical Block Device Abstraction Traits.
//!
//! Verbatim implementation of the `ReadOnlyBlockSource` and `WritableBlockSource` traits
//! specified in Vajra Master Technical Document §16.
//!
//! # Type-Level Safety Split
//!
//! The recovery engine and forensic analysis crates operate exclusively against
//! `&mut dyn ReadOnlyBlockSource`. Because `WritableBlockSource` is a distinct trait extending
//! `ReadOnlyBlockSource`, and read-only types (such as `PhysicalDrive` or `ForensicImage`) do NOT
//! implement `WritableBlockSource`, it is a compile-time impossibility for recovery/carving code
//! to issue a write operation against original evidence.

use crate::error::IoError;
use crate::fingerprint::DeviceFingerprint;
use crate::media_type::MediaType;
use crate::sanitize::SanitizeMethod;
use crate::write_blocker::WriteBlockerMetadata;

/// Implemented by anything that can be read from: physical devices,
/// forensic images, RAID arrays composed of local drives, and
/// decrypted views of encrypted volumes.
pub trait ReadOnlyBlockSource: Send {
    /// Read `count` contiguous blocks starting from logical block address `lba`.
    ///
    /// # Returns
    /// A buffer of exactly `count * self.block_size()` bytes on success.
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError>;

    /// Total number of addressable logical blocks on the storage source.
    fn total_blocks(&self) -> u64;

    /// Logical block size in bytes (e.g. 512, 4096).
    fn block_size(&self) -> u32;

    /// Media type classification (Hdd, SataSsd, Nvme, Sed, Usb, SdCard, ForensicImage).
    fn media_type(&self) -> MediaType;

    /// Whether hardware or software write-blocking is active.
    fn is_write_blocked(&self) -> bool;

    /// Optional metadata describing detected write-blocker hardware or state.
    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata>;

    /// Cryptographically deterministic device fingerprint (§23).
    fn device_fingerprint(&self) -> DeviceFingerprint;
}

impl<T: ?Sized + ReadOnlyBlockSource> ReadOnlyBlockSource for Box<T> {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        (**self).read_blocks(lba, count)
    }

    fn total_blocks(&self) -> u64 {
        (**self).total_blocks()
    }

    fn block_size(&self) -> u32 {
        (**self).block_size()
    }

    fn media_type(&self) -> MediaType {
        (**self).media_type()
    }

    fn is_write_blocked(&self) -> bool {
        (**self).is_write_blocked()
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        (**self).write_blocker_info()
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        (**self).device_fingerprint()
    }
}

/// Only implemented by live physical devices being deliberately
/// operated on in Sanitization Mode. A ForensicImage type, by
/// construction, never implements this trait.
pub trait WritableBlockSource: ReadOnlyBlockSource {
    /// Write contiguous block data starting at logical block address `lba`.
    ///
    /// `data.len()` must be an exact multiple of `self.block_size()`.
    fn write_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), IoError>;

    /// List of hardware-supported sanitization methods for this device (§33a, §35).
    fn supported_sanitize_methods(&self) -> Vec<SanitizeMethod>;

    /// Issue a hardware or firmware-level sanitization command (§35).
    fn issue_sanitize(&mut self, method: SanitizeMethod) -> Result<(), IoError>;
}
