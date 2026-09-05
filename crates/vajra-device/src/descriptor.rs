//! Storage device descriptor and identity metadata.
//!
//! Provides the normalized `DeviceDescriptor` for all physical block storage devices (§23).

use serde::{Deserialize, Serialize};
use vajra_core::{MediaType, WriteBlockerMetadata};

/// Normalized metadata descriptor for a physical storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDescriptor {
    /// OS device path (e.g. `\\.\PhysicalDrive0` on Windows, `/dev/nvme0n1` on Linux).
    pub path: String,
    /// Numeric device index (e.g. 0 for PhysicalDrive0).
    pub device_index: u32,
    /// Manufacturer or vendor name (e.g. "Samsung", "Western Digital").
    pub manufacturer: String,
    /// Hardware model name (e.g. "SSD 980 PRO 1TB").
    pub model: String,
    /// Hardware serial number.
    pub serial: String,
    /// Total capacity in bytes.
    pub capacity_bytes: u64,
    /// Logical block size in bytes (typically 512 or 4096).
    pub logical_block_size: u32,
    /// Physical block size in bytes (e.g. 4096 for Advanced Format 4Kn/512e).
    pub physical_block_size: u32,
    /// Media type classification (§16).
    pub media_type: MediaType,
    /// Interface / transport bus type (e.g. "NVMe", "SATA", "USB", "SCSI").
    pub interface: String,
    /// Partition table classification ("GPT", "MBR", or "Raw / Unpartitioned").
    pub partition_table: String,
    /// True if the device hosts the host operating system boot or root volume (§24).
    ///
    /// Note: `vajra-device` only detects and flags this property. Refusal/enforcement
    /// logic belongs to the Safety/Policy Engine.
    pub is_system_disk: bool,
    /// True if the device is reported as read-only by the operating system.
    pub is_read_only: bool,
    /// True if hardware or software write-blocking is detected.
    pub is_write_blocked: bool,
    /// Optional metadata describing the detected write blocker.
    pub write_blocker_info: Option<WriteBlockerMetadata>,
    /// Sample bytes from the device boundary (first sector / LBA 0) for fingerprinting.
    pub boundary_sample: Vec<u8>,
}

impl DeviceDescriptor {
    /// Human-readable capacity formatted in standard binary/decimal units (e.g. "1.92 TB").
    pub fn formatted_capacity(&self) -> String {
        let bytes = self.capacity_bytes as f64;
        if bytes >= 1_000_000_000_000.0 {
            format!("{:.2} TB ({:.2} TiB)", bytes / 1_000_000_000_000.0, bytes / (1024.0 * 1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1_000_000_000.0 {
            format!("{:.2} GB ({:.2} GiB)", bytes / 1_000_000_000.0, bytes / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1_000_000.0 {
            format!("{:.2} MB ({:.2} MiB)", bytes / 1_000_000.0, bytes / (1024.0 * 1024.0))
        } else {
            format!("{} bytes", self.capacity_bytes)
        }
    }
}
