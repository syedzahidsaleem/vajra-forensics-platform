//! # vajra-device
//!
//! Direct physical block device detection, fingerprinting, SMART/NVMe health diagnostics,
//! write-blocker detection, and sector I/O for Windows and Linux (§23–§24).
//!
//! # Architecture & Safety
//!
//! - [`PhysicalDrive`]: Read-only device handle implementing [`vajra_core::ReadOnlyBlockSource`].
//! - [`WritablePhysicalDrive`]: Writable device handle implementing [`vajra_core::WritableBlockSource`].
//! - [`enumerate_devices`]: Hardware block storage discovery with OS system-disk and write-blocker flagging.
//! - [`fingerprint_device`]: Deterministic SHA-256 identity computation (§23).
//! - [`device_health`]: Diagnostic report generation with calibrated thresholds (§23).

pub mod descriptor;
pub mod detection;
pub mod drive;
pub mod health;
pub mod os;

pub use descriptor::DeviceDescriptor;
pub use detection::{check_write_blocker, detect_partition_table};
pub use drive::{PhysicalDrive, WritablePhysicalDrive};
pub use health::{
    DeviceHealth, HddHealthInfo, HealthStatus, HpaDcoInfo, NvmeHealthInfo, SmartAttribute,
};
pub use os::imp::enumerate_devices;

use vajra_core::{DeviceFingerprint, IoError};

/// Computes the deterministic SHA-256 device fingerprint for a given descriptor (§23).
///
/// Hashes stable identity attributes (serial, model, capacity) and boundary sector sample.
pub fn fingerprint_device(descriptor: &DeviceDescriptor) -> Result<DeviceFingerprint, IoError> {
    Ok(DeviceFingerprint::compute(
        &descriptor.manufacturer,
        &descriptor.model,
        &descriptor.serial,
        descriptor.capacity_bytes,
        &descriptor.interface,
        &descriptor.boundary_sample,
    ))
}

/// Queries hardware health diagnostics for a device descriptor (§23).
pub fn device_health(descriptor: &DeviceDescriptor) -> Result<DeviceHealth, IoError> {
    os::imp::query_device_health(descriptor)
}
