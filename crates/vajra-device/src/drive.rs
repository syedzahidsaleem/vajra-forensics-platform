//! Concrete Physical Storage Block Device Implementations (§16, §23, §24).
//!
//! # Strict Type-Level Safety Split
//!
//! - [`PhysicalDrive`]: Implements ONLY [`ReadOnlyBlockSource`]. It has NO `.write_blocks()`
//!   method and NO [`WritableBlockSource`] implementation. This guarantees at compile time
//!   that recovery, carving, and analysis engines cannot write to evidence.
//!
//! - [`WritablePhysicalDrive`]: Implements [`WritableBlockSource`] (and [`ReadOnlyBlockSource`]).
//!   Constructed exclusively through [`WritablePhysicalDrive::open_writable`] for explicit
//!   sanitization operations.

use crate::descriptor::DeviceDescriptor;
use crate::health::DeviceHealth;
use crate::os::imp::{query_device_health, OsDriveHandle};
use std::path::Path;
use vajra_core::{
    DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, SanitizeMethod,
    WritableBlockSource, WriteBlockerMetadata,
};

/// Read-only physical block storage device (§16, §23).
///
/// Implements ONLY [`ReadOnlyBlockSource`]. By construction, it contains no write methods
/// and cannot be passed to any API requiring [`WritableBlockSource`].
pub struct PhysicalDrive {
    descriptor: DeviceDescriptor,
    handle: OsDriveHandle,
    fingerprint: DeviceFingerprint,
}

impl PhysicalDrive {
    /// Opens a physical block device in read-only mode.
    ///
    /// # Safety and Access
    ///
    /// Opening physical storage devices on Windows/Linux requires elevated Administrator/root privileges.
    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self, IoError> {
        let p = path.as_ref();
        let handle = OsDriveHandle::open_readonly(p)?;

        // Enumerate devices to locate descriptor
        let devices = crate::enumerate_devices()?;
        let path_str = p.to_string_lossy().to_string();

        let descriptor = devices
            .into_iter()
            .find(|d| d.path.eq_ignore_ascii_case(&path_str) || path_str.contains(&d.path))
            .unwrap_or_else(|| {
                let file_len = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                DeviceDescriptor {
                    path: path_str.clone(),
                    device_index: 0,
                    manufacturer: "Generic".to_string(),
                    model: "Physical Drive".to_string(),
                    serial: "UNKNOWN".to_string(),
                    capacity_bytes: file_len,
                    logical_block_size: 512,
                    physical_block_size: 512,
                    media_type: MediaType::Hdd,
                    interface: "Direct".to_string(),
                    partition_table: "Unknown".to_string(),
                    is_system_disk: false,
                    is_read_only: true,
                    is_write_blocked: false,
                    write_blocker_info: None,
                    boundary_sample: vec![0u8; 512],
                }
            });

        let fingerprint = DeviceFingerprint::compute(
            &descriptor.manufacturer,
            &descriptor.model,
            &descriptor.serial,
            descriptor.capacity_bytes,
            &descriptor.interface,
            &descriptor.boundary_sample,
        );

        Ok(Self {
            descriptor,
            handle,
            fingerprint,
        })
    }

    /// Accesses the underlying device metadata descriptor.
    pub fn descriptor(&self) -> &DeviceDescriptor {
        &self.descriptor
    }

    /// Queries the hardware health diagnostic report (§23).
    pub fn health(&self) -> Result<DeviceHealth, IoError> {
        query_device_health(&self.descriptor)
    }
}

impl ReadOnlyBlockSource for PhysicalDrive {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        self.handle.read_blocks(lba, count, self.descriptor.logical_block_size)
    }

    fn total_blocks(&self) -> u64 {
        if self.descriptor.logical_block_size == 0 {
            0
        } else {
            self.descriptor.capacity_bytes / (self.descriptor.logical_block_size as u64)
        }
    }

    fn block_size(&self) -> u32 {
        self.descriptor.logical_block_size
    }

    fn media_type(&self) -> MediaType {
        self.descriptor.media_type
    }

    fn is_write_blocked(&self) -> bool {
        self.descriptor.is_write_blocked
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        self.descriptor.write_blocker_info.clone()
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.fingerprint.clone()
    }
}

/// Writable physical block storage device for Sanitization Mode only (§16, §35).
///
/// Implements [`WritableBlockSource`] and [`ReadOnlyBlockSource`].
pub struct WritablePhysicalDrive {
    descriptor: DeviceDescriptor,
    handle: OsDriveHandle,
    fingerprint: DeviceFingerprint,
}

impl WritablePhysicalDrive {
    /// Opens a physical block device in writable mode for destructive sanitization operations.
    ///
    /// # Safety and Access
    ///
    /// This constructor must only be invoked from Sanitization Mode workflows after
    /// explicit operator identity re-confirmation (§43).
    pub fn open_writable(path: impl AsRef<Path>) -> Result<Self, IoError> {
        let p = path.as_ref();
        let handle = OsDriveHandle::open_writable(p)?;

        let devices = crate::enumerate_devices()?;
        let path_str = p.to_string_lossy().to_string();

        let descriptor = devices
            .into_iter()
            .find(|d| d.path.eq_ignore_ascii_case(&path_str) || path_str.contains(&d.path))
            .unwrap_or_else(|| DeviceDescriptor {
                path: path_str.clone(),
                device_index: 0,
                manufacturer: "Generic".to_string(),
                model: "Physical Drive".to_string(),
                serial: "UNKNOWN".to_string(),
                capacity_bytes: 0,
                logical_block_size: 512,
                physical_block_size: 512,
                media_type: MediaType::Hdd,
                interface: "Direct".to_string(),
                partition_table: "Unknown".to_string(),
                is_system_disk: false,
                is_read_only: false,
                is_write_blocked: false,
                write_blocker_info: None,
                boundary_sample: vec![0u8; 512],
            });

        let fingerprint = DeviceFingerprint::compute(
            &descriptor.manufacturer,
            &descriptor.model,
            &descriptor.serial,
            descriptor.capacity_bytes,
            &descriptor.interface,
            &descriptor.boundary_sample,
        );

        Ok(Self {
            descriptor,
            handle,
            fingerprint,
        })
    }

    /// Accesses the underlying device metadata descriptor.
    pub fn descriptor(&self) -> &DeviceDescriptor {
        &self.descriptor
    }

    /// Queries the hardware health diagnostic report (§23).
    pub fn health(&self) -> Result<DeviceHealth, IoError> {
        query_device_health(&self.descriptor)
    }
}

impl ReadOnlyBlockSource for WritablePhysicalDrive {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        self.handle.read_blocks(lba, count, self.descriptor.logical_block_size)
    }

    fn total_blocks(&self) -> u64 {
        if self.descriptor.logical_block_size == 0 {
            0
        } else {
            self.descriptor.capacity_bytes / (self.descriptor.logical_block_size as u64)
        }
    }

    fn block_size(&self) -> u32 {
        self.descriptor.logical_block_size
    }

    fn media_type(&self) -> MediaType {
        self.descriptor.media_type
    }

    fn is_write_blocked(&self) -> bool {
        self.descriptor.is_write_blocked
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        self.descriptor.write_blocker_info.clone()
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.fingerprint.clone()
    }
}

impl WritableBlockSource for WritablePhysicalDrive {
    fn write_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), IoError> {
        self.handle.write_blocks(lba, data, self.descriptor.logical_block_size)
    }

    fn supported_sanitize_methods(&self) -> Vec<SanitizeMethod> {
        match self.descriptor.media_type {
            MediaType::Nvme => vec![
                SanitizeMethod::NvmeSanitizeBlock,
                SanitizeMethod::NvmeSanitizeCrypto,
                SanitizeMethod::NvmeFormat,
                SanitizeMethod::HostOverwriteSinglePass,
            ],
            MediaType::SataSsd => vec![
                SanitizeMethod::AtaEnhancedSecureErase,
                SanitizeMethod::AtaSecureErase,
                SanitizeMethod::HostOverwriteSinglePass,
            ],
            MediaType::Hdd => vec![
                SanitizeMethod::HostOverwriteSinglePass,
                SanitizeMethod::HostOverwriteMultiPass { passes: 3 },
                SanitizeMethod::AtaSecureErase,
            ],
            MediaType::Sed => vec![
                SanitizeMethod::CryptographicErase,
                SanitizeMethod::HostOverwriteSinglePass,
            ],
            MediaType::Usb | MediaType::SdCard => vec![
                SanitizeMethod::HostOverwriteSinglePass,
                SanitizeMethod::HostOverwriteMultiPass { passes: 3 },
            ],
            MediaType::ForensicImage => vec![],
        }
    }

    fn issue_sanitize(&mut self, method: SanitizeMethod) -> Result<(), IoError> {
        match method {
            SanitizeMethod::HostOverwriteSinglePass => {
                let total = self.total_blocks();
                let b_size = self.block_size() as usize;
                let chunk_blocks = 2048u32;
                let zeroes = vec![0u8; chunk_blocks as usize * b_size];

                let mut current_lba = 0u64;
                while current_lba < total {
                    let count = chunk_blocks.min((total - current_lba) as u32);
                    let slice = &zeroes[..(count as usize * b_size)];
                    self.write_blocks(current_lba, slice)?;
                    current_lba += count as u64;
                }
                Ok(())
            }
            _ => Err(IoError::UnsupportedOperation {
                operation: format!("issue_sanitize({:?})", method),
                reason: "Hardware protocol command execution will be integrated in Module 1 sanitization engine (Conversation 6)".to_string(),
            }),
        }
    }
}
