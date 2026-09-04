//! Platform-specific OS device layer abstraction.

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as imp;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as imp;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub mod stub {
    use crate::descriptor::DeviceDescriptor;
    use crate::health::DeviceHealth;
    use std::path::Path;
    use vajra_core::{IoError, MediaType};

    pub fn enumerate_devices() -> Result<Vec<DeviceDescriptor>, IoError> {
        Err(IoError::UnsupportedOperation {
            operation: "enumerate_devices".to_string(),
            reason: "Platform not supported in this build".to_string(),
        })
    }

    pub fn query_device_health(_desc: &DeviceDescriptor) -> Result<DeviceHealth, IoError> {
        Err(IoError::UnsupportedOperation {
            operation: "query_device_health".to_string(),
            reason: "Platform not supported in this build".to_string(),
        })
    }

    pub struct OsDriveHandle;

    impl OsDriveHandle {
        pub fn open_readonly(_path: &Path) -> Result<Self, IoError> {
            Err(IoError::UnsupportedOperation {
                operation: "open_readonly".to_string(),
                reason: "Platform not supported in this build".to_string(),
            })
        }

        pub fn open_writable(_path: &Path) -> Result<Self, IoError> {
            Err(IoError::UnsupportedOperation {
                operation: "open_writable".to_string(),
                reason: "Platform not supported in this build".to_string(),
            })
        }

        pub fn read_blocks(&mut self, _lba: u64, _count: u32, _block_size: u32) -> Result<Vec<u8>, IoError> {
            Err(IoError::UnsupportedOperation {
                operation: "read_blocks".to_string(),
                reason: "Platform not supported in this build".to_string(),
            })
        }

        pub fn write_blocks(&mut self, _lba: u64, _data: &[u8], _block_size: u32) -> Result<(), IoError> {
            Err(IoError::UnsupportedOperation {
                operation: "write_blocks".to_string(),
                reason: "Platform not supported in this build".to_string(),
            })
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub use stub as imp;
