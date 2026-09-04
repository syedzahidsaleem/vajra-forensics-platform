//! Mock Writable Block Source for Safe Offline Testing (§16, §45).
//!
//! Provides an in-memory simulated `WritableBlockSource` implementing all block I/O
//! and hardware sanitize commands for testing without touching physical disks.

use vajra_core::error::IoError;
use vajra_core::fingerprint::DeviceFingerprint;
use vajra_core::media_type::MediaType;
use vajra_core::sanitize::SanitizeMethod;
use vajra_core::traits::{ReadOnlyBlockSource, WritableBlockSource};
use vajra_core::write_blocker::WriteBlockerMetadata;

/// In-memory mock storage device implementing `WritableBlockSource` for automated tests.
pub struct MockWritableDevice {
    pub buffer: Vec<u8>,
    pub block_size: u32,
    pub media_type: MediaType,
    pub is_write_blocked: bool,
    pub write_blocker_info: Option<WriteBlockerMetadata>,
    pub supported_methods: Vec<SanitizeMethod>,
    pub write_log: Vec<(u64, usize)>, // (lba, length)
    pub sanitize_log: Vec<SanitizeMethod>,
    pub simulate_command_failure: bool,
    pub simulate_disconnect: bool,
}

impl MockWritableDevice {
    /// Creates a new in-memory mock device with specified sector count and block size.
    pub fn new(total_blocks: u64, block_size: u32, media_type: MediaType) -> Self {
        let total_bytes = (total_blocks as usize) * (block_size as usize);
        Self {
            buffer: vec![0u8; total_bytes],
            block_size,
            media_type,
            is_write_blocked: false,
            write_blocker_info: None,
            supported_methods: vec![
                SanitizeMethod::HostOverwriteSinglePass,
                SanitizeMethod::HostOverwriteMultiPass { passes: 3 },
                SanitizeMethod::NvmeSanitizeBlock,
                SanitizeMethod::CryptographicErase,
            ],
            write_log: Vec::new(),
            sanitize_log: Vec::new(),
            simulate_command_failure: false,
            simulate_disconnect: false,
        }
    }

    /// Populates data starting at given LBA for forensic carving tests.
    pub fn populate_data(&mut self, lba: u64, data: &[u8]) {
        let offset = (lba as usize) * (self.block_size as usize);
        if offset + data.len() <= self.buffer.len() {
            self.buffer[offset..offset + data.len()].copy_from_slice(data);
        }
    }
}

impl ReadOnlyBlockSource for MockWritableDevice {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        if self.simulate_disconnect {
            return Err(IoError::DeviceDisconnected {
                device_id: "mock_device".to_string(),
            });
        }

        let start = (lba as usize) * (self.block_size as usize);
        let len = (count as usize) * (self.block_size as usize);
        if start + len > self.buffer.len() {
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: "Requested blocks extend past device capacity".to_string(),
            });
        }

        Ok(self.buffer[start..start + len].to_vec())
    }

    fn total_blocks(&self) -> u64 {
        (self.buffer.len() / self.block_size as usize) as u64
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn media_type(&self) -> MediaType {
        self.media_type
    }

    fn is_write_blocked(&self) -> bool {
        self.is_write_blocked
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        self.write_blocker_info.clone()
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        DeviceFingerprint::compute(
            "MockVendor",
            "MockModel",
            "MOCK-SN-998877",
            self.buffer.len() as u64,
            "MockInterface",
            &self.buffer[..512.min(self.buffer.len())],
        )
    }
}

impl WritableBlockSource for MockWritableDevice {
    fn write_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), IoError> {
        if self.simulate_disconnect {
            return Err(IoError::DeviceDisconnected {
                device_id: "mock_device".to_string(),
            });
        }
        if self.is_write_blocked {
            return Err(IoError::PermissionDenied {
                details: "Device is write blocked".to_string(),
            });
        }

        let start = (lba as usize) * (self.block_size as usize);
        if start + data.len() > self.buffer.len() {
            return Err(IoError::WriteFailureAtLba {
                lba,
                count: (data.len() / self.block_size as usize) as u32,
                details: "Write extends past device capacity".to_string(),
            });
        }

        self.buffer[start..start + data.len()].copy_from_slice(data);
        self.write_log.push((lba, data.len()));
        Ok(())
    }

    fn supported_sanitize_methods(&self) -> Vec<SanitizeMethod> {
        self.supported_methods.clone()
    }

    fn issue_sanitize(&mut self, method: SanitizeMethod) -> Result<(), IoError> {
        if self.simulate_disconnect {
            return Err(IoError::DeviceDisconnected {
                device_id: "mock_device".to_string(),
            });
        }
        if self.simulate_command_failure {
            return Err(IoError::Other(format!("Hardware command {:?} failed", method)));
        }

        self.sanitize_log.push(method);
        // Simulate hardware sanitize by zeroing the entire buffer
        self.buffer.fill(0x00);
        Ok(())
    }
}
