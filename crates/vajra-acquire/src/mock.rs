//! Simulated Faulty Block Source for safe bad-sector unit/integration testing (§20).
//!
//! In compliance with the project's standing safety invariant, no destructive or fault-injection
//! operations are ever run against physical disks. This module provides a test-only
//! [`ReadOnlyBlockSource`] wrapper that deterministically injects controller errors, transient
//! retryable faults, and oversized-block read failures.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vajra_core::{DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, WriteBlockerMetadata};

/// Simulated failure mode for specific LBA ranges.
#[derive(Debug, Clone)]
pub enum InjectedFault {
    /// LBA range always fails with a hard read error.
    PermanentBadSector { reason: String },

    /// LBA range fails `fail_count` times before succeeding.
    TransientFailure {
        fail_count: u32,
        current_attempts: Arc<Mutex<u32>>,
    },

    /// LBA range fails if requested block `count > max_allowed_blocks`.
    /// Used to test the §20 flowchart rule that splits large chunks into single sectors.
    FailAboveBlockSize { max_allowed_blocks: u32 },
}

/// In-memory mock block device with configurable fault injection.
pub struct SimulatedFaultyBlockSource {
    backing_data: Vec<u8>,
    block_size: u32,
    total_blocks: u64,
    faults: Vec<(u64, u64, InjectedFault)>, // (start_lba, end_lba, fault)
    lba_read_counts: Arc<Mutex<HashMap<u64, u32>>>,
    fingerprint: DeviceFingerprint,
}

impl SimulatedFaultyBlockSource {
    /// Creates a simulated device backed by the provided byte buffer.
    pub fn new(backing_data: Vec<u8>, block_size: u32) -> Self {
        let total_blocks = (backing_data.len() as u64).div_ceil(block_size as u64);

        let fingerprint = DeviceFingerprint::compute(
            "Vajra Simulation Lab",
            "Faulty Mock Disk 1000",
            "MOCK-SIM-9999",
            backing_data.len() as u64,
            "Virtual RAM Bus",
            if backing_data.is_empty() {
                &[]
            } else {
                &backing_data[..block_size.min(backing_data.len() as u32) as usize]
            },
        );

        Self {
            backing_data,
            block_size,
            total_blocks,
            faults: Vec::new(),
            lba_read_counts: Arc::new(Mutex::new(HashMap::new())),
            fingerprint,
        }
    }

    /// Inject a permanent read failure across the LBA range `[start_lba ..= end_lba]`.
    pub fn inject_permanent_bad_sector(&mut self, start_lba: u64, end_lba: u64, reason: &str) {
        self.faults.push((
            start_lba,
            end_lba,
            InjectedFault::PermanentBadSector {
                reason: reason.to_string(),
            },
        ));
    }

    /// Inject a transient failure across `[start_lba ..= end_lba]` that fails `fail_count` times before succeeding.
    pub fn inject_transient_failure(&mut self, start_lba: u64, end_lba: u64, fail_count: u32) {
        self.faults.push((
            start_lba,
            end_lba,
            InjectedFault::TransientFailure {
                fail_count,
                current_attempts: Arc::new(Mutex::new(0)),
            },
        ));
    }

    /// Inject a failure that occurs when read count exceeds `max_blocks`.
    pub fn inject_fail_above_block_size(&mut self, start_lba: u64, end_lba: u64, max_blocks: u32) {
        self.faults.push((
            start_lba,
            end_lba,
            InjectedFault::FailAboveBlockSize { max_allowed_blocks: max_blocks },
        ));
    }

    /// Returns the number of times a specific LBA was attempted to be read.
    pub fn read_attempts_for_lba(&self, lba: u64) -> u32 {
        let counts = self.lba_read_counts.lock().unwrap();
        counts.get(&lba).copied().unwrap_or(0)
    }
}

impl ReadOnlyBlockSource for SimulatedFaultyBlockSource {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        let end_lba = lba + count as u64 - 1;

        // Record attempt counts
        {
            let mut counts = self.lba_read_counts.lock().unwrap();
            for cur_lba in lba..=end_lba {
                *counts.entry(cur_lba).or_insert(0) += 1;
            }
        }

        // Check for injected faults
        for (f_start, f_end, fault) in &self.faults {
            let overlaps = lba <= *f_end && end_lba >= *f_start;
            if overlaps {
                match fault {
                    InjectedFault::PermanentBadSector { reason } => {
                        return Err(IoError::ReadFailureAtLba {
                            lba,
                            count,
                            details: format!("Simulated CRC/UNC Bad Sector: {}", reason),
                        });
                    }
                    InjectedFault::TransientFailure {
                        fail_count,
                        current_attempts,
                    } => {
                        let mut attempts = current_attempts.lock().unwrap();
                        if *attempts < *fail_count {
                            *attempts += 1;
                            return Err(IoError::ReadFailureAtLba {
                                lba,
                                count,
                                details: format!(
                                    "Simulated Transient Error (attempt {} of {})",
                                    *attempts, fail_count
                                ),
                            });
                        }
                    }
                    InjectedFault::FailAboveBlockSize { max_allowed_blocks } => {
                        if count > *max_allowed_blocks {
                            return Err(IoError::ReadFailureAtLba {
                                lba,
                                count,
                                details: format!(
                                    "Simulated Controller Timeout on large read: count {} > max {}",
                                    count, max_allowed_blocks
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Clean read from backing buffer
        let bsize = self.block_size as usize;
        let start_offset = lba as usize * bsize;
        let total_bytes = count as usize * bsize;
        let end_offset = start_offset + total_bytes;

        if start_offset >= self.backing_data.len() {
            return Ok(vec![0u8; total_bytes]);
        }

        let mut buf = vec![0u8; total_bytes];
        let available_end = end_offset.min(self.backing_data.len());
        if available_end > start_offset {
            let slice = &self.backing_data[start_offset..available_end];
            buf[..slice.len()].copy_from_slice(slice);
        }

        Ok(buf)
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn media_type(&self) -> MediaType {
        MediaType::ForensicImage
    }

    fn is_write_blocked(&self) -> bool {
        true
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        None
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.fingerprint.clone()
    }
}
