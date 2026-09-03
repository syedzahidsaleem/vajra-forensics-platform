//! Local RAID Reconstruction Engine (`vajra-raid`).
//!
//! Reconstructs local degraded or healthy RAID 0 (striping), RAID 1 (mirroring),
//! and RAID 5 (parity striping) array configurations into a unified read-only block source (§15, §53).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use vajra_core::{
    DeviceFingerprint, IoError, MediaType, ReadOnlyBlockSource, WriteBlockerMetadata,
};

/// Supported software and hardware RAID configurations (local drives only, §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RaidLevel {
    /// RAID 0 — Block striping across N drives without parity.
    Raid0,
    /// RAID 1 — Block mirroring across N drives.
    Raid1,
    /// RAID 5 — Block striping with distributed rotating parity. Supports 1 missing drive.
    Raid5,
}

impl std::fmt::Display for RaidLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaidLevel::Raid0 => write!(f, "RAID 0 (Striping)"),
            RaidLevel::Raid1 => write!(f, "RAID 1 (Mirroring)"),
            RaidLevel::Raid5 => write!(f, "RAID 5 (Parity Striping)"),
        }
    }
}

/// Errors occurring during RAID array assembly and sector reconstruction.
#[derive(Debug, Error)]
pub enum RaidError {
    #[error("I/O error reading member block source: {0}")]
    Io(#[from] IoError),
    #[error("RAID configuration error: at least {required} member drives are required, found {found}")]
    InsufficientDrives { required: usize, found: usize },
    #[error("Incompatible drive geometries: block size or sector count mismatch")]
    IncompatibleDriveGeometries,
    #[error("Unrecoverable RAID failure: {0}")]
    Unrecoverable(String),
}

/// A unified, virtual `ReadOnlyBlockSource` representing a local RAID array (§15).
pub struct RaidArrayReader<S: ReadOnlyBlockSource> {
    level: RaidLevel,
    stripe_size_blocks: u32,
    /// Array of member drive slots. `None` represents a missing, offline, or failed member drive.
    members: Vec<Option<S>>,
    block_size: u32,
    member_blocks: u64,
}

impl<S: ReadOnlyBlockSource> RaidArrayReader<S> {
    /// Constructs a new local RAID array from member drives.
    ///
    /// For degraded arrays (e.g. RAID 5 with a missing drive), pass `None` for the missing slot.
    pub fn new(
        level: RaidLevel,
        stripe_size_blocks: u32,
        members: Vec<Option<S>>,
    ) -> Result<Self, RaidError> {
        let healthy_count = members.iter().filter(|m| m.is_some()).count();

        match level {
            RaidLevel::Raid0 => {
                if healthy_count < 2 || healthy_count != members.len() {
                    return Err(RaidError::InsufficientDrives {
                        required: members.len(),
                        found: healthy_count,
                    });
                }
            }
            RaidLevel::Raid1 => {
                if healthy_count < 1 {
                    return Err(RaidError::InsufficientDrives {
                        required: 1,
                        found: 0,
                    });
                }
            }
            RaidLevel::Raid5 => {
                if members.len() < 3 {
                    return Err(RaidError::InsufficientDrives {
                        required: 3,
                        found: members.len(),
                    });
                }
                if members.len() - healthy_count > 1 {
                    return Err(RaidError::Unrecoverable(format!(
                        "RAID 5 allows at most 1 missing drive, but {} drives are missing",
                        members.len() - healthy_count
                    )));
                }
            }
        }

        // Validate member block sizes and reference capacity
        let first_healthy = members
            .iter()
            .find_map(|m| m.as_ref())
            .ok_or(RaidError::InsufficientDrives {
                required: 1,
                found: 0,
            })?;

        let block_size = first_healthy.block_size();
        let member_blocks = first_healthy.total_blocks();

        for m in members.iter().flatten() {
            if m.block_size() != block_size {
                return Err(RaidError::IncompatibleDriveGeometries);
            }
        }

        Ok(Self {
            level,
            stripe_size_blocks: stripe_size_blocks.max(1),
            members,
            block_size,
            member_blocks,
        })
    }

    /// Returns the active RAID level configuration.
    pub fn raid_level(&self) -> RaidLevel {
        self.level
    }

    /// Returns whether the array is currently operating in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.members.iter().any(|m| m.is_none())
    }

    /// Reads a single block from a specific member drive slot, performing XOR reconstruction if missing.
    fn read_member_block(&mut self, slot_idx: usize, member_lba: u64) -> Result<Vec<u8>, IoError> {
        let num_members = self.members.len();

        if let Some(ref mut drive) = self.members[slot_idx] {
            drive.read_blocks(member_lba, 1)
        } else {
            // Degraded XOR recovery for RAID 5 missing drive
            if self.level != RaidLevel::Raid5 {
                return Err(IoError::ReadFailureAtLba {
                    lba: member_lba,
                    reason: format!("Member drive {} is missing in RAID array", slot_idx),
                });
            }

            let mut parity_buffer = vec![0u8; self.block_size as usize];

            for idx in 0..num_members {
                if idx == slot_idx {
                    continue;
                }

                let drive = self.members[idx].as_mut().ok_or_else(|| {
                    IoError::ReadFailureAtLba {
                        lba: member_lba,
                        reason: "Multiple missing drives in RAID 5".to_string(),
                    }
                })?;

                let chunk = drive.read_blocks(member_lba, 1)?;
                for (b, p) in chunk.iter().zip(parity_buffer.iter_mut()) {
                    *p ^= b;
                }
            }

            Ok(parity_buffer)
        }
    }
}

impl<S: ReadOnlyBlockSource> ReadOnlyBlockSource for RaidArrayReader<S> {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        let mut result = Vec::with_capacity((count * self.block_size) as usize);
        let num_members = self.members.len() as u64;

        for current_lba in lba..(lba + count as u64) {
            match self.level {
                RaidLevel::Raid0 => {
                    let stripe_unit = current_lba / self.stripe_size_blocks as u64;
                    let block_in_stripe = current_lba % self.stripe_size_blocks as u64;
                    let target_slot = (stripe_unit % num_members) as usize;
                    let member_lba =
                        ((stripe_unit / num_members) * self.stripe_size_blocks as u64)
                            + block_in_stripe;

                    let block = self.read_member_block(target_slot, member_lba)?;
                    result.extend_from_slice(&block);
                }
                RaidLevel::Raid1 => {
                    // Mirroring: Read from first available healthy slot
                    let healthy_slot = self
                        .members
                        .iter()
                        .position(|m| m.is_some())
                        .unwrap_or(0);
                    let block = self.read_member_block(healthy_slot, current_lba)?;
                    result.extend_from_slice(&block);
                }
                RaidLevel::Raid5 => {
                    // Left-symmetric RAID 5 mapping
                    let data_disks = num_members - 1;
                    let stripe_unit = current_lba / self.stripe_size_blocks as u64;
                    let block_in_stripe = current_lba % self.stripe_size_blocks as u64;
                    let stripe_row = stripe_unit / data_disks;

                    // Parity disk index for this stripe row rotates: (num_members - 1 - (stripe_row % num_members))
                    let parity_disk = ((num_members - 1
                        + num_members
                        - (stripe_row % num_members))
                        % num_members) as usize;

                    let data_disk_idx = (stripe_unit % data_disks) as usize;
                    let target_slot = if data_disk_idx >= parity_disk {
                        data_disk_idx + 1
                    } else {
                        data_disk_idx
                    };

                    let member_lba =
                        (stripe_row * self.stripe_size_blocks as u64) + block_in_stripe;
                    let block = self.read_member_block(target_slot, member_lba)?;
                    result.extend_from_slice(&block);
                }
            }
        }

        Ok(result)
    }

    fn total_blocks(&self) -> u64 {
        match self.level {
            RaidLevel::Raid0 => self.member_blocks * self.members.len() as u64,
            RaidLevel::Raid1 => self.member_blocks,
            RaidLevel::Raid5 => self.member_blocks * (self.members.len() as u64 - 1),
        }
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
        DeviceFingerprint::from_raw_fields(
            &format!("RaidArray-{}", self.level),
            "RAID015",
            self.total_blocks() * self.block_size as u64,
            &[0u8; 512],
            MediaType::ForensicImage,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDrive {
        data: Vec<u8>,
        block_size: u32,
    }

    impl ReadOnlyBlockSource for MockDrive {
        fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
            let start = (lba * self.block_size as u64) as usize;
            let len = (count * self.block_size) as usize;
            Ok(self.data[start..start + len].to_vec())
        }

        fn total_blocks(&self) -> u64 {
            (self.data.len() / self.block_size as usize) as u64
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
            DeviceFingerprint::from_raw_fields("Mock", "M", 1024, &[0u8; 512], MediaType::ForensicImage)
        }
    }

    #[test]
    fn test_raid0_striping() {
        let d1 = MockDrive { data: vec![1u8; 512], block_size: 512 };
        let d2 = MockDrive { data: vec![2u8; 512], block_size: 512 };

        let mut raid = RaidArrayReader::new(
            RaidLevel::Raid0,
            1,
            vec![Some(d1), Some(d2)],
        ).unwrap();

        assert_eq!(raid.total_blocks(), 2);
        let b1 = raid.read_blocks(0, 1).unwrap();
        assert_eq!(b1[0], 1);
        let b2 = raid.read_blocks(1, 1).unwrap();
        assert_eq!(b2[0], 2);
    }

    #[test]
    fn test_raid5_degraded_xor_reconstruction() {
        // Disk 0: Data A (0xAA)
        let d0 = MockDrive { data: vec![0xAAu8; 512], block_size: 512 };
        // Disk 1: Missing (None)
        // Disk 2: Parity P = 0xAA ^ 0xBB = 0x11
        let d2 = MockDrive { data: vec![0x11u8; 512], block_size: 512 };

        let mut raid5 = RaidArrayReader::new(
            RaidLevel::Raid5,
            1,
            vec![Some(d0), None, Some(d2)],
        ).unwrap();

        assert!(raid5.is_degraded());
        // Read block from missing disk 1 -> reconstructed via XOR -> 0xAA ^ 0x11 = 0xBB
        let reconstructed = raid5.read_blocks(1, 1).unwrap();
        assert_eq!(reconstructed[0], 0xBB);
    }
}
