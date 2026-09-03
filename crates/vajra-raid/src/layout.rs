//! RAID Array Geometry and Stripe Mapping Engine (§15 Part III, §16).

use crate::error::RaidError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaidLevel {
    Raid0,
    Raid5,
    Raid6,
}

impl std::fmt::Display for RaidLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaidLevel::Raid0 => write!(f, "RAID 0 (Striping)"),
            RaidLevel::Raid5 => write!(f, "RAID 5 (Single XOR Parity)"),
            RaidLevel::Raid6 => write!(f, "RAID 6 (Dual Parity Reed-Solomon)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParityLayout {
    LeftSymmetric,
    LeftAsymmetric,
    RightSymmetric,
    RightAsymmetric,
}

impl Default for ParityLayout {
    fn default() -> Self {
        ParityLayout::LeftSymmetric
    }
}

/// RAID Array Geometry parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaidGeometry {
    pub level: RaidLevel,
    pub layout: ParityLayout,
    pub num_members: usize,
    pub chunk_size_bytes: u32,
    pub sector_size: u32,
    pub data_offset_sectors: u64,
    pub member_capacity_sectors: u64,
}

impl RaidGeometry {
    pub fn new(
        level: RaidLevel,
        layout: ParityLayout,
        num_members: usize,
        chunk_size_bytes: u32,
        sector_size: u32,
        data_offset_sectors: u64,
        member_capacity_sectors: u64,
    ) -> Result<Self, RaidError> {
        if chunk_size_bytes == 0 || (chunk_size_bytes & (chunk_size_bytes - 1)) != 0 {
            return Err(RaidError::InvalidChunkSize(chunk_size_bytes));
        }
        if sector_size == 0 || chunk_size_bytes % sector_size != 0 {
            return Err(RaidError::InvalidGeometry(format!(
                "Chunk size {} must be multiple of sector size {}",
                chunk_size_bytes, sector_size
            )));
        }

        let min_members = match level {
            RaidLevel::Raid0 => 2,
            RaidLevel::Raid5 => 3,
            RaidLevel::Raid6 => 4,
        };

        if num_members < min_members {
            return Err(RaidError::InvalidGeometry(format!(
                "{level} requires at least {min_members} member drives, got {num_members}"
            )));
        }

        Ok(Self {
            level,
            layout,
            num_members,
            chunk_size_bytes,
            sector_size,
            data_offset_sectors,
            member_capacity_sectors,
        })
    }

    #[inline(always)]
    pub fn chunk_size_sectors(&self) -> u64 {
        (self.chunk_size_bytes / self.sector_size) as u64
    }

    /// Total data disks per stripe row.
    #[inline(always)]
    pub fn data_disks_per_stripe(&self) -> usize {
        match self.level {
            RaidLevel::Raid0 => self.num_members,
            RaidLevel::Raid5 => self.num_members - 1,
            RaidLevel::Raid6 => self.num_members - 2,
        }
    }

    /// Total addressable logical capacity in sectors.
    pub fn total_logical_sectors(&self) -> u64 {
        let usable_member_sectors = self.member_capacity_sectors.saturating_sub(self.data_offset_sectors);
        let num_stripes_per_member = usable_member_sectors / self.chunk_size_sectors();
        num_stripes_per_member * self.chunk_size_sectors() * (self.data_disks_per_stripe() as u64)
    }

    /// Maps a logical array LBA to its physical member disk index and sector LBA on that disk.
    pub fn map_lba(&self, array_lba: u64) -> DiskBlockLocation {
        let chunk_sec = self.chunk_size_sectors();
        let chunk_idx = array_lba / chunk_sec;
        let offset_in_chunk = array_lba % chunk_sec;
        let data_disks = self.data_disks_per_stripe() as u64;

        let stripe_row = chunk_idx / data_disks;
        let data_col = (chunk_idx % data_disks) as usize;

        let member_idx = match self.level {
            RaidLevel::Raid0 => data_col,
            RaidLevel::Raid5 => self.map_raid5_member(stripe_row as usize, data_col),
            RaidLevel::Raid6 => self.map_raid6_member(stripe_row as usize, data_col),
        };

        let member_lba = self.data_offset_sectors + (stripe_row * chunk_sec) + offset_in_chunk;

        DiskBlockLocation {
            stripe_row,
            data_col,
            member_idx,
            member_lba,
            offset_in_chunk,
        }
    }

    /// Returns the parity disk index (P) for a given stripe row in RAID 5/6.
    pub fn parity_p_index(&self, stripe_row: usize) -> usize {
        let n = self.num_members;
        match self.level {
            RaidLevel::Raid0 => 0,
            RaidLevel::Raid5 => match self.layout {
                ParityLayout::LeftSymmetric | ParityLayout::LeftAsymmetric => {
                    (n - 1 - (stripe_row % n)) % n
                }
                ParityLayout::RightSymmetric | ParityLayout::RightAsymmetric => stripe_row % n,
            },
            RaidLevel::Raid6 => match self.layout {
                ParityLayout::LeftSymmetric | ParityLayout::LeftAsymmetric => {
                    let raw = (stripe_row % n) as isize;
                    let mut p = (n as isize) - 2 - raw;
                    while p < 0 {
                        p += n as isize;
                    }
                    (p as usize) % n
                }
                ParityLayout::RightSymmetric | ParityLayout::RightAsymmetric => stripe_row % n,
            },
        }
    }

    /// Returns the Q parity disk index for a given stripe row in RAID 6.
    pub fn parity_q_index(&self, stripe_row: usize) -> usize {
        let p = self.parity_p_index(stripe_row);
        (p + 1) % self.num_members
    }

    fn map_raid5_member(&self, stripe_row: usize, data_col: usize) -> usize {
        let n = self.num_members;
        let p = self.parity_p_index(stripe_row);

        match self.layout {
            ParityLayout::LeftSymmetric | ParityLayout::RightSymmetric => {
                (p + 1 + data_col) % n
            }
            ParityLayout::LeftAsymmetric | ParityLayout::RightAsymmetric => {
                if data_col < p {
                    data_col
                } else {
                    data_col + 1
                }
            }
        }
    }

    fn map_raid6_member(&self, stripe_row: usize, data_col: usize) -> usize {
        let n = self.num_members;
        let p = self.parity_p_index(stripe_row);
        let q = (p + 1) % n;

        match self.layout {
            ParityLayout::LeftSymmetric | ParityLayout::RightSymmetric => {
                (q + 1 + data_col) % n
            }
            ParityLayout::LeftAsymmetric | ParityLayout::RightAsymmetric => {
                let mut idx = data_col;
                if idx >= p.min(q) {
                    idx += 1;
                }
                if idx >= p.max(q) {
                    idx += 1;
                }
                idx % n
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskBlockLocation {
    pub stripe_row: u64,
    pub data_col: usize,
    pub member_idx: usize,
    pub member_lba: u64,
    pub offset_in_chunk: u64,
}
