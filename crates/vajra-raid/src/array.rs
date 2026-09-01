//! Core RaidArray struct implementing ReadOnlyBlockSource (§15 Part III, §16).

use crate::error::RaidError;
use crate::galois::GaloisField;
use crate::layout::{DiskBlockLocation, ParityLayout, RaidGeometry, RaidLevel};
use crate::superblock::detect_mdadm_superblock;
use sha2::{Digest, Sha256};
use vajra_core::error::IoError;
use vajra_core::fingerprint::DeviceFingerprint;
use vajra_core::media_type::MediaType;
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_core::write_blocker::WriteBlockerMetadata;

/// A software RAID array exposing an assembled multi-disk volume as a single `ReadOnlyBlockSource` (§16).
pub struct RaidArray {
    members: Vec<Option<Box<dyn ReadOnlyBlockSource>>>,
    geometry: RaidGeometry,
    galois: GaloisField,
    total_logical_blocks: u64,
    fingerprint: DeviceFingerprint,
}

impl RaidArray {
    /// Constructs a RaidArray from an explicit geometry and a list of member block sources.
    /// Missing or failed members can be supplied as `None` for degraded mode.
    pub fn new(
        geometry: RaidGeometry,
        members: Vec<Option<Box<dyn ReadOnlyBlockSource>>>,
    ) -> Result<Self, RaidError> {
        if members.len() != geometry.num_members {
            return Err(RaidError::MemberCountMismatch {
                expected: geometry.num_members,
                found: members.len(),
            });
        }

        let missing_count = members.iter().filter(|m| m.is_none()).count();
        match geometry.level {
            RaidLevel::Raid0 => {
                if missing_count > 0 {
                    return Err(RaidError::InsufficientMembers {
                        level: "RAID 0".to_string(),
                        surviving: geometry.num_members - missing_count,
                        total: geometry.num_members,
                    });
                }
            }
            RaidLevel::Raid5 => {
                if missing_count > 1 {
                    return Err(RaidError::InsufficientMembers {
                        level: "RAID 5".to_string(),
                        surviving: geometry.num_members - missing_count,
                        total: geometry.num_members,
                    });
                }
            }
            RaidLevel::Raid6 => {
                if missing_count > 2 {
                    return Err(RaidError::InsufficientMembers {
                        level: "RAID 6".to_string(),
                        surviving: geometry.num_members - missing_count,
                        total: geometry.num_members,
                    });
                }
            }
        }

        let total_logical_blocks = geometry.total_logical_sectors();

        // Derive deterministic fingerprint from geometry and surviving members
        let mut hasher = Sha256::new();
        hasher.update(format!("RAID:{:?}:{}:{}", geometry.level, geometry.num_members, geometry.chunk_size_bytes).as_bytes());
        for (i, m) in members.iter().enumerate() {
            if let Some(ref drive) = m {
                let fp = drive.device_fingerprint();
                hasher.update(format!("{}:{}", i, fp.sha256_hash).as_bytes());
            } else {
                hasher.update(format!("{}:MISSING", i).as_bytes());
            }
        }
        let hash_hex = hex::encode(hasher.finalize());

        let fingerprint = DeviceFingerprint {
            manufacturer: "Vajra Software RAID".to_string(),
            model: format!("Virtual {}", geometry.level),
            serial: format!("RAID-{}-{}", geometry.level, &hash_hex[..8].to_uppercase()),
            capacity_bytes: total_logical_blocks * (geometry.sector_size as u64),
            sha256_hash: hash_hex,
            interface: "RAID-Virtual".to_string(),
        };

        Ok(Self {
            members,
            geometry,
            galois: GaloisField::new(),
            total_logical_blocks,
            fingerprint,
        })
    }

    /// Automatically detects array parameters and member ordering from mdadm superblocks.
    pub fn auto_detect(mut candidate_members: Vec<Box<dyn ReadOnlyBlockSource>>) -> Result<Self, RaidError> {
        if candidate_members.is_empty() {
            return Err(RaidError::SuperblockNotFound);
        }

        let mut detected_sbs = Vec::new();
        for (i, m) in candidate_members.iter_mut().enumerate() {
            if let Ok(sb) = detect_mdadm_superblock(m.as_mut()) {
                detected_sbs.push((i, sb));
            }
        }

        if detected_sbs.is_empty() {
            return Err(RaidError::SuperblockNotFound);
        }

        let primary_sb = detected_sbs[0].1.clone();
        let total_raid_disks = primary_sb.raid_disks as usize;
        let sector_size = candidate_members[0].block_size();
        let member_capacity = candidate_members[0].total_blocks();

        let geometry = primary_sb.to_geometry(sector_size, member_capacity)?;
        let mut ordered_members: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = (0..total_raid_disks).map(|_| None).collect();

        // Place candidates into their detected dev_number slots
        let mut used_candidates = vec![false; candidate_members.len()];
        for (cand_idx, sb) in &detected_sbs {
            let slot = sb.dev_number as usize;
            if slot < total_raid_disks && sb.set_uuid == primary_sb.set_uuid {
                used_candidates[*cand_idx] = true;
            }
        }

        let mut candidate_iter = candidate_members.into_iter();
        for (cand_idx, is_used) in used_candidates.into_iter().enumerate() {
            let member = candidate_iter.next().unwrap();
            if is_used {
                let slot = detected_sbs.iter().find(|(idx, _)| *idx == cand_idx).unwrap().1.dev_number as usize;
                if slot < total_raid_disks {
                    ordered_members[slot] = Some(member);
                }
            }
        }

        Self::new(geometry, ordered_members)
    }

    pub fn geometry(&self) -> &RaidGeometry {
        &self.geometry
    }

    pub fn is_degraded(&self) -> bool {
        self.members.iter().any(|m| m.is_none())
    }

    pub fn missing_member_indices(&self) -> Vec<usize> {
        self.members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| if m.is_none() { Some(i) } else { None })
            .collect()
    }

    /// Reconstructs a single block on-the-fly for degraded reads.
    fn reconstruct_block(&mut self, loc: &DiskBlockLocation, count: u32) -> Result<Vec<u8>, IoError> {
        let block_bytes = (count * self.geometry.sector_size) as usize;
        let chunk_sec = self.geometry.chunk_size_sectors();

        match self.geometry.level {
            RaidLevel::Raid0 => Err(IoError::ReadFailureAtLba {
                lba: loc.member_lba,
                count,
                details: "RAID 0 member missing: array unrecoverable".to_string(),
            }),
            RaidLevel::Raid5 => {
                let mut reconstructed = vec![0u8; block_bytes];
                let n = self.geometry.num_members;

                for disk_idx in 0..n {
                    if disk_idx == loc.member_idx {
                        continue;
                    }
                    if let Some(ref mut member) = self.members[disk_idx] {
                        let member_lba = self.geometry.data_offset_sectors + (loc.stripe_row * chunk_sec) + loc.offset_in_chunk;
                        let block_data = member.read_blocks(member_lba, count)?;
                        for (r_b, &d_b) in reconstructed.iter_mut().zip(block_data.iter()) {
                            *r_b ^= d_b;
                        }
                    } else {
                        return Err(IoError::ReadFailureAtLba {
                            lba: loc.member_lba,
                            count,
                            details: "Multiple drive failures in RAID 5: array unrecoverable".to_string(),
                        });
                    }
                }
                Ok(reconstructed)
            }
            RaidLevel::Raid6 => {
                self.reconstruct_raid6_block(loc, count)
            }
        }
    }

    fn reconstruct_raid6_block(&mut self, loc: &DiskBlockLocation, count: u32) -> Result<Vec<u8>, IoError> {
        let block_bytes = (count * self.geometry.sector_size) as usize;
        let chunk_sec = self.geometry.chunk_size_sectors();
        let n = self.geometry.num_members;
        let stripe_row = loc.stripe_row as usize;

        let p_idx = self.geometry.parity_p_index(stripe_row);
        let q_idx = self.geometry.parity_q_index(stripe_row);

        let missing: Vec<usize> = (0..n).filter(|&i| self.members[i].is_none()).collect();

        if missing.len() == 1 {
            // Single failure: use P if surviving, or Q if P is failed
            if missing[0] != p_idx && self.members[p_idx].is_some() {
                // Reconstruct with XOR (P parity)
                let mut reconstructed = vec![0u8; block_bytes];
                for disk_idx in 0..n {
                    if disk_idx == loc.member_idx || disk_idx == q_idx {
                        continue;
                    }
                    if let Some(ref mut member) = self.members[disk_idx] {
                        let member_lba = self.geometry.data_offset_sectors + (loc.stripe_row * chunk_sec) + loc.offset_in_chunk;
                        let block_data = member.read_blocks(member_lba, count)?;
                        for (r_b, &d_b) in reconstructed.iter_mut().zip(block_data.iter()) {
                            *r_b ^= d_b;
                        }
                    }
                }
                return Ok(reconstructed);
            }
        }

        // Dual failure or missing P: read all surviving blocks
        let mut surviving_blocks: Vec<(usize, Vec<u8>)> = Vec::new();
        for disk_idx in 0..n {
            if let Some(ref mut member) = self.members[disk_idx] {
                let member_lba = self.geometry.data_offset_sectors + (loc.stripe_row * chunk_sec) + loc.offset_in_chunk;
                let data = member.read_blocks(member_lba, count)?;
                surviving_blocks.push((disk_idx, data));
            }
        }

        // Map data disk relative indexes 0..(n-2)
        let mut data_disk_indices = Vec::new();
        for col in 0..(n - 2) {
            let d_idx = match self.geometry.layout {
                ParityLayout::LeftSymmetric | ParityLayout::RightSymmetric => (q_idx + 1 + col) % n,
                _ => {
                    let mut idx = col;
                    if idx >= p_idx.min(q_idx) { idx += 1; }
                    if idx >= p_idx.max(q_idx) { idx += 1; }
                    idx % n
                }
            };
            data_disk_indices.push(d_idx);
        }

        let p_block = surviving_blocks.iter().find(|(idx, _)| *idx == p_idx).map(|(_, b)| b.as_slice());
        let q_block = surviving_blocks.iter().find(|(idx, _)| *idx == q_idx).map(|(_, b)| b.as_slice());

        let target_col = loc.data_col;

        if missing.contains(&p_idx) && !missing.contains(&q_idx) {
            // P is missing, Q is intact: use reconstruct_with_q
            let intact_data: Vec<(usize, &[u8])> = data_disk_indices
                .iter()
                .enumerate()
                .filter(|(_, &d_idx)| d_idx != loc.member_idx && self.members[d_idx].is_some())
                .map(|(col_idx, &d_idx)| {
                    let blk = surviving_blocks.iter().find(|(i, _)| *i == d_idx).unwrap().1.as_slice();
                    (col_idx, blk)
                })
                .collect();

            let mut out = vec![0u8; block_bytes];
            self.galois.reconstruct_with_q(&intact_data, q_block.unwrap(), target_col, &mut out);
            return Ok(out);
        }

        if !missing.contains(&p_idx) && missing.contains(&q_idx) {
            // Q is missing, P is intact: reconstruct using P parity (simple XOR)
            let intact_data: Vec<(usize, &[u8])> = data_disk_indices
                .iter()
                .enumerate()
                .filter(|(_, &d_idx)| d_idx != loc.member_idx && self.members[d_idx].is_some())
                .map(|(col_idx, &d_idx)| {
                    let blk = surviving_blocks.iter().find(|(i, _)| *i == d_idx).unwrap().1.as_slice();
                    (col_idx, blk)
                })
                .collect();

            let mut out = vec![0u8; block_bytes];
            self.galois.reconstruct_with_p(&intact_data, p_block.unwrap(), &mut out);
            return Ok(out);
        }

        if !missing.contains(&p_idx) && !missing.contains(&q_idx) {
            // Both P and Q are intact, but two data disks are missing
            let missing_data_cols: Vec<usize> = data_disk_indices
                .iter()
                .enumerate()
                .filter(|(_, &d_idx)| self.members[d_idx].is_none())
                .map(|(col_idx, _)| col_idx)
                .collect();

            if missing_data_cols.len() == 2 {
                let col_x = missing_data_cols[0];
                let col_y = missing_data_cols[1];

                let intact_data: Vec<(usize, &[u8])> = data_disk_indices
                    .iter()
                    .enumerate()
                    .filter(|(_, &d_idx)| self.members[d_idx].is_some())
                    .map(|(col_idx, &d_idx)| {
                        let blk = surviving_blocks.iter().find(|(i, _)| *i == d_idx).unwrap().1.as_slice();
                        (col_idx, blk)
                    })
                    .collect();

                let mut out_x = vec![0u8; block_bytes];
                let mut out_y = vec![0u8; block_bytes];

                self.galois.reconstruct_2_data(
                    &intact_data,
                    p_block.unwrap(),
                    q_block.unwrap(),
                    col_x,
                    col_y,
                    &mut out_x,
                    &mut out_y,
                );

                if target_col == col_x {
                    return Ok(out_x);
                } else {
                    return Ok(out_y);
                }
            }
        }

        Err(IoError::ReadFailureAtLba {
            lba: loc.member_lba,
            count,
            details: "Unrecoverable multi-drive failure in RAID 6 stripe".to_string(),
        })
    }
}

impl ReadOnlyBlockSource for RaidArray {
    fn read_blocks(&mut self, start_lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        if start_lba + (count as u64) > self.total_logical_blocks {
            return Err(IoError::ReadFailureAtLba {
                lba: start_lba,
                count,
                details: format!(
                    "Read out of bounds: LBA {}..{} exceeds total logical blocks {}",
                    start_lba,
                    start_lba + (count as u64),
                    self.total_logical_blocks
                ),
            });
        }

        let mut result = Vec::with_capacity((count as usize) * (self.geometry.sector_size as usize));
        let mut cur_lba = start_lba;
        let mut remaining = count;

        let chunk_sec = self.geometry.chunk_size_sectors();

        while remaining > 0 {
            let loc = self.geometry.map_lba(cur_lba);
            let sectors_to_chunk_end = (chunk_sec - loc.offset_in_chunk) as u32;
            let take_sectors = remaining.min(sectors_to_chunk_end);

            let chunk_data = if let Some(ref mut member) = self.members[loc.member_idx] {
                member.read_blocks(loc.member_lba, take_sectors)?
            } else {
                self.reconstruct_block(&loc, take_sectors)?
            };

            result.extend_from_slice(&chunk_data);
            cur_lba += take_sectors as u64;
            remaining -= take_sectors;
        }

        Ok(result)
    }

    fn total_blocks(&self) -> u64 {
        self.total_logical_blocks
    }

    fn block_size(&self) -> u32 {
        self.geometry.sector_size
    }

    fn media_type(&self) -> MediaType {
        MediaType::ForensicImage // RAID array virtual storage device
    }

    fn is_write_blocked(&self) -> bool {
        true // Strictly read-only block source per §16
    }

    fn write_blocker_info(&self) -> Option<WriteBlockerMetadata> {
        None
    }

    fn device_fingerprint(&self) -> DeviceFingerprint {
        self.fingerprint.clone()
    }
}
