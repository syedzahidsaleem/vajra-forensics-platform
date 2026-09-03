//! Integration tests for vajra-raid (§15 Part III, §16).
//!
//! Verifies byte-for-byte reconstruction of RAID 0, RAID 5, and RAID 6 arrays
//! under intact, single-degraded, and dual-degraded conditions.

use vajra_core::error::IoError;
use vajra_core::fingerprint::DeviceFingerprint;
use vajra_core::media_type::MediaType;
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_core::write_blocker::WriteBlockerMetadata;
use vajra_raid::galois::GaloisField;
use vajra_raid::layout::{ParityLayout, RaidGeometry, RaidLevel};
use vajra_raid::RaidArray;

/// In-memory mock block source for deterministic synthetic testing.
struct MockBlockSource {
    data: Vec<u8>,
    sector_size: u32,
    serial: String,
}

impl MockBlockSource {
    fn new(data: Vec<u8>, sector_size: u32, serial: &str) -> Self {
        Self {
            data,
            sector_size,
            serial: serial.to_string(),
        }
    }
}

impl ReadOnlyBlockSource for MockBlockSource {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError> {
        let offset = (lba as usize) * (self.sector_size as usize);
        let len = (count as usize) * (self.sector_size as usize);
        if offset + len > self.data.len() {
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: "Mock out of bounds".to_string(),
            });
        }
        Ok(self.data[offset..offset + len].to_vec())
    }

    fn total_blocks(&self) -> u64 {
        (self.data.len() as u64) / (self.sector_size as u64)
    }

    fn block_size(&self) -> u32 {
        self.sector_size
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
        DeviceFingerprint {
            manufacturer: "Mock".to_string(),
            model: "Mock Drive".to_string(),
            serial: self.serial.clone(),
            capacity_bytes: self.data.len() as u64,
            interface: "Mock".to_string(),
            sha256_hash: "00".to_string(),
        }
    }
}

#[test]
fn test_raid0_intact_reconstruction_and_boundary_reading() {
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize; // 8 sectors per chunk
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 3usize;
    let chunks_per_member = 10usize;

    let total_data_bytes = num_members * chunks_per_member * chunk_size_bytes;
    let mut ground_truth = vec![0u8; total_data_bytes];
    for (i, byte) in ground_truth.iter_mut().enumerate() {
        *byte = ((i * 31 + 7) % 256) as u8;
    }

    // Split ground truth into 3 member drives
    let mut member_buffers = vec![vec![0u8; chunks_per_member * chunk_size_bytes]; num_members];
    for chunk_idx in 0..(num_members * chunks_per_member) {
        let member_idx = chunk_idx % num_members;
        let member_chunk_idx = chunk_idx / num_members;
        let src_start = chunk_idx * chunk_size_bytes;
        let dst_start = member_chunk_idx * chunk_size_bytes;
        member_buffers[member_idx][dst_start..dst_start + chunk_size_bytes]
            .copy_from_slice(&ground_truth[src_start..src_start + chunk_size_bytes]);
    }

    let members: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = member_buffers
        .into_iter()
        .enumerate()
        .map(|(i, b)| Some(Box::new(MockBlockSource::new(b, sector_size as u32, &format!("DRIVE-{}", i))) as Box<dyn ReadOnlyBlockSource>))
        .collect();

    let geometry = RaidGeometry::new(
        RaidLevel::Raid0,
        ParityLayout::LeftSymmetric,
        num_members,
        chunk_size_bytes as u32,
        sector_size as u32,
        0,
        (chunks_per_member * chunk_sectors) as u64,
    ).unwrap();

    let mut raid = RaidArray::new(geometry, members).unwrap();

    // Read full array and compare byte-for-byte
    let total_sectors = raid.total_blocks();
    let read_back = raid.read_blocks(0, total_sectors as u32).unwrap();
    assert_eq!(read_back, ground_truth, "RAID 0 read-back must match ground truth exactly");

    // Test sub-chunk unaligned reads crossing chunk boundaries
    let unaligned_read = raid.read_blocks(7, 10).unwrap(); // Spans chunk 0 and chunk 1
    assert_eq!(
        unaligned_read,
        ground_truth[7 * 512..17 * 512],
        "Unaligned multi-chunk read must match ground truth"
    );
}

#[test]
fn test_raid5_intact_and_degraded_xor_reconstruction() {
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize;
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 4usize; // 3 data disks + 1 parity per stripe
    let num_stripes = 8usize;

    let data_disks = num_members - 1;
    let total_data_bytes = data_disks * num_stripes * chunk_size_bytes;
    let mut ground_truth = vec![0u8; total_data_bytes];
    for (i, byte) in ground_truth.iter_mut().enumerate() {
        *byte = ((i * 73 + 19) % 256) as u8;
    }

    // Allocate 4 member disk buffers
    let mut member_buffers = vec![vec![0u8; num_stripes * chunk_size_bytes]; num_members];

    let geometry = RaidGeometry::new(
        RaidLevel::Raid5,
        ParityLayout::LeftSymmetric,
        num_members,
        chunk_size_bytes as u32,
        sector_size as u32,
        0,
        (num_stripes * chunk_sectors) as u64,
    ).unwrap();

    for stripe in 0..num_stripes {
        let p_idx = geometry.parity_p_index(stripe);
        let mut parity_block = vec![0u8; chunk_size_bytes];

        for col in 0..data_disks {
            let data_disk_idx = (p_idx + 1 + col) % num_members;
            let gt_chunk_idx = stripe * data_disks + col;
            let gt_start = gt_chunk_idx * chunk_size_bytes;
            let chunk_slice = &ground_truth[gt_start..gt_start + chunk_size_bytes];

            let dst_start = stripe * chunk_size_bytes;
            member_buffers[data_disk_idx][dst_start..dst_start + chunk_size_bytes].copy_from_slice(chunk_slice);

            for (p_b, &d_b) in parity_block.iter_mut().zip(chunk_slice.iter()) {
                *p_b ^= d_b;
            }
        }

        let p_start = stripe * chunk_size_bytes;
        member_buffers[p_idx][p_start..p_start + chunk_size_bytes].copy_from_slice(&parity_block);
    }

    // 1. Test INTACT RAID 5
    let members_intact: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = member_buffers
        .iter()
        .enumerate()
        .map(|(i, b)| Some(Box::new(MockBlockSource::new(b.clone(), sector_size as u32, &format!("DRIVE-{}", i))) as Box<dyn ReadOnlyBlockSource>))
        .collect();

    let mut raid_intact = RaidArray::new(geometry.clone(), members_intact).unwrap();
    assert!(!raid_intact.is_degraded());
    let read_intact = raid_intact.read_blocks(0, raid_intact.total_blocks() as u32).unwrap();
    assert_eq!(read_intact, ground_truth, "Intact RAID 5 read-back must match ground truth");

    // 2. Test DEGRADED RAID 5 with Drive #1 failed/missing!
    let failed_drive_idx = 1;
    let mut members_degraded: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = Vec::new();
    for (i, b) in member_buffers.iter().enumerate() {
        if i == failed_drive_idx {
            members_degraded.push(None);
        } else {
            members_degraded.push(Some(Box::new(MockBlockSource::new(b.clone(), sector_size as u32, &format!("DRIVE-{}", i)))));
        }
    }

    let mut raid_degraded = RaidArray::new(geometry.clone(), members_degraded).unwrap();
    assert!(raid_degraded.is_degraded(), "RAID 5 with missing drive must report degraded");
    assert_eq!(raid_degraded.missing_member_indices(), vec![failed_drive_idx]);

    let read_degraded = raid_degraded.read_blocks(0, raid_degraded.total_blocks() as u32).unwrap();
    assert_eq!(
        read_degraded, ground_truth,
        "Degraded RAID 5 with Drive #1 missing must reconstruct identical ground truth on-the-fly via XOR!"
    );
}

#[test]
fn test_raid6_dual_parity_intact_and_dual_degraded_reconstruction() {
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize;
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 5usize; // 3 data disks + 2 parity (P + Q) per stripe
    let num_stripes = 6usize;
    let data_disks = num_members - 2;

    let total_data_bytes = data_disks * num_stripes * chunk_size_bytes;
    let mut ground_truth = vec![0u8; total_data_bytes];
    for (i, byte) in ground_truth.iter_mut().enumerate() {
        *byte = ((i * 127 + 53) % 256) as u8;
    }

    let galois = GaloisField::new();
    let mut member_buffers = vec![vec![0u8; num_stripes * chunk_size_bytes]; num_members];

    let geometry = RaidGeometry::new(
        RaidLevel::Raid6,
        ParityLayout::LeftSymmetric,
        num_members,
        chunk_size_bytes as u32,
        sector_size as u32,
        0,
        (num_stripes * chunk_sectors) as u64,
    ).unwrap();

    for stripe in 0..num_stripes {
        let p_idx = geometry.parity_p_index(stripe);
        let q_idx = geometry.parity_q_index(stripe);

        let mut data_chunks: Vec<&[u8]> = Vec::new();
        for col in 0..data_disks {
            let d_idx = (q_idx + 1 + col) % num_members;
            let gt_chunk_idx = stripe * data_disks + col;
            let gt_start = gt_chunk_idx * chunk_size_bytes;
            let chunk_slice = &ground_truth[gt_start..gt_start + chunk_size_bytes];

            let dst_start = stripe * chunk_size_bytes;
            member_buffers[d_idx][dst_start..dst_start + chunk_size_bytes].copy_from_slice(chunk_slice);
            data_chunks.push(chunk_slice);
        }

        let mut p_block = vec![0u8; chunk_size_bytes];
        let mut q_block = vec![0u8; chunk_size_bytes];

        galois.compute_p_parity(&data_chunks, &mut p_block);
        galois.compute_q_parity(&data_chunks, &mut q_block);

        let p_start = stripe * chunk_size_bytes;
        let q_start = stripe * chunk_size_bytes;
        member_buffers[p_idx][p_start..p_start + chunk_size_bytes].copy_from_slice(&p_block);
        member_buffers[q_idx][q_start..q_start + chunk_size_bytes].copy_from_slice(&q_block);
    }

    // 1. Test INTACT RAID 6
    let members_intact: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = member_buffers
        .iter()
        .enumerate()
        .map(|(i, b)| Some(Box::new(MockBlockSource::new(b.clone(), sector_size as u32, &format!("DRIVE-{}", i))) as Box<dyn ReadOnlyBlockSource>))
        .collect();

    let mut raid_intact = RaidArray::new(geometry.clone(), members_intact).unwrap();
    let read_intact = raid_intact.read_blocks(0, raid_intact.total_blocks() as u32).unwrap();
    assert_eq!(read_intact, ground_truth, "Intact RAID 6 read-back must match ground truth");

    // 2. Test DUAL DEGRADED RAID 6 with TWO DRIVES FAILED (Drive #0 and Drive #2 missing!)
    let failed_0 = 0;
    let failed_2 = 2;
    let mut members_dual_degraded: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = Vec::new();
    for (i, b) in member_buffers.iter().enumerate() {
        if i == failed_0 || i == failed_2 {
            members_dual_degraded.push(None); // Both drives failed
        } else {
            members_dual_degraded.push(Some(Box::new(MockBlockSource::new(b.clone(), sector_size as u32, &format!("DRIVE-{}", i)))));
        }
    }

    let mut raid_dual = RaidArray::new(geometry.clone(), members_dual_degraded).unwrap();
    assert!(raid_dual.is_degraded());
    assert_eq!(raid_dual.missing_member_indices(), vec![failed_0, failed_2]);

    let read_dual_degraded = raid_dual.read_blocks(0, raid_dual.total_blocks() as u32).unwrap();
    assert_eq!(
        read_dual_degraded, ground_truth,
        "Dual-degraded RAID 6 (2 missing drives) must reconstruct exact ground truth via Reed-Solomon Galois Field syndromic math!"
    );
}

#[test]
fn test_mdadm_superblock_detection_and_auto_assembly() {
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize;
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 3usize;
    let num_stripes = 4usize;
    let data_disks = num_members - 1;

    let data_offset_sectors = 16u64; // Superblock at LBA 8 (offset 4096), Data starts at LBA 16 (offset 8192)
    let total_member_sectors = data_offset_sectors + (num_stripes * chunk_sectors) as u64;

    let total_data_bytes = data_disks * num_stripes * chunk_size_bytes;
    let mut ground_truth = vec![0u8; total_data_bytes];
    for (i, byte) in ground_truth.iter_mut().enumerate() {
        *byte = ((i * 41 + 13) % 256) as u8;
    }

    let set_uuid = [0x42u8; 16];
    let mut candidate_drives: Vec<Box<dyn ReadOnlyBlockSource>> = Vec::new();

    for dev_num in 0..num_members {
        let mut disk_data = vec![0u8; (total_member_sectors as usize) * sector_size];

        // Write mdadm 1.2 superblock at offset 4096 bytes (LBA 8)
        let sb_offset = 4096;
        let magic: u32 = 0xa9280c09;
        let major: u32 = 1;
        let level: i32 = 5;
        let layout: u32 = 2; // LeftSymmetric
        let chunksize: u32 = chunk_sectors as u32;
        let raid_disks: u32 = num_members as u32;
        let data_offset: u64 = data_offset_sectors;
        let data_size: u64 = (num_stripes * chunk_sectors) as u64;

        disk_data[sb_offset..sb_offset + 4].copy_from_slice(&magic.to_le_bytes());
        disk_data[sb_offset + 4..sb_offset + 8].copy_from_slice(&major.to_le_bytes());
        disk_data[sb_offset + 16..sb_offset + 32].copy_from_slice(&set_uuid);
        disk_data[sb_offset + 72..sb_offset + 76].copy_from_slice(&level.to_le_bytes());
        disk_data[sb_offset + 76..sb_offset + 80].copy_from_slice(&layout.to_le_bytes());
        disk_data[sb_offset + 88..sb_offset + 92].copy_from_slice(&chunksize.to_le_bytes());
        disk_data[sb_offset + 92..sb_offset + 96].copy_from_slice(&raid_disks.to_le_bytes());
        disk_data[sb_offset + 128..sb_offset + 136].copy_from_slice(&data_offset.to_le_bytes());
        disk_data[sb_offset + 136..sb_offset + 144].copy_from_slice(&data_size.to_le_bytes());
        disk_data[sb_offset + 160..sb_offset + 164].copy_from_slice(&(dev_num as u32).to_le_bytes());

        // Write data and parity to data area
        for stripe in 0..num_stripes {
            let p_idx = (num_members - 1 - (stripe % num_members)) % num_members;
            let stripe_data_offset = ((data_offset_sectors as usize) + stripe * chunk_sectors) * sector_size;

            if dev_num == p_idx {
                // Compute XOR parity
                let mut parity = vec![0u8; chunk_size_bytes];
                for col in 0..data_disks {
                    let gt_chunk_idx = stripe * data_disks + col;
                    let gt_slice = &ground_truth[gt_chunk_idx * chunk_size_bytes..(gt_chunk_idx + 1) * chunk_size_bytes];
                    for (p_b, &d_b) in parity.iter_mut().zip(gt_slice.iter()) {
                        *p_b ^= d_b;
                    }
                }
                disk_data[stripe_data_offset..stripe_data_offset + chunk_size_bytes].copy_from_slice(&parity);
            } else {
                // Determine data column
                let mut d_col = 0;
                for col in 0..data_disks {
                    if (p_idx + 1 + col) % num_members == dev_num {
                        d_col = col;
                        break;
                    }
                }
                let gt_chunk_idx = stripe * data_disks + d_col;
                let gt_slice = &ground_truth[gt_chunk_idx * chunk_size_bytes..(gt_chunk_idx + 1) * chunk_size_bytes];
                disk_data[stripe_data_offset..stripe_data_offset + chunk_size_bytes].copy_from_slice(gt_slice);
            }
        }

        candidate_drives.push(Box::new(MockBlockSource::new(
            disk_data,
            sector_size as u32,
            &format!("MD-MEMBER-{}", dev_num),
        )));
    }

    // Auto-detect and assemble
    let mut auto_raid = RaidArray::auto_detect(candidate_drives).unwrap();
    assert_eq!(auto_raid.geometry().level, RaidLevel::Raid5);
    assert_eq!(auto_raid.geometry().num_members, 3);
    assert_eq!(auto_raid.geometry().chunk_size_bytes, 4096);

    let read_back = auto_raid.read_blocks(0, auto_raid.total_blocks() as u32).unwrap();
    assert_eq!(read_back, ground_truth, "Auto-detected RAID 5 array must read ground truth accurately");
}

