//! End-to-end CLI diagnostic and validation tests for vajra-raid and vajra-crypto-vol (§15, §16, §57).

use aes::cipher::KeyInit;
use aes::Aes256;
use crc32fast::Hasher as Crc32Hasher;
use std::fs::{self, File};
use std::io::Write;
use tempfile::TempDir;
use vajra_carve::{PipelineOptions, RecoveryPipeline};
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_crypto_vol::cipher::Aes256XtsCipher;
use vajra_crypto_vol::EncryptedVolume;
use vajra_raid::layout::{ParityLayout, RaidGeometry, RaidLevel};
use vajra_raid::superblock::{write_mdadm_1_2_superblock, MdadmSuperblock};
use vajra_raid::RaidArray;
use xts_mode::Xts128;

#[test]
fn test_e2e_raid_superblock_creation_detection_and_assembly() {
    let temp_dir = TempDir::new().unwrap();
    let num_members = 3usize;
    let chunk_size_sectors = 128u32; // 64 KiB
    let sector_size = 512usize;
    let member_sectors = 1024usize;

    let mut member_paths = Vec::new();
    let set_uuid = [0x42u8; 16];

    for dev_idx in 0..num_members {
        let path = temp_dir.path().join(format!("raid_member_{}.raw", dev_idx));
        let mut file = File::create(&path).unwrap();
        let mut data = vec![0u8; member_sectors * sector_size];

        // Write mdadm 1.2 superblock at LBA 8 (byte 4096)
        let sb = MdadmSuperblock {
            major_version: 1,
            minor_version: 2,
            set_uuid,
            set_name: "vajra_forensic_array".to_string(),
            level: RaidLevel::Raid5,
            layout: ParityLayout::LeftSymmetric,
            chunk_size_sectors,
            raid_disks: num_members as u32,
            data_offset_sectors: 16,
            data_size_sectors: (member_sectors - 16) as u64,
            dev_number: dev_idx as u32,
        };

        write_mdadm_1_2_superblock(&mut data[4096..4096 + 512], &sb);

        // Put unique marker in data area (LBA 16+)
        let marker = format!("DATA_CHUNK_DEV_{}_MARKER", dev_idx);
        data[16 * sector_size..16 * sector_size + marker.len()].copy_from_slice(marker.as_bytes());

        file.write_all(&data).unwrap();
        member_paths.push(path.to_str().unwrap().to_string());
    }

    // Auto-assemble using vajra-raid
    let sources: Vec<Box<dyn ReadOnlyBlockSource>> = member_paths
        .iter()
        .map(|p| Box::new(vajra_image::RawImageReader::open(p, None).unwrap()) as Box<dyn ReadOnlyBlockSource>)
        .collect();

    let mut array = RaidArray::auto_detect(sources).unwrap();
    assert_eq!(array.geometry().level, RaidLevel::Raid5);
    assert_eq!(array.geometry().num_members, 3);
    assert!(!array.is_degraded());

    // Read LBA 0 of assembled array
    let lba0 = array.read_blocks(0, 1).unwrap();
    assert_eq!(&lba0[..23], b"DATA_CHUNK_DEV_0_MARKER");
}

#[test]
fn test_e2e_carving_directly_from_encrypted_volume_over_degraded_raid() {
    let temp_dir = TempDir::new().unwrap();
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize;
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 3usize;
    let num_stripes = 4usize;
    let data_disks = 2usize;

    let total_data_bytes = data_disks * num_stripes * chunk_size_bytes; // 32 KiB
    let mut ground_truth_filesystem = vec![0u8; total_data_bytes];

    // Build minimal valid 1x1 PNG with valid CRC-32 checksums
    let mut valid_png = Vec::new();
    valid_png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // Magic
    let ihdr_data = [
        0x00, 0x00, 0x00, 0x01, // width: 1
        0x00, 0x00, 0x00, 0x01, // height: 1
        0x08, 0x02, 0x00, 0x00, 0x00, // 8-bit RGB, deflate, filter 0, no interlace
    ];
    valid_png.extend_from_slice(&13u32.to_be_bytes());
    valid_png.extend_from_slice(b"IHDR");
    valid_png.extend_from_slice(&ihdr_data);
    let mut hasher = Crc32Hasher::new();
    hasher.update(b"IHDR");
    hasher.update(&ihdr_data);
    valid_png.extend_from_slice(&hasher.finalize().to_be_bytes());

    // IEND chunk (0 bytes data)
    valid_png.extend_from_slice(&0u32.to_be_bytes());
    valid_png.extend_from_slice(b"IEND");
    let mut hasher = Crc32Hasher::new();
    hasher.update(b"IEND");
    valid_png.extend_from_slice(&hasher.finalize().to_be_bytes());

    // Embed PNG at sector 4 (byte 2048)
    ground_truth_filesystem[2048..2048 + valid_png.len()].copy_from_slice(&valid_png);

    // Master key for AES-256-XTS
    let mut master_key = [0u8; 64];
    for (i, b) in master_key.iter_mut().enumerate() {
        *b = (i * 13 + 7) as u8;
    }

    // Encrypt filesystem with AES-256-XTS
    let cipher_1 = Aes256::new_from_slice(&master_key[0..32]).unwrap();
    let cipher_2 = Aes256::new_from_slice(&master_key[32..64]).unwrap();
    let xts = Xts128::new(cipher_1, cipher_2);
    let mut encrypted_payload = ground_truth_filesystem.clone();

    for (sector_idx, chunk) in encrypted_payload.chunks_exact_mut(sector_size).enumerate() {
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&(sector_idx as u64).to_le_bytes());
        xts.encrypt_area(chunk, sector_size, 0, |_| tweak);
    }

    // Distribute across RAID 5 member disks
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
            let chunk_slice = &encrypted_payload[gt_start..gt_start + chunk_size_bytes];

            let dst_start = stripe * chunk_size_bytes;
            member_buffers[data_disk_idx][dst_start..dst_start + chunk_size_bytes].copy_from_slice(chunk_slice);

            for (p_b, &d_b) in parity_block.iter_mut().zip(chunk_slice.iter()) {
                *p_b ^= d_b;
            }
        }

        let p_start = stripe * chunk_size_bytes;
        member_buffers[p_idx][p_start..p_start + chunk_size_bytes].copy_from_slice(&parity_block);
    }

    // Save RAID members to disk, and simulate Drive #1 missing/corrupt
    let mut member_sources: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = Vec::new();
    for (i, buf) in member_buffers.into_iter().enumerate() {
        if i == 1 {
            // Simulated missing / dropped member
            member_sources.push(None);
        } else {
            let file_path = temp_dir.path().join(format!("degraded_raid_member_{}.raw", i));
            fs::write(&file_path, &buf).unwrap();
            let reader = vajra_image::RawImageReader::open(file_path.to_str().unwrap(), None).unwrap();
            member_sources.push(Some(Box::new(reader)));
        }
    }

    // 1. Construct degraded RAID 5 array
    let raid_array = RaidArray::new(geometry, member_sources).unwrap();
    assert!(raid_array.is_degraded(), "Array must be degraded with missing member #1");

    // 2. Wrap degraded array directly into EncryptedVolume
    let sector_cipher = Box::new(Aes256XtsCipher::new(&master_key).unwrap());
    let mut encrypted_vol = EncryptedVolume::new(raid_array, sector_cipher, 0, "LUKS-RAID-CARVE");

    // 3. Run carving engine DIRECTLY against the decrypted virtual stream!
    let pipeline = RecoveryPipeline::new();
    let options = PipelineOptions {
        partition_offset: 0,
        enable_tier1: false,
        enable_tier2: true,
        enable_tier3: false,
        target_types: Some(vec!["png".to_string()]),
        max_bgc_search_radius: Some(128),
    };
    let results = pipeline.run(&mut encrypted_vol, &options).unwrap();

    // 4. Verify that the embedded PNG was successfully discovered and extracted!
    assert!(!results.is_empty(), "Carver must recover the PNG from the decrypted RAID array");
    let recovered_png = results.iter().find(|a| a.file_type.to_lowercase() == "png").expect("PNG artifact must be found");
    assert_eq!(recovered_png.source_locations[0].0, 4, "PNG artifact must be located at sector 4");
    assert!(recovered_png.confidence_score >= 0.65, "PNG confidence score was {}", recovered_png.confidence_score);
    assert_eq!(recovered_png.confidence_breakdown.structural_validity, 1.0, "PNG structural validity must be 1.0 (V_OK)");
    assert_eq!(recovered_png.confidence_breakdown.header_footer_integrity, 1.0, "PNG header-footer integrity must be 1.0");
}
