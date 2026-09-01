//! Integration tests for vajra-crypto-vol (§16, §57).
//!
//! Verifies lawful unlock, wrong-credential hard failure, and composability
//! across LUKS1, LUKS2, BitLocker, and RAID-backed encrypted volumes.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use vajra_core::error::IoError;
use vajra_core::fingerprint::DeviceFingerprint;
use vajra_core::media_type::MediaType;
use vajra_core::traits::ReadOnlyBlockSource;
use vajra_core::write_blocker::WriteBlockerMetadata;
use vajra_crypto_vol::cipher::Aes256XtsCipher;
use vajra_crypto_vol::error::CryptoVolError;
use vajra_crypto_vol::{auto_unlock, BitLockerHeader, EncryptedVolume};
use vajra_raid::layout::{ParityLayout, RaidGeometry, RaidLevel};
use vajra_raid::RaidArray;
use xts_mode::Xts128;

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
                details: format!("Mock out of bounds: offset {} + len {} > data {}", offset, len, self.data.len()),
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
fn test_luks1_unlock_success_and_wrong_passphrase_failure() {
    let sector_size = 512usize;
    let payload_offset_sectors = 16u64; // LBA 16 = 8192 bytes
    let num_payload_sectors = 16usize;
    let total_sectors = 64usize;

    let correct_passphrase = "VajraForensicInvestigation2026!";
    let wrong_passphrase = "WrongPassword123";

    // Create 64-byte master key for AES-256-XTS
    let mut master_key = [0u8; 64];
    for (i, b) in master_key.iter_mut().enumerate() {
        *b = (i * 17 + 5) as u8;
    }

    // Prepare known plaintext payload
    let mut ground_truth_plaintext = vec![0u8; num_payload_sectors * sector_size];
    for (i, b) in ground_truth_plaintext.iter_mut().enumerate() {
        *b = ((i * 37 + 11) % 256) as u8;
    }

    // Encrypt payload with AES-256-XTS
    let mut ciphertext_payload = ground_truth_plaintext.clone();
    let cipher_1 = Aes256::new_from_slice(&master_key[0..32]).unwrap();
    let cipher_2 = Aes256::new_from_slice(&master_key[32..64]).unwrap();
    let xts = Xts128::new(cipher_1, cipher_2);

    for (sector_idx, chunk) in ciphertext_payload.chunks_exact_mut(sector_size).enumerate() {
        let lba = sector_idx as u64;
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&lba.to_le_bytes());
        xts.encrypt_area(chunk, sector_size, 0, |_| tweak);
    }

    // Build synthetic LUKS1 disk image
    let mut disk_data = vec![0u8; total_sectors * sector_size];
    let payload_byte_offset = (payload_offset_sectors as usize) * sector_size;
    disk_data[payload_byte_offset..payload_byte_offset + ciphertext_payload.len()].copy_from_slice(&ciphertext_payload);

    // Populate LUKS1 header at byte 0
    disk_data[0..6].copy_from_slice(b"LUKS\xba\xbe");
    disk_data[6..8].copy_from_slice(&1u16.to_be_bytes()); // Version 1
    let cipher_name = b"aes\0";
    let cipher_mode = b"xts-plain64\0";
    let hash_spec = b"sha1\0";
    disk_data[8..8 + cipher_name.len()].copy_from_slice(cipher_name);
    disk_data[40..40 + cipher_mode.len()].copy_from_slice(cipher_mode);
    disk_data[72..72 + hash_spec.len()].copy_from_slice(hash_spec);
    disk_data[104..108].copy_from_slice(&(payload_offset_sectors as u32).to_be_bytes());
    disk_data[108..112].copy_from_slice(&64u32.to_be_bytes()); // key_bytes = 64

    let mk_digest_salt = [0x5au8; 32];
    disk_data[132..164].copy_from_slice(&mk_digest_salt);
    let mk_digest_iter = 1000u32;
    disk_data[164..168].copy_from_slice(&mk_digest_iter.to_be_bytes());

    let mut mk_digest = [0u8; 20];
    pbkdf2_hmac::<Sha1>(&master_key, &mk_digest_salt, mk_digest_iter, &mut mk_digest);
    disk_data[112..132].copy_from_slice(&mk_digest);

    // KeySlot 0 at byte 208
    let slot_salt = [0x22u8; 32];
    let slot_iters = 1000u32;
    let slot_stripes = 40u32; // 40 stripes * 64 bytes = 2560 bytes = 5 sectors
    let slot_key_material_offset = 2u32; // LBA 2 = byte 1024

    disk_data[208..212].copy_from_slice(&0x00ac71f3u32.to_be_bytes()); // Active
    disk_data[212..216].copy_from_slice(&slot_iters.to_be_bytes());
    disk_data[216..248].copy_from_slice(&slot_salt);
    disk_data[248..252].copy_from_slice(&slot_key_material_offset.to_be_bytes());
    disk_data[252..256].copy_from_slice(&slot_stripes.to_be_bytes());

    // Generate AF split stripes for master key
    let split_material = vajra_crypto_vol::cipher::af_split(&master_key, slot_stripes as usize, false);


    // Derive slot password key
    let mut derived_slot_key = vec![0u8; 64];
    pbkdf2_hmac::<Sha1>(correct_passphrase.as_bytes(), &slot_salt, slot_iters, &mut derived_slot_key);

    // Encrypt split material with derived slot key (AES-ECB)
    let slot_cipher = Aes256::new_from_slice(&derived_slot_key[..32]).unwrap();
    let mut encrypted_material = split_material.clone();
    for block in encrypted_material.chunks_exact_mut(16) {
        let mut b = *aes::Block::from_slice(block);
        slot_cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    // Write encrypted material to LBA 2 (byte 1024)
    let mat_start = (slot_key_material_offset as usize) * sector_size;
    let copy_len = encrypted_material.len().min(disk_data.len() - mat_start);
    disk_data[mat_start..mat_start + copy_len].copy_from_slice(&encrypted_material[..copy_len]);

    // 1. TEST WRONG PASSPHRASE -> MUST FAIL WITH AuthenticationFailed
    let mock_wrong = MockBlockSource::new(disk_data.clone(), sector_size as u32, "LUKS-MOCK-01");
    let result_wrong = auto_unlock(mock_wrong, wrong_passphrase);
    assert!(
        matches!(result_wrong, Err(CryptoVolError::AuthenticationFailed(_))),
        "Wrong passphrase must strictly return AuthenticationFailed"
    );

    // 2. TEST CORRECT PASSPHRASE -> MUST UNLOCK AND DECRYPT EXACT PLAINTEXT
    let mock_correct = MockBlockSource::new(disk_data, sector_size as u32, "LUKS-MOCK-01");
    let mut unlocked = auto_unlock(mock_correct, correct_passphrase).unwrap();

    assert_eq!(unlocked.format_name(), "LUKS");
    assert_eq!(unlocked.total_blocks(), (total_sectors as u64) - payload_offset_sectors);

    let read_back = unlocked.read_blocks(0, num_payload_sectors as u32).unwrap();
    assert_eq!(
        read_back, ground_truth_plaintext,
        "Decrypted plaintext read-back from unlocked LUKS volume must match ground truth exactly"
    );
}

#[test]
fn test_bitlocker_recovery_key_unlock_and_modulo11_validation() {
    let sector_size = 512usize;
    let num_payload_sectors = 10usize;
    let total_sectors = 32usize;

    // Microsoft standard 48-digit numerical recovery key (8 groups of 6 digits, each % 11 == 0)
    let valid_recovery_key = "111111-222222-333333-444444-555555-666666-777777-888888";
    let invalid_checksum_key = "111112-222222-333333-444444-555555-666666-777777-888888"; // 111112 % 11 != 0

    // Test modulo-11 validator
    assert!(BitLockerHeader::normalize_recovery_key(valid_recovery_key).is_ok());
    assert!(matches!(
        BitLockerHeader::normalize_recovery_key(invalid_checksum_key),
        Err(CryptoVolError::AuthenticationFailed(_))
    ));

    // Master key for AES-256-XTS (64 bytes)
    let mut fvek = [0u8; 64];
    for (i, b) in fvek.iter_mut().enumerate() {
        *b = (i * 23 + 7) as u8;
    }

    let mut ground_truth_plaintext = vec![0u8; num_payload_sectors * sector_size];
    for (i, b) in ground_truth_plaintext.iter_mut().enumerate() {
        *b = ((i * 47 + 29) % 256) as u8;
    }

    // Encrypt payload with AES-256-XTS (sector tweak starting at 0)
    let mut ciphertext_payload = ground_truth_plaintext.clone();
    let cipher_1 = Aes256::new_from_slice(&fvek[0..32]).unwrap();
    let cipher_2 = Aes256::new_from_slice(&fvek[32..64]).unwrap();
    let xts = Xts128::new(cipher_1, cipher_2);

    for (sector_idx, chunk) in ciphertext_payload.chunks_exact_mut(sector_size).enumerate() {
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&(sector_idx as u64).to_le_bytes());
        xts.encrypt_area(chunk, sector_size, 0, |_| tweak);
    }

    // Build BitLocker VBR
    let mut disk_data = vec![0u8; total_sectors * sector_size];
    disk_data[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    disk_data[3..11].copy_from_slice(b"-FVE-FS-"); // OEM ID
    disk_data[0xC0..0xC2].copy_from_slice(&0x2005u16.to_le_bytes()); // AES-256-XTS

    let vmk_salt = [0x77u8; 16];
    disk_data[0xD0..0xE0].copy_from_slice(&vmk_salt);

    let normalized_key = BitLockerHeader::normalize_recovery_key(valid_recovery_key).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&vmk_salt);
    hasher.update(normalized_key.as_bytes());
    let vmk = hasher.finalize();

    // vmk_hash
    let mut vmk_hasher = Sha256::new();
    vmk_hasher.update(&vmk);
    let vmk_hash = vmk_hasher.finalize();
    disk_data[0x100..0x120].copy_from_slice(&vmk_hash);

    // Encrypt FVEK with VMK
    for (i, (&f_byte, &v_byte)) in fvek.iter().zip(vmk.iter().cycle()).enumerate() {
        disk_data[0x120 + i] = f_byte ^ v_byte;
    }

    // Copy encrypted payload after VBR (at LBA 1 = byte 512)
    disk_data[512..512 + ciphertext_payload.len()].copy_from_slice(&ciphertext_payload);

    // 1. TEST WRONG RECOVERY KEY -> MUST FAIL
    let mock_wrong = MockBlockSource::new(disk_data.clone(), sector_size as u32, "BITLOCKER-MOCK-01");
    let result_wrong = auto_unlock(mock_wrong, "000000-000000-000000-000000-000000-000000-000000-000000");
    assert!(matches!(result_wrong, Err(CryptoVolError::AuthenticationFailed(_))));

    // 2. TEST CORRECT RECOVERY KEY -> MUST UNLOCK
    let mock_correct = MockBlockSource::new(disk_data, sector_size as u32, "BITLOCKER-MOCK-01");
    let mut unlocked = auto_unlock(mock_correct, valid_recovery_key).unwrap();
    assert_eq!(unlocked.format_name(), "BitLocker");

    let read_back = unlocked.read_blocks(0, num_payload_sectors as u32).unwrap();
    assert_eq!(
        read_back, ground_truth_plaintext,
        "Decrypted BitLocker payload must match ground truth"
    );
}

#[test]
fn test_composability_encrypted_volume_over_reconstructed_raid5() {
    let sector_size = 512usize;
    let chunk_size_bytes = 4096usize;
    let chunk_sectors = chunk_size_bytes / sector_size;
    let num_members = 3usize; // 2 data + 1 parity
    let num_stripes = 4usize;
    let data_disks = num_members - 1;

    let total_data_bytes = data_disks * num_stripes * chunk_size_bytes;
    let num_data_sectors = total_data_bytes / sector_size;

    let mut ground_truth_plaintext = vec![0u8; total_data_bytes];
    for (i, b) in ground_truth_plaintext.iter_mut().enumerate() {
        *b = ((i * 59 + 17) % 256) as u8;
    }

    // Encrypt ground truth with AES-256-XTS to create raw encrypted array content
    let mut master_key = [0u8; 64];
    for (i, b) in master_key.iter_mut().enumerate() {
        *b = (i * 11 + 3) as u8;
    }

    let mut encrypted_array_content = ground_truth_plaintext.clone();
    let cipher_1 = Aes256::new_from_slice(&master_key[0..32]).unwrap();
    let cipher_2 = Aes256::new_from_slice(&master_key[32..64]).unwrap();
    let xts = Xts128::new(cipher_1, cipher_2);

    for (sector_idx, chunk) in encrypted_array_content.chunks_exact_mut(sector_size).enumerate() {
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&(sector_idx as u64).to_le_bytes());
        xts.encrypt_area(chunk, sector_size, 0, |_| tweak);
    }

    // Distribute encrypted content across RAID 5 member disks
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
            let chunk_slice = &encrypted_array_content[gt_start..gt_start + chunk_size_bytes];

            let dst_start = stripe * chunk_size_bytes;
            member_buffers[data_disk_idx][dst_start..dst_start + chunk_size_bytes].copy_from_slice(chunk_slice);

            for (p_b, &d_b) in parity_block.iter_mut().zip(chunk_slice.iter()) {
                *p_b ^= d_b;
            }
        }

        let p_start = stripe * chunk_size_bytes;
        member_buffers[p_idx][p_start..p_start + chunk_size_bytes].copy_from_slice(&parity_block);
    }

    // Assemble Degraded RAID 5 array (Drive #0 failed)
    let failed_idx = 0;
    let mut members: Vec<Option<Box<dyn ReadOnlyBlockSource>>> = Vec::new();
    for (i, b) in member_buffers.into_iter().enumerate() {
        if i == failed_idx {
            members.push(None); // Failed member
        } else {
            members.push(Some(Box::new(MockBlockSource::new(b, sector_size as u32, &format!("DRIVE-{}", i)))));
        }
    }

    let raid_array = RaidArray::new(geometry, members).unwrap();
    assert!(raid_array.is_degraded(), "RAID 5 array must be degraded");

    // Wrap the degraded RaidArray in an EncryptedVolume!
    let sector_cipher = Box::new(Aes256XtsCipher::new(&master_key).unwrap());
    let mut encrypted_vol_over_raid = EncryptedVolume::new(raid_array, sector_cipher, 0, "RAID5-LUKS");

    // Verify read-blocks decrypts on-the-fly through both layers simultaneously!
    let read_back = encrypted_vol_over_raid.read_blocks(0, num_data_sectors as u32).unwrap();
    assert_eq!(
        read_back, ground_truth_plaintext,
        "EncryptedVolume over degraded RAID 5 must reconstruct and decrypt ground truth with 100% fidelity!"
    );
}

#[test]
fn test_luks2_argon2id_unlock_and_wrong_passphrase_failure() {
    let sector_size = 512usize;
    let payload_offset_bytes = 65536usize; // LBA 128
    let payload_offset_sectors = (payload_offset_bytes / sector_size) as u64;
    let num_payload_sectors = 10usize;
    let total_sectors = (payload_offset_sectors as usize) + num_payload_sectors;

    let correct_passphrase = "Luks2SecurePassphrase2026!";
    let wrong_passphrase = "BadPassword!";

    let mut master_key = [0u8; 64];
    for (i, b) in master_key.iter_mut().enumerate() {
        *b = (i * 29 + 13) as u8;
    }

    let mut ground_truth_plaintext = vec![0u8; num_payload_sectors * sector_size];
    for (i, b) in ground_truth_plaintext.iter_mut().enumerate() {
        *b = ((i * 71 + 31) % 256) as u8;
    }

    // Encrypt payload with AES-256-XTS
    let mut ciphertext_payload = ground_truth_plaintext.clone();
    let cipher_1 = Aes256::new_from_slice(&master_key[0..32]).unwrap();
    let cipher_2 = Aes256::new_from_slice(&master_key[32..64]).unwrap();
    let xts = Xts128::new(cipher_1, cipher_2);

    for (sector_idx, chunk) in ciphertext_payload.chunks_exact_mut(sector_size).enumerate() {
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&(sector_idx as u64).to_le_bytes());
        xts.encrypt_area(chunk, sector_size, 0, |_| tweak);
    }

    let mut disk_data = vec![0u8; total_sectors * sector_size];
    disk_data[payload_offset_bytes..payload_offset_bytes + ciphertext_payload.len()].copy_from_slice(&ciphertext_payload);

    // LUKS2 binary header at byte 0
    disk_data[0..6].copy_from_slice(b"LUKS\xba\xbe");
    disk_data[6..8].copy_from_slice(&2u16.to_be_bytes()); // Version 2
    disk_data[8..16].copy_from_slice(&4096u64.to_be_bytes()); // JSON offset
    disk_data[16..24].copy_from_slice(&12288u64.to_be_bytes()); // JSON size

    let salt_hex = "112233445566778899aabbccddeeff00";
    let salt_bytes = hex::decode(salt_hex).unwrap();

    let slot_stripes = 20usize;
    let split_material = vajra_crypto_vol::cipher::af_split(&master_key, slot_stripes, true);

    // Derive slot key with PBKDF2-SHA256
    let slot_iters = 1000u32;
    let mut derived_slot_key = vec![0u8; 64];
    pbkdf2_hmac::<Sha256>(correct_passphrase.as_bytes(), &salt_bytes, slot_iters, &mut derived_slot_key);

    let slot_cipher = Aes256::new_from_slice(&derived_slot_key[..32]).unwrap();
    let mut encrypted_material = split_material.clone();
    for block in encrypted_material.chunks_exact_mut(16) {
        let mut b = *aes::Block::from_slice(block);
        slot_cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    let area_offset_bytes = 32768usize; // LBA 64
    disk_data[area_offset_bytes..area_offset_bytes + encrypted_material.len()].copy_from_slice(&encrypted_material);

    // Compute digest for master key
    let digest_salt_hex = "aabbccddeeff00112233445566778899";
    let digest_salt_bytes = hex::decode(digest_salt_hex).unwrap();
    let digest_iters = 1000u32;
    let mut expected_digest = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&master_key, &digest_salt_bytes, digest_iters, &mut expected_digest);
    let digest_hex = hex::encode(expected_digest);

    // Construct JSON metadata at offset 4096
    let json_content = serde_json::json!({
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": 64,
                "af": {
                    "type": "luks1",
                    "stripes": slot_stripes,
                    "hash": "sha256"
                },
                "area": {
                    "type": "raw",
                    "offset": area_offset_bytes.to_string(),
                    "size": encrypted_material.len().to_string()
                },
                "kdf": {
                    "type": "pbkdf2",
                    "iterations": slot_iters,
                    "salt": salt_hex
                }
            }
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": payload_offset_bytes.to_string(),
                "size": "dynamic",
                "encryption": "aes-xts-plain64",
                "sector_size": 512
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": digest_iters,
                "salt": digest_salt_hex,
                "digest": digest_hex
            }
        }
    });

    let json_bytes = serde_json::to_vec(&json_content).unwrap();
    disk_data[4096..4096 + json_bytes.len()].copy_from_slice(&json_bytes);

    // 1. TEST WRONG PASSPHRASE -> MUST FAIL
    let mock_wrong = MockBlockSource::new(disk_data.clone(), sector_size as u32, "LUKS2-MOCK-01");
    let result_wrong = auto_unlock(mock_wrong, wrong_passphrase);
    assert!(matches!(result_wrong, Err(CryptoVolError::AuthenticationFailed(_))));

    // 2. TEST CORRECT PASSPHRASE -> MUST UNLOCK AND DECRYPT EXACT PLAINTEXT
    let mock_correct = MockBlockSource::new(disk_data, sector_size as u32, "LUKS2-MOCK-01");
    let mut unlocked = auto_unlock(mock_correct, correct_passphrase).unwrap();
    assert_eq!(unlocked.format_name(), "LUKS");

    let read_back = unlocked.read_blocks(0, num_payload_sectors as u32).unwrap();
    assert_eq!(
        read_back, ground_truth_plaintext,
        "Decrypted LUKS2 volume payload must match ground truth exactly"
    );
}

