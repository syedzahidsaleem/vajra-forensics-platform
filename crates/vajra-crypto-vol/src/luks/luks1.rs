//! LUKS1 Header Parser and Key Unlock Pipeline (§16, §57).

use crate::cipher::{af_merge, Aes128XtsCipher, Aes256XtsCipher, SectorCipher};
use crate::error::CryptoVolError;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;
use vajra_core::traits::ReadOnlyBlockSource;
use zeroize::Zeroize;

pub const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
pub const LUKS_KEYSLOT_ACTIVE: u32 = 0x00ac71f3;

#[derive(Debug, Clone)]
pub struct Luks1KeySlot {
    pub active: u32,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub key_material_offset_sectors: u32,
    pub stripes: u32,
}

#[derive(Debug, Clone)]
pub struct Luks1Header {
    pub version: u16,
    pub cipher_name: String,
    pub cipher_mode: String,
    pub hash_spec: String,
    pub payload_offset_sectors: u64,
    pub key_bytes: u32,
    pub mk_digest: [u8; 20],
    pub mk_digest_salt: [u8; 32],
    pub mk_digest_iter: u32,
    pub uuid: String,
    pub keyslots: [Luks1KeySlot; 8],
}

impl Luks1Header {
    pub fn parse(buf: &[u8]) -> Result<Self, CryptoVolError> {
        if buf.len() < 592 {
            return Err(CryptoVolError::InvalidHeader("Buffer too short for LUKS1 header".to_string()));
        }

        if &buf[0..6] != LUKS_MAGIC {
            return Err(CryptoVolError::InvalidHeader("Invalid LUKS magic bytes".to_string()));
        }

        let version = u16::from_be_bytes(buf[6..8].try_into().unwrap());
        if version != 1 {
            return Err(CryptoVolError::UnsupportedFormat(format!("Unsupported LUKS version: {}", version)));
        }

        let cipher_name = String::from_utf8_lossy(&buf[8..40]).trim_matches(char::from(0)).to_string();
        let cipher_mode = String::from_utf8_lossy(&buf[40..72]).trim_matches(char::from(0)).to_string();
        let hash_spec = String::from_utf8_lossy(&buf[72..104]).trim_matches(char::from(0)).to_string();

        let payload_offset_sectors = u32::from_be_bytes(buf[104..108].try_into().unwrap()) as u64;
        let key_bytes = u32::from_be_bytes(buf[108..112].try_into().unwrap());

        let mut mk_digest = [0u8; 20];
        mk_digest.copy_from_slice(&buf[112..132]);

        let mut mk_digest_salt = [0u8; 32];
        mk_digest_salt.copy_from_slice(&buf[132..164]);

        let mk_digest_iter = u32::from_be_bytes(buf[164..168].try_into().unwrap());
        let uuid = String::from_utf8_lossy(&buf[168..208]).trim_matches(char::from(0)).to_string();

        let mut keyslots = Vec::with_capacity(8);
        for i in 0..8 {
            let base = 208 + i * 48;
            let active = u32::from_be_bytes(buf[base..base + 4].try_into().unwrap());
            let iterations = u32::from_be_bytes(buf[base + 4..base + 8].try_into().unwrap());
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&buf[base + 8..base + 40]);
            let key_material_offset_sectors = u32::from_be_bytes(buf[base + 40..base + 44].try_into().unwrap());
            let stripes = u32::from_be_bytes(buf[base + 44..base + 48].try_into().unwrap());

            keyslots.push(Luks1KeySlot {
                active,
                iterations,
                salt,
                key_material_offset_sectors,
                stripes,
            });
        }

        Ok(Self {
            version,
            cipher_name,
            cipher_mode,
            hash_spec,
            payload_offset_sectors,
            key_bytes,
            mk_digest,
            mk_digest_salt,
            mk_digest_iter,
            uuid,
            keyslots: keyslots.try_into().unwrap(),
        })
    }

    /// Lawful unlock with passphrase (§57).
    pub fn unlock(
        &self,
        source: &mut dyn ReadOnlyBlockSource,
        passphrase: &str,
    ) -> Result<(Box<dyn SectorCipher>, u64), CryptoVolError> {
        let block_size = source.block_size() as u64;
        let use_sha256 = self.hash_spec.to_lowercase().contains("sha256");

        for (_slot_idx, slot) in self.keyslots.iter().enumerate() {
            if slot.active != LUKS_KEYSLOT_ACTIVE {
                continue;
            }

            let mut derived_key = vec![0u8; self.key_bytes as usize];
            if use_sha256 {
                pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &slot.salt, slot.iterations, &mut derived_key);
            } else {
                pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), &slot.salt, slot.iterations, &mut derived_key);
            }

            // Read encrypted key material
            let total_key_material_bytes = (slot.stripes as usize) * (self.key_bytes as usize);
            let sectors_to_read = ((total_key_material_bytes as u64) + block_size - 1) / block_size;
            let lba = slot.key_material_offset_sectors as u64;

            let raw_key_material = source.read_blocks(lba, sectors_to_read as u32)?;
            let mut encrypted_material = raw_key_material[..total_key_material_bytes].to_vec();

            // Decrypt key material with AES-ECB
            if derived_key.len() == 64 {
                let cipher = Aes256::new_from_slice(&derived_key[..32]).unwrap();
                for block in encrypted_material.chunks_exact_mut(16) {
                    let mut b = *aes::Block::from_slice(block);
                    cipher.decrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
            } else if derived_key.len() == 32 {
                let cipher = Aes128::new_from_slice(&derived_key[..16]).unwrap();
                for block in encrypted_material.chunks_exact_mut(16) {
                    let mut b = *aes::Block::from_slice(block);
                    cipher.decrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
            }

            // Merge Anti-Forensic stripes
            let mut master_key = vec![0u8; self.key_bytes as usize];
            if af_merge(
                &encrypted_material,
                self.key_bytes as usize,
                slot.stripes as usize,
                use_sha256,
                &mut master_key,
            ).is_err() {
                derived_key.zeroize();
                master_key.zeroize();
                continue;
            }

            // Validate candidate master key against recorded mk_digest
            let mut candidate_digest = [0u8; 20];
            pbkdf2_hmac::<Sha1>(&master_key, &self.mk_digest_salt, self.mk_digest_iter, &mut candidate_digest);

            if candidate_digest == self.mk_digest {
                // Correct key unlocked!
                let cipher: Box<dyn SectorCipher> = if master_key.len() == 64 {
                    Box::new(Aes256XtsCipher::new(&master_key)?)
                } else {
                    Box::new(Aes128XtsCipher::new(&master_key)?)
                };

                master_key.zeroize();
                derived_key.zeroize();

                return Ok((cipher, self.payload_offset_sectors));
            }

            master_key.zeroize();
            derived_key.zeroize();
        }

        Err(CryptoVolError::AuthenticationFailed(
            "Incorrect passphrase for LUKS1 volume".to_string(),
        ))
    }
}
