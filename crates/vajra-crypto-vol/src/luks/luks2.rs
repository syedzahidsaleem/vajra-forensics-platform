//! LUKS2 JSON Metadata Parser and Argon2id / PBKDF2 Unlock Pipeline (§16, §57).

use crate::cipher::{af_merge, Aes128XtsCipher, Aes256XtsCipher, SectorCipher};
use crate::error::CryptoVolError;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use vajra_core::traits::ReadOnlyBlockSource;
use zeroize::Zeroize;

pub const LUKS2_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

#[derive(Debug, Deserialize)]
pub struct Luks2JsonRoot {
    pub keyslots: HashMap<String, Luks2JsonKeyslot>,
    pub segments: HashMap<String, Luks2JsonSegment>,
    pub digests: HashMap<String, Luks2JsonDigest>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonKeyslot {
    #[serde(rename = "type")]
    pub slot_type: String,
    pub key_size: usize,
    pub af: Luks2JsonAf,
    pub area: Luks2JsonArea,
    pub kdf: Luks2JsonKdf,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonAf {
    #[serde(rename = "type")]
    pub af_type: String,
    pub stripes: usize,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonArea {
    #[serde(rename = "type")]
    pub area_type: String,
    pub offset: String,
    pub size: String,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonKdf {
    #[serde(rename = "type")]
    pub kdf_type: String,
    pub time: Option<u32>,
    pub memory: Option<u32>,
    pub cpus: Option<u32>,
    pub iterations: Option<u32>,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonSegment {
    #[serde(rename = "type")]
    pub seg_type: String,
    pub offset: String,
    pub encryption: String,
    pub sector_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2JsonDigest {
    #[serde(rename = "type")]
    pub digest_type: String,
    pub keyslots: Vec<String>,
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: Option<u32>,
    pub salt: String,
    pub digest: String,
}

pub struct Luks2Header {
    pub version: u16,
    pub json: Luks2JsonRoot,
}

impl Luks2Header {
    pub fn parse(buf: &[u8]) -> Result<Self, CryptoVolError> {
        if buf.len() < 4096 {
            return Err(CryptoVolError::InvalidHeader("Buffer too short for LUKS2 header".to_string()));
        }

        if &buf[0..6] != LUKS2_MAGIC {
            return Err(CryptoVolError::InvalidHeader("Invalid LUKS2 magic bytes".to_string()));
        }

        let version = u16::from_be_bytes(buf[6..8].try_into().unwrap());
        if version != 2 {
            return Err(CryptoVolError::UnsupportedFormat(format!("Expected LUKS version 2, got {}", version)));
        }

        // Parse JSON metadata segment (starting at byte 4096 or immediate JSON string in header)
        let json_slice = if buf.len() >= 8192 {
            &buf[4096..]
        } else {
            &buf[512..]
        };

        // Trim trailing zeros
        let json_end = json_slice.iter().position(|&b| b == 0).unwrap_or(json_slice.len());
        let json_str = String::from_utf8_lossy(&json_slice[..json_end]);

        let json: Luks2JsonRoot = serde_json::from_str(&json_str).map_err(|e| {
            CryptoVolError::InvalidHeader(format!("Failed to parse LUKS2 JSON metadata: {}", e))
        })?;

        Ok(Self { version, json })
    }

    /// Lawful unlock with passphrase (§57).
    pub fn unlock(
        &self,
        source: &mut dyn ReadOnlyBlockSource,
        passphrase: &str,
    ) -> Result<(Box<dyn SectorCipher>, u64), CryptoVolError> {
        let block_size = source.block_size() as u64;

        // Find primary segment offset
        let primary_segment = self.json.segments.get("0").ok_or_else(|| {
            CryptoVolError::InvalidHeader("No primary segment (0) found in LUKS2 JSON".to_string())
        })?;

        let payload_offset_bytes: u64 = primary_segment.offset.parse().unwrap_or(16777216);
        let payload_offset_sectors = payload_offset_bytes / block_size;

        for (slot_name, slot) in &self.json.keyslots {
            if slot.slot_type != "luks2" {
                continue;
            }

            let salt_bytes = hex::decode(&slot.kdf.salt)
                .or_else(|_| hex::decode(slot.kdf.salt.replace('-', "")))
                .unwrap_or_else(|_| slot.kdf.salt.as_bytes().to_vec());

            let mut derived_key = vec![0u8; slot.key_size];

            if slot.kdf.kdf_type == "argon2id" {
                let time_cost = slot.kdf.time.unwrap_or(4);
                let mem_cost = slot.kdf.memory.unwrap_or(65536);
                let lanes = slot.kdf.cpus.unwrap_or(4);

                let params = Params::new(mem_cost, time_cost, lanes, Some(slot.key_size))
                    .map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

                argon2.hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut derived_key)
                    .map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
            } else {
                // PBKDF2 fallback
                let iters = slot.kdf.iterations.unwrap_or(1000);
                pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt_bytes, iters, &mut derived_key);
            }

            // Read encrypted key material area
            let area_offset_bytes: u64 = slot.area.offset.parse().unwrap_or(32768);
            let area_size_bytes: usize = slot.area.size.parse().unwrap_or(258048);

            let area_lba = area_offset_bytes / block_size;
            let sectors_to_read = ((area_size_bytes as u64) + block_size - 1) / block_size;

            let raw_material = source.read_blocks(area_lba, sectors_to_read as u32)?;
            let mut encrypted_material = raw_material[..area_size_bytes.min(raw_material.len())].to_vec();

            // Decrypt key material
            if derived_key.len() == 64 {
                if let Ok(cipher) = Aes256::new_from_slice(&derived_key[..32]) {
                    for block in encrypted_material.chunks_exact_mut(16) {
                        let mut b = *aes::Block::from_slice(block);
                        cipher.decrypt_block(&mut b);
                        block.copy_from_slice(&b);
                    }
                }
            } else if derived_key.len() == 32 {
                if let Ok(cipher) = Aes128::new_from_slice(&derived_key[..16]) {
                    for block in encrypted_material.chunks_exact_mut(16) {
                        let mut b = *aes::Block::from_slice(block);
                        cipher.decrypt_block(&mut b);
                        block.copy_from_slice(&b);
                    }
                }
            }

            // Merge AF stripes
            let mut master_key = vec![0u8; slot.key_size];
            let use_sha256 = slot.af.hash.to_lowercase().contains("sha256");
            if af_merge(
                &encrypted_material,
                slot.key_size,
                slot.af.stripes,
                use_sha256,
                &mut master_key,
            ).is_err() {
                derived_key.zeroize();
                master_key.zeroize();
                continue;
            }

            // Match against digests
            let matching_digest = self.json.digests.values().find(|d| d.keyslots.contains(slot_name));
            if let Some(digest) = matching_digest {
                let d_salt = hex::decode(&digest.salt).unwrap_or_else(|_| digest.salt.as_bytes().to_vec());
                let expected_digest = hex::decode(&digest.digest).unwrap_or_default();
                let iters = digest.iterations.unwrap_or(1000);

                let mut cand_digest = vec![0u8; expected_digest.len().max(32)];
                pbkdf2_hmac::<Sha256>(&master_key, &d_salt, iters, &mut cand_digest);

                if !expected_digest.is_empty() && &cand_digest[..expected_digest.len()] == expected_digest.as_slice() {
                    let cipher: Box<dyn SectorCipher> = if master_key.len() == 64 {
                        Box::new(Aes256XtsCipher::new(&master_key)?)
                    } else {
                        Box::new(Aes128XtsCipher::new(&master_key)?)
                    };

                    master_key.zeroize();
                    derived_key.zeroize();

                    return Ok((cipher, payload_offset_sectors));
                }
            }

            master_key.zeroize();
            derived_key.zeroize();
        }

        Err(CryptoVolError::AuthenticationFailed(
            "Incorrect passphrase for LUKS2 volume".to_string(),
        ))
    }
}
