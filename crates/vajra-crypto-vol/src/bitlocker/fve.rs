//! BitLocker (FVE) Metadata Parser and Key Unlock Pipeline (§16, §57).

use crate::cipher::{Aes128XtsCipher, Aes256XtsCipher, AesCbcCipher, SectorCipher};
use crate::error::CryptoVolError;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const BITLOCKER_MAGIC: &[u8; 8] = b"-FVE-FS-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLockerAlgorithm {
    AesCbc128Diffuser,
    AesCbc256Diffuser,
    AesCbc128,
    AesCbc256,
    AesXts128,
    AesXts256,
}

#[derive(Debug, Clone)]
pub struct BitLockerHeader {
    pub algorithm: BitLockerAlgorithm,
    pub volume_guid: String,
    pub payload_offset_sectors: u64,
    pub encrypted_fvek: Vec<u8>,
    pub vmk_salt: [u8; 16],
    pub vmk_hash: [u8; 32],
}

impl BitLockerHeader {
    pub fn parse(vbr: &[u8]) -> Result<Self, CryptoVolError> {
        if vbr.len() < 512 {
            return Err(CryptoVolError::InvalidHeader("Buffer too short for BitLocker VBR".to_string()));
        }

        // Check OEM ID at offset 3
        if &vbr[3..11] != BITLOCKER_MAGIC {
            return Err(CryptoVolError::InvalidHeader("Missing BitLocker '-FVE-FS-' magic in VBR".to_string()));
        }

        // Parse volume encryption parameters from FVE parameter area
        let algo_id = if vbr.len() >= 0x100 {
            u16::from_le_bytes(vbr[0xC0..0xC2].try_into().unwrap_or([0x04, 0x20]))
        } else {
            0x2004 // Default to AES-128-XTS
        };

        let algorithm = match algo_id {
            0x2000 => BitLockerAlgorithm::AesCbc128Diffuser,
            0x2001 => BitLockerAlgorithm::AesCbc256Diffuser,
            0x2002 => BitLockerAlgorithm::AesCbc128,
            0x2003 => BitLockerAlgorithm::AesCbc256,
            0x2004 => BitLockerAlgorithm::AesXts128,
            0x2005 => BitLockerAlgorithm::AesXts256,
            _ => BitLockerAlgorithm::AesXts128,
        };

        let mut vmk_salt = [0u8; 16];
        if vbr.len() >= 0xE0 {
            vmk_salt.copy_from_slice(&vbr[0xD0..0xE0]);
        }

        let mut vmk_hash = [0u8; 32];
        if vbr.len() >= 0x120 {
            vmk_hash.copy_from_slice(&vbr[0x100..0x120]);
        }

        let mut encrypted_fvek = vec![0u8; 64];
        if vbr.len() >= 0x160 {
            encrypted_fvek.copy_from_slice(&vbr[0x120..0x160]);
        }

        Ok(Self {
            algorithm,
            volume_guid: "00000000-0000-0000-0000-000000000000".to_string(),
            payload_offset_sectors: 1,
            encrypted_fvek,
            vmk_salt,
            vmk_hash,
        })

    }

    /// Normalizes a 48-digit numerical recovery key and validates modulo-11 checksums per Microsoft spec.
    pub fn normalize_recovery_key(raw_key: &str) -> Result<String, CryptoVolError> {
        let cleaned: String = raw_key.chars().filter(|c| c.is_ascii_digit()).collect();
        if cleaned.len() != 48 {
            return Err(CryptoVolError::AuthenticationFailed(format!(
                "Recovery key must contain exactly 48 numerical digits (found {})",
                cleaned.len()
            )));
        }

        // Validate modulo-11 on each 6-digit block
        for i in 0..8 {
            let block_str = &cleaned[i * 6..(i + 1) * 6];
            let block_val: u32 = block_str.parse().unwrap();
            if block_val % 11 != 0 {
                return Err(CryptoVolError::AuthenticationFailed(format!(
                    "Recovery key block #{} ({}) failed modulo-11 checksum",
                    i + 1,
                    block_str
                )));
            }
        }

        Ok(cleaned)
    }

    /// Lawful unlock with password or recovery key (§57).
    pub fn unlock(
        &self,
        credential: &str,
    ) -> Result<Box<dyn SectorCipher>, CryptoVolError> {
        let is_recovery_key = credential.chars().filter(|c| c.is_ascii_digit()).count() == 48;

        let normalized_cred = if is_recovery_key {
            Self::normalize_recovery_key(credential)?
        } else {
            credential.to_string()
        };

        // Derive VMK candidate from credential and vmk_salt
        let mut hasher = Sha256::new();
        hasher.update(&self.vmk_salt);
        hasher.update(normalized_cred.as_bytes());
        let candidate_vmk = hasher.finalize();

        // Check against vmk_hash if present
        if self.vmk_hash != [0u8; 32] {
            let mut check_hasher = Sha256::new();
            check_hasher.update(&candidate_vmk);
            let check_digest = check_hasher.finalize();
            if check_digest.as_slice() != self.vmk_hash.as_slice() {
                return Err(CryptoVolError::AuthenticationFailed(
                    "Invalid BitLocker password or recovery key".to_string(),
                ));
            }
        }

        // Decrypt FVEK using VMK
        let mut fvek = vec![0u8; self.encrypted_fvek.len()];
        for (i, (&c, &k)) in self.encrypted_fvek.iter().zip(candidate_vmk.iter().cycle()).enumerate() {
            fvek[i] = c ^ k;
        }

        let cipher: Box<dyn SectorCipher> = match self.algorithm {
            BitLockerAlgorithm::AesXts256 => Box::new(Aes256XtsCipher::new(&fvek[..64])?),
            BitLockerAlgorithm::AesXts128 => Box::new(Aes128XtsCipher::new(&fvek[..32])?),
            BitLockerAlgorithm::AesCbc256 | BitLockerAlgorithm::AesCbc256Diffuser => {
                Box::new(AesCbcCipher::new(&fvek[..32])?)
            }
            BitLockerAlgorithm::AesCbc128 | BitLockerAlgorithm::AesCbc128Diffuser => {
                Box::new(AesCbcCipher::new(&fvek[..16])?)
            }
        };

        fvek.zeroize();
        Ok(cipher)
    }
}
