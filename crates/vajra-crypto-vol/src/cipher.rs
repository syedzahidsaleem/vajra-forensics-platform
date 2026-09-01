//! Sector cipher abstraction and Anti-Forensic merge algorithms (§16, §57).

use crate::error::CryptoVolError;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use xts_mode::Xts128;
use zeroize::Zeroize;

/// Common trait for sector-level ciphers (AES-XTS, AES-CBC).
pub trait SectorCipher: Send + Sync {
    fn decrypt_sector(&self, sector_lba: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoVolError>;
    fn cipher_name(&self) -> &str;
    fn key_bits(&self) -> u32;
}

/// AES-128-XTS sector cipher.
pub struct Aes128XtsCipher {
    xts: Xts128<Aes128>,
}

impl Aes128XtsCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoVolError> {
        if key.len() != 32 {
            return Err(CryptoVolError::KeyDerivationError(format!(
                "AES-128-XTS requires 32-byte key (got {})",
                key.len()
            )));
        }
        let cipher_1 = Aes128::new_from_slice(&key[0..16]).map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
        let cipher_2 = Aes128::new_from_slice(&key[16..32]).map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
        let xts = Xts128::new(cipher_1, cipher_2);
        Ok(Self { xts })
    }
}

impl SectorCipher for Aes128XtsCipher {
    fn decrypt_sector(&self, sector_lba: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoVolError> {
        if ciphertext.len() != plaintext.len() || ciphertext.len() % 16 != 0 {
            return Err(CryptoVolError::DecryptionError {
                lba: sector_lba,
                reason: format!("Ciphertext length {} is not a multiple of 16", ciphertext.len()),
            });
        }

        plaintext.copy_from_slice(ciphertext);
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&sector_lba.to_le_bytes());

        self.xts.decrypt_area(plaintext, ciphertext.len(), 0, |_| tweak);

        Ok(())
    }

    fn cipher_name(&self) -> &str {
        "aes-xts-plain64"
    }

    fn key_bits(&self) -> u32 {
        128
    }
}

/// AES-256-XTS sector cipher.
pub struct Aes256XtsCipher {
    xts: Xts128<Aes256>,
}

impl Aes256XtsCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoVolError> {
        if key.len() != 64 {
            return Err(CryptoVolError::KeyDerivationError(format!(
                "AES-256-XTS requires 64-byte key (got {})",
                key.len()
            )));
        }
        let cipher_1 = Aes256::new_from_slice(&key[0..32]).map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
        let cipher_2 = Aes256::new_from_slice(&key[32..64]).map_err(|e| CryptoVolError::KeyDerivationError(e.to_string()))?;
        let xts = Xts128::new(cipher_1, cipher_2);
        Ok(Self { xts })
    }
}

impl SectorCipher for Aes256XtsCipher {
    fn decrypt_sector(&self, sector_lba: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoVolError> {
        if ciphertext.len() != plaintext.len() || ciphertext.len() % 16 != 0 {
            return Err(CryptoVolError::DecryptionError {
                lba: sector_lba,
                reason: format!("Ciphertext length {} is not a multiple of 16", ciphertext.len()),
            });
        }

        plaintext.copy_from_slice(ciphertext);
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&sector_lba.to_le_bytes());

        self.xts.decrypt_area(plaintext, ciphertext.len(), 0, |_| tweak);

        Ok(())
    }

    fn cipher_name(&self) -> &str {
        "aes-xts-plain64"
    }

    fn key_bits(&self) -> u32 {
        256
    }
}

/// AES-CBC sector cipher (BitLocker legacy mode).
pub struct AesCbcCipher {
    key: Vec<u8>,
    is_256: bool,
}

impl AesCbcCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoVolError> {
        match key.len() {
            16 => Ok(Self { key: key.to_vec(), is_256: false }),
            32 => Ok(Self { key: key.to_vec(), is_256: true }),
            other => Err(CryptoVolError::KeyDerivationError(format!(
                "AES-CBC requires 16 or 32-byte key (got {})",
                other
            ))),
        }
    }
}

impl SectorCipher for AesCbcCipher {
    fn decrypt_sector(&self, sector_lba: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoVolError> {
        if ciphertext.len() != plaintext.len() || ciphertext.len() % 16 != 0 {
            return Err(CryptoVolError::DecryptionError {
                lba: sector_lba,
                reason: "Invalid ciphertext alignment".to_string(),
            });
        }

        // IV derived from sector LBA (AES-CBC plain64)
        let mut iv = [0u8; 16];
        iv[0..8].copy_from_slice(&sector_lba.to_le_bytes());

        if self.is_256 {
            let cipher = Aes256::new_from_slice(&self.key).map_err(|e| CryptoVolError::DecryptionError {
                lba: sector_lba,
                reason: e.to_string(),
            })?;
            let mut prev_block = iv;
            for chunk in ciphertext.chunks(16).zip(plaintext.chunks_mut(16)) {
                let (ct_block, pt_block) = chunk;
                let mut block = *aes::Block::from_slice(ct_block);
                cipher.decrypt_block(&mut block);
                for (p, (&b, &iv_b)) in pt_block.iter_mut().zip(block.iter().zip(prev_block.iter())) {
                    *p = b ^ iv_b;
                }
                prev_block.copy_from_slice(ct_block);
            }
        } else {
            let cipher = Aes128::new_from_slice(&self.key).map_err(|e| CryptoVolError::DecryptionError {
                lba: sector_lba,
                reason: e.to_string(),
            })?;
            let mut prev_block = iv;
            for chunk in ciphertext.chunks(16).zip(plaintext.chunks_mut(16)) {
                let (ct_block, pt_block) = chunk;
                let mut block = *aes::Block::from_slice(ct_block);
                cipher.decrypt_block(&mut block);
                for (p, (&b, &iv_b)) in pt_block.iter_mut().zip(block.iter().zip(prev_block.iter())) {
                    *p = b ^ iv_b;
                }
                prev_block.copy_from_slice(ct_block);
            }
        }

        Ok(())
    }

    fn cipher_name(&self) -> &str {
        if self.is_256 { "aes-cbc-plain64-256" } else { "aes-cbc-plain64-128" }
    }

    fn key_bits(&self) -> u32 {
        if self.is_256 { 256 } else { 128 }
    }
}

/// Anti-Forensic Splitter forward split (used for testing and creation).
pub fn af_split(key: &[u8], stripes: usize, use_sha256: bool) -> Vec<u8> {
    let key_bytes = key.len();
    let mut split_data = vec![0u8; stripes * key_bytes];
    let mut buf = vec![0u8; key_bytes];

    for i in 0..(stripes - 1) {
        let chunk = &mut split_data[i * key_bytes..(i + 1) * key_bytes];
        for (j, b) in chunk.iter_mut().enumerate() {
            *b = ((i * 37 + j * 13 + 7) % 256) as u8;
        }
        for (b, &s) in buf.iter_mut().zip(chunk.iter()) {
            *b ^= s;
        }

        let mut hash_buf = vec![0u8; key_bytes];
        let hash_len = if use_sha256 { 32 } else { 20 };
        let num_blocks = (key_bytes + hash_len - 1) / hash_len;

        for block_num in 0..num_blocks {
            let iv = ((i * num_blocks + block_num) as u32).to_be_bytes();
            let take = (key_bytes - block_num * hash_len).min(hash_len);
            if use_sha256 {
                let mut hasher = Sha256::new();
                hasher.update(&iv);
                hasher.update(&buf);
                let digest = hasher.finalize();
                hash_buf[block_num * hash_len..block_num * hash_len + take].copy_from_slice(&digest[..take]);
            } else {
                let mut hasher = Sha1::new();
                hasher.update(&iv);
                hasher.update(&buf);
                let digest = hasher.finalize();
                hash_buf[block_num * hash_len..block_num * hash_len + take].copy_from_slice(&digest[..take]);
            }
        }
        buf.copy_from_slice(&hash_buf);
    }

    let last_chunk = &mut split_data[(stripes - 1) * key_bytes..stripes * key_bytes];
    for (last_b, (&b_val, &k_val)) in last_chunk.iter_mut().zip(buf.iter().zip(key.iter())) {
        *last_b = b_val ^ k_val;
    }

    split_data
}

/// Anti-Forensic Splitter inverse (AFMerge) for LUKS1/LUKS2.
pub fn af_merge(
    split_data: &[u8],
    key_bytes: usize,
    stripes: usize,
    use_sha256: bool,
    out_key: &mut [u8],
) -> Result<(), CryptoVolError> {
    if split_data.len() < stripes * key_bytes {
        return Err(CryptoVolError::InvalidHeader(format!(
            "AFSplit buffer too small: expected {} bytes, got {}",
            stripes * key_bytes,
            split_data.len()
        )));
    }
    if out_key.len() < key_bytes {
        return Err(CryptoVolError::KeyDerivationError("Output buffer too small for key".to_string()));
    }

    let mut buf = vec![0u8; key_bytes];
    let mut hash_buf = vec![0u8; key_bytes];
    let hash_len = if use_sha256 { 32 } else { 20 };
    let num_blocks = (key_bytes + hash_len - 1) / hash_len;

    for i in 0..stripes {
        let src = &split_data[i * key_bytes..(i + 1) * key_bytes];
        for (b, &s) in buf.iter_mut().zip(src.iter()) {
            *b ^= s;
        }

        if i + 1 < stripes {
            for block_num in 0..num_blocks {
                let iv = ((i * num_blocks + block_num) as u32).to_be_bytes();
                let take = (key_bytes - block_num * hash_len).min(hash_len);
                if use_sha256 {
                    let mut hasher = Sha256::new();
                    hasher.update(&iv);
                    hasher.update(&buf);
                    let digest = hasher.finalize();
                    hash_buf[block_num * hash_len..block_num * hash_len + take].copy_from_slice(&digest[..take]);
                } else {
                    let mut hasher = Sha1::new();
                    hasher.update(&iv);
                    hasher.update(&buf);
                    let digest = hasher.finalize();
                    hash_buf[block_num * hash_len..block_num * hash_len + take].copy_from_slice(&digest[..take]);
                }
            }
            buf.copy_from_slice(&hash_buf);
        }
    }

    out_key[..key_bytes].copy_from_slice(&buf);
    buf.zeroize();
    hash_buf.zeroize();

    Ok(())
}

