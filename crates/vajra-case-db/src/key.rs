//! Database key management with Argon2id and Zeroize (§17, §44).

use crate::error::DbError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit database encryption key, securely zeroed on drop (§17, §44).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DatabaseKey {
    key_material: [u8; 32],
}

impl std::fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DatabaseKey([REDACTED])")
    }
}

impl DatabaseKey {
    /// Creates a key from raw 256-bit entropy.
    pub fn from_raw(key_bytes: [u8; 32]) -> Self {
        Self {
            key_material: key_bytes,
        }
    }

    pub const DEFAULT_SALT: &'static [u8] = b"vajra_vault_salt_v1";

    /// Derives a 256-bit database key from a passphrase using Argon2id (§17, §44).
    ///
    /// Uses standard parameters (Memory: 64MB, Iterations: 3, Parallelism: 1)
    /// suitable for forensic workstation security.
    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Self, DbError> {
        if salt.len() < 8 {
            return Err(DbError::KeyError(
                "Salt must be at least 8 bytes in length for Argon2id key derivation".to_string(),
            ));
        }

        let mut key_material = [0u8; 32];
        let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|e| DbError::KeyError(format!("Argon2id params error: {}", e)))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_material)
            .map_err(|e| DbError::KeyError(format!("Argon2id derivation failed: {}", e)))?;

        Ok(Self { key_material })
    }

    /// Derives the default forensic workstation station key when no explicit key is supplied.
    pub fn default_station_key() -> Self {
        Self::from_passphrase("vajra_default_forensic_station_key_offline", Self::DEFAULT_SALT)
            .expect("Default station key derivation must succeed")
    }

    /// Returns a slice of the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_material
    }

    /// Returns the hex-encoded representation of the key (for SQLCipher PRAGMA key string).
    pub fn as_hex(&self) -> String {
        hex::encode(self.key_material)
    }
}
