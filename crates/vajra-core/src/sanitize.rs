//! Sanitization methods and commands.
//!
//! Enumerates NIST SP 800-88 Rev. 1 and IEEE 2883-2022 sanitization primitives (§33a–§35).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Sanitization method supported by storage hardware or software overwrite engines.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizeMethod {
    /// ATA SECURITY ERASE UNIT (Normal mode).
    AtaSecureErase,
    /// ATA SECURITY ERASE UNIT (Enhanced mode - clears reallocated blocks).
    AtaEnhancedSecureErase,
    /// NVMe Sanitize command with Block Erase (SANACT = 0x02).
    NvmeSanitizeBlock,
    /// NVMe Sanitize command with Crypto Erase (SANACT = 0x04).
    NvmeSanitizeCrypto,
    /// NVMe Format NVM command with User Data Erase.
    NvmeFormat,
    /// TCG Opal / Enterprise cryptographic key invalidation (Cryptographic Erase).
    CryptographicErase,
    /// Single-pass host-level logical overwrite (NIST 800-88 Clear).
    HostOverwriteSinglePass,
    /// Multi-pass host-level logical overwrite (e.g. DoD 5220.22-M, 3 passes).
    HostOverwriteMultiPass { passes: u32 },
    /// SCSI / SAS Sanitize command with Overwrite.
    ScsiSanitizeOverwrite,
    /// SCSI / SAS Sanitize command with Cryptographic Erase.
    ScsiSanitizeCrypto,
}

impl fmt::Display for SanitizeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SanitizeMethod::AtaSecureErase => write!(f, "ATA Secure Erase"),
            SanitizeMethod::AtaEnhancedSecureErase => write!(f, "ATA Enhanced Secure Erase"),
            SanitizeMethod::NvmeSanitizeBlock => write!(f, "NVMe Sanitize (Block Erase)"),
            SanitizeMethod::NvmeSanitizeCrypto => write!(f, "NVMe Sanitize (Crypto Erase)"),
            SanitizeMethod::NvmeFormat => write!(f, "NVMe Format (User Data Erase)"),
            SanitizeMethod::CryptographicErase => write!(f, "Cryptographic Erase (TCG/SED)"),
            SanitizeMethod::HostOverwriteSinglePass => write!(f, "Host Overwrite (1 pass - NIST Clear)"),
            SanitizeMethod::HostOverwriteMultiPass { passes } => write!(f, "Host Overwrite ({passes} passes)"),
            SanitizeMethod::ScsiSanitizeOverwrite => write!(f, "SCSI Sanitize (Overwrite)"),
            SanitizeMethod::ScsiSanitizeCrypto => write!(f, "SCSI Sanitize (Crypto Erase)"),
        }
    }
}
