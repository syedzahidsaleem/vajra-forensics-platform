//! Storage device fingerprinting.
//!
//! Provides deterministic SHA-256 fingerprint derivation per Technical Blueprint §23.
//!
//! The fingerprint is derived from stable identity attributes (serial, model, capacity)
//! plus a boundary-sector sample, NOT the device's full data.
//! Note: `interface` is excluded from the hash input so adapter/bridge changes across sessions
//! do not alter the identity hash, but is retained on `DeviceFingerprint` for display.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Unique hardware identity fingerprint for a storage device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// Manufacturer name (e.g. "Samsung", "Western Digital").
    pub manufacturer: String,
    /// Hardware model identifier (e.g. "SSD 980 PRO 1TB").
    pub model: String,
    /// Hardware serial number (e.g. "S5GXNF0R123456").
    pub serial: String,
    /// Total capacity in bytes.
    pub capacity_bytes: u64,
    /// Hardware interface type (e.g. "NVMe", "SATA", "USB"). Display only.
    pub interface: String,
    /// Hex-encoded SHA-256 fingerprint hash.
    pub sha256_hash: String,
}

impl DeviceFingerprint {
    /// Computes the deterministic SHA-256 device fingerprint per §23.
    ///
    /// The hash input comprises:
    /// 1. Normalized Serial Number (trimmed, uppercase)
    /// 2. Normalized Model Name (trimmed, uppercase)
    /// 3. Total capacity in bytes (64-bit little-endian)
    /// 4. Boundary sector sample bytes (first and/or last sector data)
    ///
    /// `interface` is intentionally excluded from the hash computation to ensure stability
    /// if a drive is moved between direct SATA/NVMe connections and USB bridge enclosures.
    pub fn compute(
        manufacturer: &str,
        model: &str,
        serial: &str,
        capacity_bytes: u64,
        interface: &str,
        boundary_sample: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();

        // 1. Serial (normalized uppercase, trimmed)
        let norm_serial = serial.trim().to_uppercase();
        hasher.update((norm_serial.len() as u32).to_le_bytes());
        hasher.update(norm_serial.as_bytes());

        // 2. Model (normalized uppercase, trimmed)
        let norm_model = model.trim().to_uppercase();
        hasher.update((norm_model.len() as u32).to_le_bytes());
        hasher.update(norm_model.as_bytes());

        // 3. Capacity bytes (little-endian u64)
        hasher.update(capacity_bytes.to_le_bytes());

        // 4. Boundary sample (length-prefixed)
        hasher.update((boundary_sample.len() as u32).to_le_bytes());
        hasher.update(boundary_sample);

        let hash_bytes = hasher.finalize();
        let sha256_hash = hex::encode(hash_bytes);

        Self {
            manufacturer: manufacturer.trim().to_string(),
            model: model.trim().to_string(),
            serial: serial.trim().to_string(),
            capacity_bytes,
            interface: interface.trim().to_string(),
            sha256_hash,
        }
    }
}

impl fmt::Display for DeviceFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Manufacturer: {}  Model: {}
Serial: {}  Capacity: {} bytes
Interface: {}
Fingerprint (SHA-256): {}",
            self.manufacturer, self.model, self.serial, self.capacity_bytes, self.interface, self.sha256_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_determinism() {
        let sample = [0x55u8; 512];
        let fp1 = DeviceFingerprint::compute("Samsung", "980 PRO", "S5GX123456", 1_000_204_886_016, "NVMe", &sample);
        let fp2 = DeviceFingerprint::compute("Samsung", "980 PRO", "S5GX123456", 1_000_204_886_016, "NVMe", &sample);
        assert_eq!(fp1.sha256_hash, fp2.sha256_hash);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_interface_invariance() {
        // Interface should not change the SHA-256 hash
        let sample = [0xAAu8; 512];
        let fp_nvme = DeviceFingerprint::compute("Crucial", "CT1000P3SSD8", "2245E67890", 1_000_000_000_000, "NVMe", &sample);
        let fp_usb = DeviceFingerprint::compute("Crucial", "CT1000P3SSD8", "2245E67890", 1_000_000_000_000, "USB-to-NVMe Bridge", &sample);

        assert_eq!(fp_nvme.sha256_hash, fp_usb.sha256_hash);
        assert_ne!(fp_nvme.interface, fp_usb.interface);
    }

    #[test]
    fn test_fingerprint_sensitivity_to_serial() {
        let sample = [0u8; 512];
        let fp1 = DeviceFingerprint::compute("WD", "WD10EZEX", "WD-WCC4N1234567", 1_000_000_000_000, "SATA", &sample);
        let fp2 = DeviceFingerprint::compute("WD", "WD10EZEX", "WD-WCC4N1234568", 1_000_000_000_000, "SATA", &sample);
        assert_ne!(fp1.sha256_hash, fp2.sha256_hash);
    }

    #[test]
    fn test_fingerprint_sensitivity_to_model() {
        let sample = [0u8; 512];
        let fp1 = DeviceFingerprint::compute("WD", "WD10EZEX", "WD-WCC4N1234567", 1_000_000_000_000, "SATA", &sample);
        let fp2 = DeviceFingerprint::compute("WD", "WD20EZEX", "WD-WCC4N1234567", 1_000_000_000_000, "SATA", &sample);
        assert_ne!(fp1.sha256_hash, fp2.sha256_hash);
    }

    #[test]
    fn test_fingerprint_sensitivity_to_capacity() {
        let sample = [0u8; 512];
        let fp1 = DeviceFingerprint::compute("Seagate", "ST1000DM010", "Z9A12345", 1_000_000_000_000, "SATA", &sample);
        let fp2 = DeviceFingerprint::compute("Seagate", "ST1000DM010", "Z9A12345", 2_000_000_000_000, "SATA", &sample);
        assert_ne!(fp1.sha256_hash, fp2.sha256_hash);
    }

    #[test]
    fn test_fingerprint_sensitivity_to_boundary_sample() {
        let sample1 = [0x00u8; 512];
        let mut sample2 = [0x00u8; 512];
        sample2[510] = 0x55;
        sample2[511] = 0xAA; // MBR signature

        let fp1 = DeviceFingerprint::compute("Seagate", "ST1000DM010", "Z9A12345", 1_000_000_000_000, "SATA", &sample1);
        let fp2 = DeviceFingerprint::compute("Seagate", "ST1000DM010", "Z9A12345", 1_000_000_000_000, "SATA", &sample2);
        assert_ne!(fp1.sha256_hash, fp2.sha256_hash);
    }

    #[test]
    fn test_fingerprint_whitespace_and_case_normalization() {
        let sample = [0x12u8; 64];
        let fp1 = DeviceFingerprint::compute("Samsung", "  980 pro  ", "  s5gx123456  ", 1_000_000_000_000, "NVMe", &sample);
        let fp2 = DeviceFingerprint::compute("Samsung", "980 PRO", "S5GX123456", 1_000_000_000_000, "NVMe", &sample);
        assert_eq!(fp1.sha256_hash, fp2.sha256_hash);
    }
}
