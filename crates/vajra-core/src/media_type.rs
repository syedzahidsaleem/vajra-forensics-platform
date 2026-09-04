//! Media type classification for physical and virtual storage.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification of the underlying storage medium.
///
/// Used by the sanitization decision engine (§33a, §35) and recovery pipeline (§25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaType {
    /// Magnetic hard disk drive with spinning platters.
    Hdd,
    /// Solid state drive over Serial ATA (SATA).
    SataSsd,
    /// Solid state drive over NVM Express (NVMe / PCIe).
    Nvme,
    /// Self-Encrypting Drive (SED / TCG Opal / Enterprise).
    Sed,
    /// USB flash memory drive / thumb drive.
    Usb,
    /// Secure Digital (SD / microSD) card.
    SdCard,
    /// Forensic disk image file on local storage (RAW/DD, E01, AFF4).
    ForensicImage,
}

impl MediaType {
    /// Returns true if the medium is flash/solid-state based.
    pub fn is_solid_state(&self) -> bool {
        matches!(self, MediaType::SataSsd | MediaType::Nvme | MediaType::Sed | MediaType::Usb | MediaType::SdCard)
    }

    /// Returns true if the medium is a virtual forensic disk image.
    pub fn is_image(&self) -> bool {
        matches!(self, MediaType::ForensicImage)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaType::Hdd => write!(f, "HDD (Magnetic)"),
            MediaType::SataSsd => write!(f, "SATA SSD"),
            MediaType::Nvme => write!(f, "NVMe SSD"),
            MediaType::Sed => write!(f, "Self-Encrypting Drive (SED)"),
            MediaType::Usb => write!(f, "USB Flash Drive"),
            MediaType::SdCard => write!(f, "SD/microSD Card"),
            MediaType::ForensicImage => write!(f, "Forensic Disk Image"),
        }
    }
}
