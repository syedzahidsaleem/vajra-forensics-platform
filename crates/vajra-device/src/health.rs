//! Storage device health diagnostics and SMART/NVMe log parsing (§23).
//!
//! Implements SMART attribute extraction for HDDs/SATA SSDs and NVMe Health Information Log
//! parsing with calibrated threshold analysis and plain-language recommendations.

use serde::{Deserialize, Serialize};
use std::fmt;
use vajra_core::MediaType;

/// Overall operational health status of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Device is operating within nominal parameters.
    Good,
    /// Device shows degradation (e.g. reallocated sectors, elevated wear, high temperature).
    Warning,
    /// Severe hardware failure or imminent data loss predicted.
    Critical,
    /// Health diagnostics could not be queried or are not supported on this interface.
    Unknown,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Good => write!(f, "GOOD"),
            HealthStatus::Warning => write!(f, "WARNING"),
            HealthStatus::Critical => write!(f, "CRITICAL"),
            HealthStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// A parsed ATA SMART attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartAttribute {
    pub id: u8,
    pub name: String,
    pub current: u8,
    pub worst: u8,
    pub threshold: u8,
    pub raw_value: u64,
    pub failing_now: bool,
}

/// Detailed NVMe SMART / Health Information Log fields per NVMe Base Specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeHealthInfo {
    /// Critical warning bitmask (0 = normal; bit 0 = spare below threshold, bit 1 = temperature threshold).
    pub critical_warnings: u8,
    /// Composite temperature in degrees Celsius.
    pub temperature_celsius: i32,
    /// Normalized percentage of remaining spare capacity (0–100%).
    pub available_spare_percent: u8,
    /// Available spare threshold percentage (typically 10%).
    pub available_spare_threshold: u8,
    /// Percentage of drive life used (0–100%, can exceed 100% when worn past rated endurance).
    pub percentage_used: u8,
    /// Total data units read (in 512,000-byte units).
    pub data_units_read: u128,
    /// Total data units written (in 512,000-byte units).
    pub data_units_written: u128,
    /// Total host read commands issued.
    pub host_read_commands: u128,
    /// Total host write commands issued.
    pub host_write_commands: u128,
    /// Controller busy time in minutes.
    pub controller_busy_time_minutes: u128,
    /// Number of power cycles.
    pub power_cycles: u128,
    /// Number of power-on hours.
    pub power_on_hours: u128,
    /// Number of unsafe (unclean) shutdowns.
    pub unsafe_shutdowns: u128,
    /// Number of unrecovered media and data integrity errors.
    pub media_errors: u128,
    /// Number of Error Information Log entries.
    pub error_log_entries: u128,
}

/// Key HDD health diagnostic indicators (§23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HddHealthInfo {
    /// Sector count reallocated to spare pool (SMART ID 0x05).
    pub reallocated_sectors: u64,
    /// Unstable sectors waiting for reallocation (SMART ID 0xC5 / 197).
    pub pending_sectors: u64,
    /// Uncorrectable read errors (SMART ID 0xC6 / 198).
    pub uncorrectable_sectors: u64,
    /// Cumulative power-on hours (SMART ID 0x09).
    pub power_on_hours: u64,
    /// Current drive temperature in degrees Celsius.
    pub temperature_celsius: i32,
    /// Raw read error rate (SMART ID 0x01).
    pub raw_read_error_rate: u64,
}

/// Host Protected Area (HPA) and Device Configuration Overlay (DCO) diagnostic details (§35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpaDcoInfo {
    /// True if Host Protected Area is detected.
    pub hpa_detected: bool,
    /// True if Device Configuration Overlay is detected.
    pub dco_detected: bool,
    /// User-addressable max LBA capacity reported to OS.
    pub user_lba_capacity: u64,
    /// Native factory maximum LBA capacity returned by hardware IDENTIFY command.
    pub native_max_lba: u64,
    /// Total hidden sectors (native_max_lba - user_lba_capacity).
    pub hidden_sectors: u64,
}

/// Complete diagnostic health report for a storage device (§23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceHealth {
    /// Overall health status.
    pub status: HealthStatus,
    /// Media type classification.
    pub media_type: MediaType,
    /// Raw SMART attributes (if available).
    pub smart_attributes: Vec<SmartAttribute>,
    /// Parsed NVMe health metrics (if NVMe).
    pub nvme_health: Option<NvmeHealthInfo>,
    /// Key HDD diagnostic metrics (if HDD/SATA).
    pub hdd_health: Option<HddHealthInfo>,
    /// Host Protected Area / DCO status (§35).
    pub hpa_dco_info: Option<HpaDcoInfo>,
    /// Plain-language forensic / operational recommendation (§23).
    pub recommendation: String,
}

impl DeviceHealth {
    /// Evaluates diagnostic signals against calibrated thresholds (§23) to compute health status and guidance.
    ///
    /// # Threshold Rationale
    ///
    /// ## HDD Thresholds:
    /// - **Critical**: `uncorrectable_sectors > 0` OR `pending_sectors > 5` OR `reallocated_sectors > 50`.
    ///   Uncorrectable and high pending sector counts indicate active surface deterioration or head instability.
    ///   Direct exploratory reads pose a severe risk of permanent media failure. Immediate imaging is advised.
    /// - **Warning**: `pending_sectors > 0` OR `reallocated_sectors > 0` OR `temperature > 55°C`.
    ///   Any reallocated sector demonstrates that original factory spare blocks have been consumed.
    /// - **Good**: Zero reallocated/pending/uncorrectable sectors and nominal temperature.
    ///
    /// ## NVMe Thresholds:
    /// - **Critical**: `critical_warnings != 0` OR `available_spare < 10%` OR `media_errors > 10`.
    ///   Controller critical warnings flag hardware reliability events or read-only trip conditions.
    /// - **Warning**: `available_spare < 20%` OR `percentage_used > 95%` OR `media_errors > 0` OR `temperature > 70°C`.
    /// - **Good**: All reliability counters clean and spare percentage healthy (>80%).
    pub fn evaluate(
        media_type: MediaType,
        nvme_health: Option<NvmeHealthInfo>,
        hdd_health: Option<HddHealthInfo>,
        hpa_dco_info: Option<HpaDcoInfo>,
        smart_attributes: Vec<SmartAttribute>,
    ) -> Self {
        // NVMe Evaluation
        if let Some(ref nvme) = nvme_health {
            let mut status = HealthStatus::Good;
            let mut recommendation = "NVMe drive health indicators are within nominal operational parameters.".to_string();

            if nvme.critical_warnings != 0 || nvme.available_spare_percent < 10 || nvme.media_errors > 10 {
                status = HealthStatus::Critical;
                recommendation = "CRITICAL: Imminent hardware failure or severe reliability degradation detected. Available spare pool exhausted or media integrity errors present. Acquire a forensic image immediately; avoid sustained write operations.".to_string();
            } else if nvme.available_spare_percent < 20 || nvme.percentage_used >= 95 || nvme.media_errors > 0 || nvme.temperature_celsius >= 70 {
                status = HealthStatus::Warning;
                recommendation = "WARNING: NVMe drive wear or spare exhaustion detected. Monitor closely and prioritize forensic imaging.".to_string();
            }

            return Self {
                status,
                media_type,
                smart_attributes,
                nvme_health,
                hdd_health,
                hpa_dco_info,
                recommendation,
            };
        }

        // HDD Evaluation
        if let Some(ref hdd) = hdd_health {
            let mut status = HealthStatus::Good;
            let mut recommendation = "Drive health indicators are within nominal operational parameters.".to_string();

            if hdd.uncorrectable_sectors > 0 || hdd.pending_sectors > 5 || hdd.reallocated_sectors > 50 {
                status = HealthStatus::Critical;
                recommendation = "CRITICAL: Severe hardware degradation detected (uncorrectable or excessive pending sectors). Acquire a forensic image immediately with hardware write protection; halt non-essential reads.".to_string();
            } else if hdd.pending_sectors > 0 || hdd.reallocated_sectors > 0 {
                status = HealthStatus::Warning;
                recommendation = "Acquire a forensic image immediately; minimize further direct reads.".to_string();
            } else if hdd.temperature_celsius >= 55 {
                status = HealthStatus::Warning;
                recommendation = "Drive temperature is elevated. Ensure adequate cooling before sustained I/O operations.".to_string();
            }

            return Self {
                status,
                media_type,
                smart_attributes,
                nvme_health,
                hdd_health,
                hpa_dco_info,
                recommendation,
            };
        }

        // Default / Unknown
        Self {
            status: HealthStatus::Unknown,
            media_type,
            smart_attributes,
            nvme_health,
            hdd_health,
            hpa_dco_info,
            recommendation: "SMART / Health diagnostics not available or unsupported for this device interface.".to_string(),
        }
    }
}

impl fmt::Display for DeviceHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DEVICE HEALTH")?;
        writeln!(f, "Status: {}", self.status)?;

        if let Some(ref hdd) = self.hdd_health {
            writeln!(
                f,
                "Reallocated sectors: {}   Pending sectors: {}   Uncorrectable sectors: {}",
                hdd.reallocated_sectors, hdd.pending_sectors, hdd.uncorrectable_sectors
            )?;
            if hdd.temperature_celsius > 0 {
                writeln!(f, "Temperature: {}°C   Power-On Hours: {}", hdd.temperature_celsius, hdd.power_on_hours)?;
            }
        } else if let Some(ref nvme) = self.nvme_health {
            writeln!(
                f,
                "Available Spare: {}%   Percentage Used: {}%   Media Errors: {}",
                nvme.available_spare_percent, nvme.percentage_used, nvme.media_errors
            )?;
            writeln!(
                f,
                "Temperature: {}°C   Power Cycles: {}   Power-On Hours: {}",
                nvme.temperature_celsius, nvme.power_cycles, nvme.power_on_hours
            )?;
            if nvme.critical_warnings != 0 {
                writeln!(f, "Critical Warnings Bitmask: {:#04x}", nvme.critical_warnings)?;
            }
        }

        if let Some(ref hpa) = self.hpa_dco_info {
            if hpa.hpa_detected || hpa.dco_detected {
                writeln!(
                    f,
                    "HPA/DCO Hidden Sectors: {} (User Max LBA: {}, Native Max LBA: {})",
                    hpa.hidden_sectors, hpa.user_lba_capacity, hpa.native_max_lba
                )?;
            }
        }

        write!(f, "Recommendation: {}", self.recommendation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdd_health_warning_threshold() {
        let hdd = HddHealthInfo {
            reallocated_sectors: 24,
            pending_sectors: 7,
            uncorrectable_sectors: 2,
            power_on_hours: 14200,
            temperature_celsius: 38,
            raw_read_error_rate: 0,
        };

        let health = DeviceHealth::evaluate(MediaType::Hdd, None, Some(hdd), None, vec![]);
        assert_eq!(health.status, HealthStatus::Critical);
        assert!(health.recommendation.contains("Severe hardware degradation"));

        // Warning case
        let hdd_warn = HddHealthInfo {
            reallocated_sectors: 5,
            pending_sectors: 0,
            uncorrectable_sectors: 0,
            power_on_hours: 5000,
            temperature_celsius: 35,
            raw_read_error_rate: 0,
        };
        let health_warn = DeviceHealth::evaluate(MediaType::Hdd, None, Some(hdd_warn), None, vec![]);
        assert_eq!(health_warn.status, HealthStatus::Warning);
        assert_eq!(health_warn.recommendation, "Acquire a forensic image immediately; minimize further direct reads.");
    }

    #[test]
    fn test_nvme_health_thresholds() {
        let nvme_crit = NvmeHealthInfo {
            critical_warnings: 1, // spare below threshold
            temperature_celsius: 45,
            available_spare_percent: 5,
            available_spare_threshold: 10,
            percentage_used: 85,
            data_units_read: 1000,
            data_units_written: 1000,
            host_read_commands: 5000,
            host_write_commands: 5000,
            controller_busy_time_minutes: 100,
            power_cycles: 50,
            power_on_hours: 1200,
            unsafe_shutdowns: 2,
            media_errors: 15,
            error_log_entries: 2,
        };
        let health = DeviceHealth::evaluate(MediaType::Nvme, Some(nvme_crit), None, None, vec![]);
        assert_eq!(health.status, HealthStatus::Critical);
    }
}
