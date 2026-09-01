//! Sanitization Decision Engine (§34).
//!
//! Implements the verbatim decision flowchart and reasoning output specified in
//! Vajra Master Technical Document §34, providing inspectable, defensible sanitization
//! recommendations based on media type, self-encryption status, and controller features.

use serde::{Deserialize, Serialize};
use vajra_core::MediaType;
use vajra_core::SanitizeMethod;
use vajra_device::DeviceDescriptor;

/// Structured recommendation output from the Sanitization Decision Engine (§34).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationRecommendation {
    pub device_summary: String,
    pub media_type: MediaType,
    pub is_sed: bool,
    pub recommended_method: SanitizeMethod,
    pub recommended_label: String,
    pub reason: String,
    pub alternative_available: Option<String>,
    pub not_recommended: Option<String>,
    pub residual_risk_warning: Option<String>,
}

impl SanitizationRecommendation {
    /// Renders the recommendation matching the verbatim output format in §34.
    pub fn render_display(&self) -> String {
        let mut out = String::new();
        out.push_str("RECOMMENDED SANITIZATION\n");
        out.push_str(&format!("Device: {}\n", self.device_summary));
        out.push_str(&format!("Recommended: {}\n", self.recommended_label));
        out.push_str(&format!("Reason: {}\n", self.reason));

        if let Some(ref alt) = self.alternative_available {
            out.push_str(&format!("Alternative available: {}\n", alt));
        }

        if let Some(ref not_rec) = self.not_recommended {
            out.push_str(&format!("Not recommended: {}\n", not_rec));
        }

        if let Some(ref risk) = self.residual_risk_warning {
            out.push_str(&format!("\n[RESIDUAL RISK WARNING (§33a)]\n{}\n", risk));
        }

        out
    }
}

/// Sanitization Decision Engine (§34).
pub struct SanitizationDecisionEngine;

impl SanitizationDecisionEngine {
    /// Evaluates device characteristics and hardware capabilities to generate a defensible recommendation (§34).
    pub fn recommend(
        device: &DeviceDescriptor,
        supported_methods: &[SanitizeMethod],
    ) -> SanitizationRecommendation {
        let is_sed = device.media_type == MediaType::Sed
            || supported_methods.contains(&SanitizeMethod::CryptographicErase);

        let device_summary = format!(
            "{} {} | Media: {} | Interface: {} | Self-encrypting: {} | Capacity: {:.2} GB",
            device.manufacturer,
            device.model,
            device.media_type,
            device.interface,
            if is_sed { "Yes" } else { "No" },
            device.capacity_bytes as f64 / 1_000_000_000.0
        );

        // Step 1: Self-Encrypting Drive (SED) -> Cryptographic Erase (§34, §35)
        if is_sed && supported_methods.contains(&SanitizeMethod::CryptographicErase) {
            return SanitizationRecommendation {
                device_summary,
                media_type: device.media_type,
                is_sed: true,
                recommended_method: SanitizeMethod::CryptographicErase,
                recommended_label: "Cryptographic erase (TCG Opal PSID Revert)".to_string(),
                reason: "Self-encrypting drive supports controller-native key destruction, which sidesteps flash-translation-layer limitations entirely and completes in under one second with mathematically irreversible assurance.".to_string(),
                alternative_available: if supported_methods.contains(&SanitizeMethod::NvmeSanitizeBlock) {
                    Some("NVMe Sanitize (Block Erase) — slower, also controller-native.".to_string())
                } else if supported_methods.contains(&SanitizeMethod::AtaEnhancedSecureErase) {
                    Some("ATA Enhanced Secure Erase — slower, also controller-native.".to_string())
                } else {
                    None
                },
                not_recommended: Some("Host-level overwrite — cannot reach over-provisioned/spare cells.".to_string()),
                residual_risk_warning: None,
            };
        }

        // Step 2: NVMe SSD with Sanitize command support (§34, §35)
        if device.media_type == MediaType::Nvme {
            if supported_methods.contains(&SanitizeMethod::NvmeSanitizeBlock) {
                return SanitizationRecommendation {
                    device_summary,
                    media_type: device.media_type,
                    is_sed: false,
                    recommended_method: SanitizeMethod::NvmeSanitizeBlock,
                    recommended_label: "NVMe Sanitize (Block Erase)".to_string(),
                    reason: "NVMe controller-native Sanitize command purges all user data across all namespaces and physical NAND blocks, including reallocated and over-provisioned cells.".to_string(),
                    alternative_available: if supported_methods.contains(&SanitizeMethod::NvmeFormat) {
                        Some("NVMe Format (User Data Erase).".to_string())
                    } else {
                        None
                    },
                    not_recommended: Some("Host-level overwrite — cannot reach over-provisioned/spare cells.".to_string()),
                    residual_risk_warning: None,
                };
            } else if supported_methods.contains(&SanitizeMethod::NvmeFormat) {
                return SanitizationRecommendation {
                    device_summary,
                    media_type: device.media_type,
                    is_sed: false,
                    recommended_method: SanitizeMethod::NvmeFormat,
                    recommended_label: "NVMe Format (User Data Erase)".to_string(),
                    reason: "NVMe Format NVM command instructs the controller to erase user data across all active namespaces.".to_string(),
                    alternative_available: None,
                    not_recommended: Some("Host-level overwrite — cannot reach over-provisioned/spare cells.".to_string()),
                    residual_risk_warning: None,
                };
            }
        }

        // Step 3: SATA SSD with ATA Security feature set support (§34, §35)
        if device.media_type == MediaType::SataSsd {
            if supported_methods.contains(&SanitizeMethod::AtaEnhancedSecureErase) {
                return SanitizationRecommendation {
                    device_summary,
                    media_type: device.media_type,
                    is_sed: false,
                    recommended_method: SanitizeMethod::AtaEnhancedSecureErase,
                    recommended_label: "ATA Security Erase Unit (Enhanced Mode)".to_string(),
                    reason: "ATA Enhanced Secure Erase instructs the SSD controller to apply a vendor-defined erase pattern across all physical NAND cells, including wear-leveling and retired sector pools.".to_string(),
                    alternative_available: if supported_methods.contains(&SanitizeMethod::AtaSecureErase) {
                        Some("Standard ATA Secure Erase.".to_string())
                    } else {
                        None
                    },
                    not_recommended: Some("Host-level overwrite — cannot reach over-provisioned/spare cells.".to_string()),
                    residual_risk_warning: None,
                };
            } else if supported_methods.contains(&SanitizeMethod::AtaSecureErase) {
                return SanitizationRecommendation {
                    device_summary,
                    media_type: device.media_type,
                    is_sed: false,
                    recommended_method: SanitizeMethod::AtaSecureErase,
                    recommended_label: "ATA Security Erase Unit (Normal Mode)".to_string(),
                    reason: "ATA Secure Erase instructs the SSD controller to purge accessible user data areas.".to_string(),
                    alternative_available: None,
                    not_recommended: Some("Host-level overwrite — cannot reach over-provisioned/spare cells.".to_string()),
                    residual_risk_warning: None,
                };
            }
        }

        // Step 4: Magnetic HDD (§34, §35)
        if device.media_type == MediaType::Hdd {
            return SanitizationRecommendation {
                device_summary,
                media_type: device.media_type,
                is_sed: false,
                recommended_method: SanitizeMethod::HostOverwriteSinglePass,
                recommended_label: "NIST SP 800-88 Clear (Single-Pass Logical Overwrite)".to_string(),
                reason: "Magnetic HDD media is reliably cleared by single-pass logical overwrite across all addressable LBAs. Modern magnetic force microscopy cannot reconstruct overwritten PRML/EPRML tracks on post-2001 HDDs.".to_string(),
                alternative_available: Some("Multi-pass overwrite (DoD 5220.22-M 3-pass) for legacy policy compliance.".to_string()),
                not_recommended: None,
                residual_risk_warning: None,
            };
        }

        // Step 5: Fallback for USB / SD / Flash media without controller sanitize support (§33a, §34, §35)
        SanitizationRecommendation {
            device_summary,
            media_type: device.media_type,
            is_sed: false,
            recommended_method: SanitizeMethod::HostOverwriteSinglePass,
            recommended_label: "Host-Level Logical Overwrite (Fallback Mode)".to_string(),
            reason: "Device controller does not expose hardware-level ATA Secure Erase or NVMe Sanitize commands. Host-level overwrite is the only available fallback.".to_string(),
            alternative_available: Some("Host-Level Multi-Pass Overwrite (3 passes).".to_string()),
            not_recommended: None,
            residual_risk_warning: Some("WARNING: Host-level overwrite on flash media (SSD/USB/SD) cannot reach physical NAND cells in the flash translation layer (FTL) over-provisioning or wear-leveling reserve pools. Residual data may remain recoverable via chip-off analysis (§33a).".to_string()),
        }
    }
}
