//! Multi-Layer Sanitization Verification (§37).

pub mod layer1_command;
pub mod layer2_status;
pub mod layer3_deterministic;
pub mod layer4_statistical;
pub mod layer5_recovery;

use serde::{Deserialize, Serialize};
use std::fmt;
use vajra_carve::types::RecoveredArtifact;
use vajra_core::ReadOnlyBlockSource;

pub use layer1_command::{verify_layer1, Layer1Result};
pub use layer2_status::{verify_layer2, Layer2Result};
pub use layer3_deterministic::{verify_layer3, Layer3Result};
pub use layer4_statistical::{
    compute_required_sample_size, verify_layer4, verify_layer4_with_seed, Layer4Result,
    StatisticalParams,
};
pub use layer5_recovery::{verify_layer5, Layer5Result};

/// Overall Sanitization Assurance Level (§37, §38).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverallAssurance {
    /// All 5 layers passed without discrepancy.
    High,
    /// Controller-native or host-overwrite completed with statistical verification, minor caveats.
    Medium,
    /// Partial verification or fallback mode on flash media without controller purge.
    Low,
    /// Hard failure: Layer 1 failed, write errors occurred, or Layer 5 recovered residual artifacts.
    Failed,
}

impl fmt::Display for OverallAssurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OverallAssurance::High => write!(f, "HIGH"),
            OverallAssurance::Medium => write!(f, "MEDIUM"),
            OverallAssurance::Low => write!(f, "LOW"),
            OverallAssurance::Failed => write!(f, "FAILED"),
        }
    }
}

/// Comprehensive 5-Layer Verification Report (§37).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLayerVerificationReport {
    pub layer1: Layer1Result,
    pub layer2: Layer2Result,
    pub layer3: Layer3Result,
    pub layer4: Layer4Result,
    pub layer5: Layer5Result,
    pub overall_assurance: OverallAssurance,
    pub summary_reason: String,
}

/// Runs the complete 5-layer verification suite against a sanitized block device (§37).
///
/// # §33a Structural Assurance Capping
/// Host-level logical overwrite against flash media (`MediaType::Nvme`, `MediaType::SataSsd`, `MediaType::Usb`, `MediaType::SdCard`)
/// is structurally capped at `OverallAssurance::Medium`, even if all 5 layers report clean,
/// because host writes cannot purge controller-managed FTL wear-leveling / over-provisioning pools.
pub fn verify_sanitization(
    device: &mut dyn ReadOnlyBlockSource,
    command_result: &Result<(), crate::error::EraseError>,
    sample_lbas: &[u64],
    confidence: f64,
    defect_rate: f64,
    method: Option<&vajra_core::SanitizeMethod>,
) -> (MultiLayerVerificationReport, Vec<RecoveredArtifact>) {
    verify_sanitization_with_seed(
        device,
        command_result,
        sample_lbas,
        confidence,
        defect_rate,
        method,
        None,
    )
}

/// Runs the 5-layer verification suite with an optional RNG seed for reproducible statistical sampling.
pub fn verify_sanitization_with_seed(
    device: &mut dyn ReadOnlyBlockSource,
    command_result: &Result<(), crate::error::EraseError>,
    sample_lbas: &[u64],
    confidence: f64,
    defect_rate: f64,
    method: Option<&vajra_core::SanitizeMethod>,
    seed: Option<u64>,
) -> (MultiLayerVerificationReport, Vec<RecoveredArtifact>) {
    let l1 = verify_layer1(command_result);
    let l2 = verify_layer2(device);
    let l3 = verify_layer3(device, sample_lbas);
    let l4 = verify_layer4_with_seed(device, confidence, defect_rate, seed);
    let (l5, recovered_artifacts) = verify_layer5(device);

    // Resolution Override Rule (§37):
    // If Layer 5 finds ANY artifact, overall assurance is FAILED regardless of Layers 1-4.
    let (overall_assurance, summary_reason) = if !l5.passed {
        (
            OverallAssurance::Failed,
            format!(
                "OVERRIDE FAILURE: Layer 5 independent carving detected {} recoverable artifacts. Overall assurance is FAILED.",
                l5.recovered_artifacts_count
            ),
        )
    } else if !l1.passed {
        (
            OverallAssurance::Failed,
            format!("Sanitization command failed during execution: {}", l1.message),
        )
    } else if l2.passed && l3.passed && l4.passed && l5.passed {
        // §33a Structural Assurance Cap:
        let is_flash_media = matches!(
            device.media_type(),
            vajra_core::MediaType::Nvme
                | vajra_core::MediaType::SataSsd
                | vajra_core::MediaType::Usb
                | vajra_core::MediaType::SdCard
        );
        let is_host_overwrite = method.map(|m| matches!(
            m,
            vajra_core::SanitizeMethod::HostOverwriteSinglePass
                | vajra_core::SanitizeMethod::HostOverwriteMultiPass { .. }
        )).unwrap_or(false);

        if is_flash_media && is_host_overwrite {
            (
                OverallAssurance::Medium,
                "All 5 verification layers passed on addressable LBAs, but assurance is structurally capped at MEDIUM per §33a (NIST SP 800-88 §2.4) because host-level overwrite on flash media cannot reach FTL wear-leveling or over-provisioning pools.".to_string(),
            )
        } else {
            (
                OverallAssurance::High,
                "All 5 independent verification layers passed with 0 residual traces or recoverable artifacts.".to_string(),
            )
        }
    } else if l3.passed && l4.passed {
        (
            OverallAssurance::Medium,
            "Layers 3, 4, and 5 verified clean data, with minor controller status caveats.".to_string(),
        )
    } else {
        (
            OverallAssurance::Low,
            "Incomplete deterministic or statistical sampling verification.".to_string(),
        )
    };

    (
        MultiLayerVerificationReport {
            layer1: l1,
            layer2: l2,
            layer3: l3,
            layer4: l4,
            layer5: l5,
            overall_assurance,
            summary_reason,
        },
        recovered_artifacts,
    )
}
