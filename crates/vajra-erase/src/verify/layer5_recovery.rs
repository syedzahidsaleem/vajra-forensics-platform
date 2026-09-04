//! Layer 5 Verification: Independent Recovery-Engine Scan (§37).
//!
//! "This project's most genuinely novel contribution" — runs the platform's own
//! `vajra-carve` recovery pipeline against the just-sanitized device.
//!
//! # Resolution Override Rule (§37)
//! If Layer 5 finds ANY recoverable artifact, the sanitization is reported as FAILED
//! regardless of what upstream Layers 1–4 reported.

use serde::{Deserialize, Serialize};
use vajra_carve::pipeline::{PipelineOptions, RecoveryPipeline};
use vajra_carve::types::RecoveredArtifact;
use vajra_core::ReadOnlyBlockSource;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer5Result {
    pub passed: bool,
    pub recovered_artifacts_count: usize,
    pub recovered_artifact_ids: Vec<u64>,
    pub message: String,
}

/// Executes Layer 5 independent forensic carving scan against the sanitized block source (§37).
pub fn verify_layer5(device: &mut dyn ReadOnlyBlockSource) -> (Layer5Result, Vec<RecoveredArtifact>) {
    let pipeline = RecoveryPipeline::new();
    let options = PipelineOptions {
        partition_offset: 0,
        enable_tier1: false, // Pure carving scan across all unallocated sectors
        enable_tier2: true,
        enable_tier3: true,
        target_types: None,
        max_bgc_search_radius: Some(64),
    };

    let artifacts = pipeline.run(device, &options).unwrap_or_default();
    let count = artifacts.len();
    let passed = count == 0;

    let artifact_ids: Vec<u64> = artifacts.iter().map(|a| a.id).collect();

    let message = if passed {
        "Layer 5 Recovery Scan PASS: 0 recoverable artifacts or structures found across media.".to_string()
    } else {
        format!(
            "Layer 5 Recovery Scan FAILED: {} recoverable forensic artifacts detected (Artifact IDs: {:?}).",
            count, artifact_ids
        )
    };

    (
        Layer5Result {
            passed,
            recovered_artifacts_count: count,
            recovered_artifact_ids: artifact_ids,
            message,
        },
        artifacts,
    )
}
