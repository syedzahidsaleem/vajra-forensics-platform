//! Recovery Provenance and Artifact Types (§31).
//!
//! Provides the complete provenance record structure capturing every recovery
//! parameter, location, breakdown score, and limitation for evidentiary defensibility.

use crate::confidence::ConfidenceBreakdown;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Recovery Tier classification (§25, §26, §27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryTier {
    /// Tier 1: Filesystem-aware metadata recovery (MFT, Inode Table, FAT directory slack).
    Tier1Metadata,
    /// Tier 2: Signature-based carving with Garfinkel structural validation.
    Tier2Signature,
    /// Tier 3: Bifragment Gap Carving (BGC) or fragment reassembly.
    Tier3Fragmented,
}

impl fmt::Display for RecoveryTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier1Metadata => write!(f, "Tier 1 (Filesystem Metadata)"),
            Self::Tier2Signature => write!(f, "Tier 2 (Signature + Structural Validation)"),
            Self::Tier3Fragmented => write!(f, "Tier 3 (Bifragment Gap Carving)"),
        }
    }
}

/// Detailed fragmentation parameters for Tier-3 reassembled artifacts (§31).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragmentationDetail {
    /// Size of the intervening gap in sectors.
    pub gap_size_sectors: u64,
    /// LBA range of first fragment: `(start_lba, block_count)`.
    pub fragment_1: (u64, u64),
    /// LBA range of second fragment: `(start_lba, block_count)`.
    pub fragment_2: (u64, u64),
}

/// Canonical Recovered Artifact Record (§31).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveredArtifact {
    /// Unique identifier for this recovery candidate.
    pub id: u64,

    /// Which tier produced this artifact.
    pub recovery_method: RecoveryTier,

    /// Physical LBA extents on the storage media: `[(start_lba, block_count)]`.
    pub source_locations: Vec<(u64, u64)>,

    /// Original directory path if recovered from filesystem metadata.
    pub original_path: Option<String>,

    /// Inferred or recovered filename.
    pub filename_guess: Option<String>,

    /// File type string (e.g. "jpeg", "png", "pdf", "docx", "sqlite").
    pub file_type: String,

    /// Composite confidence score (0.0–1.0) derived via §29 formula.
    pub confidence_score: f32,

    /// Component breakdown of the confidence score (§29).
    pub confidence_breakdown: ConfidenceBreakdown,

    /// Fragmentation metadata if recovered via Tier 3.
    pub fragmentation_detail: Option<FragmentationDetail>,

    /// Total bytes successfully extracted into memory / payload.
    pub recovered_bytes: u64,

    /// Expected total size in bytes (from header metadata or format structure).
    pub expected_total_bytes: Option<u64>,

    /// SHA-256 checksum of recovered payload.
    pub content_hash: String,

    /// Explicit text describing any recovery limitations, truncation, or gap details (§31).
    pub recovery_limitations: Option<String>,

    /// Raw recovered file payload (in-memory buffer).
    #[serde(skip)]
    pub payload: Vec<u8>,
}

impl RecoveredArtifact {
    /// Formats provenance record for human-readable forensic logging (§31).
    pub fn format_provenance(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Recovered File #R-{}\n", self.id));
        out.push_str(&format!("Recovery method: {}\n", self.recovery_method));

        let locs: Vec<String> = self
            .source_locations
            .iter()
            .map(|(s, len)| format!("LBA {} -> {}", s, s + len))
            .collect();
        out.push_str(&format!("Source: {}\n", locs.join(", ")));

        if let Some(ref path) = self.original_path {
            out.push_str(&format!("Original path: {}\n", path));
        }

        out.push_str(&format!(
            "Confidence: {:.1}% (Structural: {:.1}%, Meta: {:.1}%, Entropy: {:.1}%)\n",
            self.confidence_score * 100.0,
            self.confidence_breakdown.structural_validity * 100.0,
            self.confidence_breakdown.metadata_cross_reference * 100.0,
            self.confidence_breakdown.entropy_consistency * 100.0
        ));

        if let Some(ref basis) = self.confidence_breakdown.entropy_explainability {
            out.push_str(&format!("  Entropy Signal Basis: {}\n", basis));
        }

        if let Some(ref frag) = self.fragmentation_detail {
            out.push_str(&format!(
                "Fragmentation: 2 fragments (gap size: {} sectors | LBA {}..{} + LBA {}..{})\n",
                frag.gap_size_sectors,
                frag.fragment_1.0,
                frag.fragment_1.0 + frag.fragment_1.1,
                frag.fragment_2.0,
                frag.fragment_2.0 + frag.fragment_2.1
            ));
        }

        out.push_str(&format!(
            "Recovered bytes: {} / {}\n",
            self.recovered_bytes,
            self.expected_total_bytes
                .map(|b| b.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        ));
        out.push_str(&format!("SHA-256: {}\n", self.content_hash));

        if let Some(ref lim) = self.recovery_limitations {
            out.push_str(&format!("Recovery limitations: {}\n", lim));
        } else {
            out.push_str("Recovery limitations: None (Complete & verified payload)\n");
        }

        out
    }
}
