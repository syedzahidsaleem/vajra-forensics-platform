//! Unified Recovery Pipeline Orchestrator (§25, §26, §27, §31).
//!
//! Enforces the strict recovery precedence:
//! Tier 1 (Filesystem Metadata) -> Tier 2 (Signature + Validation) -> Tier 3 (Bifragment Gap Carving).

use crate::entropy::EntropyAnalyzer;
use crate::error::CarveError;
use crate::tier1::{recover_tier1, AllocatedBlockMap};
use crate::tier2::{SignatureDb, ValidatorRegistry};
use crate::types::RecoveredArtifact;
use std::sync::Arc;
use vajra_core::ReadOnlyBlockSource;

/// Configuration options for a recovery pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    pub partition_offset: u64,
    pub enable_tier1: bool,
    pub enable_tier2: bool,
    pub enable_tier3: bool,
    pub target_types: Option<Vec<String>>,
    pub max_bgc_search_radius: Option<u64>,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            partition_offset: 0,
            enable_tier1: true,
            enable_tier2: true,
            enable_tier3: true,
            target_types: None,
            max_bgc_search_radius: None,
        }
    }
}

/// High-level multi-tier recovery pipeline (§25–§31).
pub struct RecoveryPipeline {
    sig_db: SignatureDb,
    registry: ValidatorRegistry,
    entropy_analyzer: Option<Arc<dyn EntropyAnalyzer>>,
}

impl Default for RecoveryPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryPipeline {
    pub fn new() -> Self {
        Self {
            sig_db: SignatureDb::standard_forensic_signatures(),
            registry: ValidatorRegistry::default(),
            entropy_analyzer: None,
        }
    }

    pub fn with_signatures(sig_db: SignatureDb) -> Self {
        Self {
            sig_db,
            registry: ValidatorRegistry::default(),
            entropy_analyzer: None,
        }
    }

    /// Configures custom entropy analyzer (e.g. `MlEntropyAnalyzer` from `vajra-ml`) (§29, §33).
    pub fn with_entropy_analyzer(mut self, analyzer: Arc<dyn EntropyAnalyzer>) -> Self {
        self.entropy_analyzer = Some(analyzer);
        self
    }

    /// Executes the full multi-tier recovery pipeline against a block source.
    pub fn run(
        &self,
        source: &mut dyn ReadOnlyBlockSource,
        options: &PipelineOptions,
    ) -> Result<Vec<RecoveredArtifact>, CarveError> {
        let mut all_artifacts = Vec::new();
        let mut allocated_map = AllocatedBlockMap::new();
        let custom_analyzer = self.entropy_analyzer.as_deref();

        // 1. Tier 1: Filesystem Metadata Recovery (§25)
        if options.enable_tier1 {
            let (tier1_artifacts, t1_map) = recover_tier1(source, options.partition_offset)?;
            allocated_map = t1_map;
            all_artifacts.extend(tier1_artifacts);
        }

        // 2. Tier 2: Signature-Based Carving + Structural Validation (§26)
        if options.enable_tier2 {
            let tier2_artifacts = crate::tier2::carve_tier2_with_analyzer(
                source,
                &self.sig_db,
                &self.registry,
                &mut allocated_map,
                options.target_types.as_deref(),
                custom_analyzer,
            )?;
            all_artifacts.extend(tier2_artifacts);
        }

        // 3. Tier 3: Bifragment Gap Carving (§27)
        if options.enable_tier3 {
            let tier3_artifacts = crate::tier3::carve_tier3_with_analyzer(
                source,
                &self.sig_db,
                &self.registry,
                &mut allocated_map,
                options.target_types.as_deref(),
                options.max_bgc_search_radius,
                custom_analyzer,
            )?;
            all_artifacts.extend(tier3_artifacts);
        }

        Ok(all_artifacts)
    }
}
