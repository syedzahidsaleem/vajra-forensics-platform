//! Vajra Machine Learning / AI Layer (`vajra-ml`) (§33).
//!
//! Provides CPU-only, explainable inference that augments the digital forensics recovery
//! pipeline without overriding deterministic structural validators.

pub mod analyzer;
pub mod classifier;
pub mod features;

pub use analyzer::MlEntropyAnalyzer;
pub use classifier::{ClassificationResult, FeatureContribution, FileTypeClassifier};
pub use features::{extract_features, ExtractedFeatures, NUM_FEATURES};
