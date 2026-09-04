//! Unified Forensic Reporting & Verification Subsystem (§41, §42, §40).

pub mod generator;
pub mod model;
pub mod timestamp;

pub use generator::ReportGenerator;
pub use model::{
    AcquisitionReportPayload, ChainOfCustodyPayload, DeviceHealthPayload, EvidenceManifestItem,
    ForensicExamPayload, RecoveredArtifactItem, RecoveryReportPayload, ReportEnvelope, ReportType,
    SanitizationCertData, SanitizationCertPayload, SmartAttributeItem, TimestampTokenRecord,
};
pub use timestamp::{fetch_timestamp_opportunistic, DEFAULT_TSA_TIMEOUT_MS, DEFAULT_TSA_URL};
