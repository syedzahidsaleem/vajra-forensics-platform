//! Write blocker detection metadata and structures.
//!
//! Tracks hardware write-blockers (Tableau, WiebeTech, CRU) and OS-level read-only status (§24).

use serde::{Deserialize, Serialize};

/// Method by which write protection or hardware write-blocker was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WriteBlockerDetectionMethod {
    /// Matched against known USB Vendor ID / Product ID table.
    KnownVidPid,
    /// Detected via OS-level disk query (e.g. read-only volume attribute).
    OsQuery,
    /// Detected via SCSI Mode Sense (Write Protect bit set).
    ScsiCommand,
    /// Operator manual assertion or override.
    ManualOverride,
}

/// Metadata identifying a detected hardware or software write blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBlockerMetadata {
    /// Identified hardware vendor (e.g. "Tableau", "CRU / WiebeTech").
    pub vendor: Option<String>,
    /// Identified hardware model (e.g. "T8u Forensic USB 3.0 Bridge").
    pub model: Option<String>,
    /// USB Vendor ID if attached over USB.
    pub vid: Option<u16>,
    /// USB Product ID if attached over USB.
    pub pid: Option<u16>,
    /// Detection method used.
    pub detection_method: WriteBlockerDetectionMethod,
    /// Whether physical hardware write-blocking is active.
    pub is_hardware_blocked: bool,
    /// Whether OS-level read-only mount / flag is active.
    pub is_os_read_only: bool,
}

impl WriteBlockerMetadata {
    /// Construct a write blocker descriptor from a known VID/PID match.
    pub fn from_vid_pid(vendor: &str, model: &str, vid: u16, pid: u16) -> Self {
        Self {
            vendor: Some(vendor.to_string()),
            model: Some(model.to_string()),
            vid: Some(vid),
            pid: Some(pid),
            detection_method: WriteBlockerDetectionMethod::KnownVidPid,
            is_hardware_blocked: true,
            is_os_read_only: true,
        }
    }

    /// Construct a write blocker descriptor from OS-level read-only query.
    pub fn from_os_read_only() -> Self {
        Self {
            vendor: None,
            model: None,
            vid: None,
            pid: None,
            detection_method: WriteBlockerDetectionMethod::OsQuery,
            is_hardware_blocked: false,
            is_os_read_only: true,
        }
    }
}
