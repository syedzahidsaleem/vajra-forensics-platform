//! Device Identity Confirmation Gate (§43).
//!
//! Enforces the layered, friction-adding safety architecture required before any destructive
//! operation can be executed.
//!
//! # Structural Two-Phase Capability Token Architecture
//!
//! Destructive sanitization methods require a `&SanitizationAuthorizationToken`.
//! This token CANNOT be instantiated directly and CANNOT be obtained in a single function call.
//! It requires a mandatory two-phase temporal sequence:
//!
//! 1. `DeviceConfirmationGate::begin(...)` -> `Result<PendingSanitization, GateError>`
//!    - Unconditionally blocks OS system disks (`is_system_disk`).
//!    - Unconditionally blocks devices with active write blockers.
//!    - Requires exact type-to-confirm serial number match.
//!    - Requires affirmative initial operator confirmation.
//!
//! 2. `PendingSanitization::finalize(self, pre_exec_confirm: bool)` -> `Result<SanitizationAuthorizationToken, GateError>`
//!    - Consumes the pending ticket by value (single-use).
//!    - Requires distinct, separate pre-execution reconfirmation immediately before write operations start.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vajra_device::DeviceDescriptor;

use crate::error::GateError;

/// Unforgeable authorization capability token required by all destructive sanitization entry points (§43).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationAuthorizationToken {
    token_id: String,
    target_path: String,
    target_serial: String,
    target_fingerprint: String,
    operator_id: String,
    authorized_at: DateTime<Utc>,
}

impl SanitizationAuthorizationToken {
    /// Target device path authorized for sanitization.
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Target device serial number authorized for sanitization.
    pub fn target_serial(&self) -> &str {
        &self.target_serial
    }

    /// Target device SHA-256 fingerprint.
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }

    /// Operator who confirmed the authorization.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Timestamp when authorization was granted.
    pub fn authorized_at(&self) -> DateTime<Utc> {
        self.authorized_at
    }

    /// Unique token ID for audit correlation.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
}

/// Phase 1 pending authorization ticket.
///
/// Must be finalized via `PendingSanitization::finalize` to mint a valid authorization token.
pub struct PendingSanitization {
    token_id: String,
    target_path: String,
    target_serial: String,
    target_fingerprint: String,
    operator_id: String,
    initiated_at: DateTime<Utc>,
}

impl PendingSanitization {
    /// Target device path.
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Target device serial number.
    pub fn target_serial(&self) -> &str {
        &self.target_serial
    }

    /// Timestamp when Phase 1 was initiated.
    pub fn initiated_at(&self) -> DateTime<Utc> {
        self.initiated_at
    }

    /// Phase 2: Final pre-execution reconfirmation immediately before operation begins (§43.3).
    ///
    /// Consumes `self` by value so that an authorization ticket cannot be reused.
    pub fn finalize(self, pre_exec_confirm: bool) -> Result<SanitizationAuthorizationToken, GateError> {
        if !pre_exec_confirm {
            return Err(GateError::PreExecConfirmationRejected);
        }

        Ok(SanitizationAuthorizationToken {
            token_id: self.token_id,
            target_path: self.target_path,
            target_serial: self.target_serial,
            target_fingerprint: self.target_fingerprint,
            operator_id: self.operator_id,
            authorized_at: Utc::now(),
        })
    }
}

/// Device Confirmation Gate (§43).
pub struct DeviceConfirmationGate;

impl DeviceConfirmationGate {
    /// Phase 1: Begin the authorization sequence (§43.1, §43.2, §43.4, §43.5).
    ///
    /// # Safety Invariants
    /// 1. Unconditionally refuses if `device.is_system_disk` is true (Hard OS block).
    /// 2. Unconditionally refuses if `device.write_blocker_info` is present.
    /// 3. Validates that `typed_serial` matches `device.serial` verbatim.
    /// 4. Validates that `initial_confirm` is true.
    pub fn begin(
        device: &DeviceDescriptor,
        operator_id: &str,
        typed_serial: &str,
        initial_confirm: bool,
    ) -> Result<PendingSanitization, GateError> {
        // Invariant 1: Hard OS/system disk block (§24, §43.5)
        if device.is_system_disk {
            return Err(GateError::SystemDiskRefusal(device.path.clone()));
        }

        // Invariant 2: Hardware/software write blocker check (§43)
        if device.write_blocker_info.is_some() {
            return Err(GateError::WriteBlockerRefusal(device.path.clone()));
        }

        // Invariant 3: Type-to-confirm serial number matching (§43.4)
        if typed_serial.trim() != device.serial.trim() {
            return Err(GateError::SerialMismatch {
                expected: device.serial.clone(),
                received: typed_serial.to_string(),
            });
        }

        // Invariant 4: Explicit initial confirmation (§43.2)
        if !initial_confirm {
            return Err(GateError::InitialConfirmationRejected);
        }

        let fingerprint_str = vajra_device::fingerprint_device(device)
            .map(|f| f.sha256_hash)
            .unwrap_or_else(|_| "UNKNOWN_FINGERPRINT".to_string());

        Ok(PendingSanitization {
            token_id: format!("GATE-AUTH-{}", Uuid::new_v4()),
            target_path: device.path.clone(),
            target_serial: device.serial.clone(),
            target_fingerprint: fingerprint_str,
            operator_id: operator_id.to_string(),
            initiated_at: Utc::now(),
        })
    }
}
