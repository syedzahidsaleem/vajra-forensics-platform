//! Hardware-Level Sanitization Dispatch (§35).
//!
//! Interfaces controller-native sanitization primitives (ATA Secure Erase, NVMe Sanitize, TCG Crypto Erase).

use vajra_core::{SanitizeMethod, WritableBlockSource};

use crate::error::EraseError;
use crate::gate::SanitizationAuthorizationToken;

/// [DESTRUCTIVE OPERATION (§43)]
/// Issues a hardware controller-level sanitize command.
///
/// Requires `&SanitizationAuthorizationToken` capability token.
pub fn execute_hardware_sanitize_destructive(
    target: &mut dyn WritableBlockSource,
    method: SanitizeMethod,
    _token: &SanitizationAuthorizationToken,
) -> Result<(), EraseError> {
    target.issue_sanitize(method)?;
    Ok(())
}
