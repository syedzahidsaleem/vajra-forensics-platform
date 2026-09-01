//! Sanitization Method Execution (§33a, §35).

pub mod hardware;
pub mod overwrite;

use vajra_core::{SanitizeMethod, WritableBlockSource};

use crate::error::EraseError;
use crate::gate::SanitizationAuthorizationToken;
use self::overwrite::OverwritePattern;

/// [DESTRUCTIVE OPERATION (§43)]
/// Executes the specified sanitization method against the target block device.
///
/// Requires `&SanitizationAuthorizationToken` capability token.
pub fn execute_sanitization_destructive<F>(
    target: &mut dyn WritableBlockSource,
    method: &SanitizeMethod,
    token: &SanitizationAuthorizationToken,
    mut progress: F,
) -> Result<(), EraseError>
where
    F: FnMut(u32, u32, u64, u64),
{
    match method {
        SanitizeMethod::HostOverwriteSinglePass => {
            overwrite::execute_overwrite_pass_destructive(
                target,
                OverwritePattern::Zeros,
                1,
                1,
                token,
                &mut progress,
            )?;
        }
        SanitizeMethod::HostOverwriteMultiPass { passes } => {
            let total = *passes;
            for p in 1..=total {
                let pattern = if p == total {
                    OverwritePattern::Zeros
                } else if p % 2 == 1 {
                    OverwritePattern::Random
                } else {
                    OverwritePattern::Ones
                };

                overwrite::execute_overwrite_pass_destructive(
                    target,
                    pattern,
                    p,
                    total,
                    token,
                    &mut progress,
                )?;
            }
        }
        SanitizeMethod::AtaSecureErase
        | SanitizeMethod::AtaEnhancedSecureErase
        | SanitizeMethod::NvmeSanitizeBlock
        | SanitizeMethod::NvmeSanitizeCrypto
        | SanitizeMethod::NvmeFormat
        | SanitizeMethod::CryptographicErase
        | SanitizeMethod::ScsiSanitizeOverwrite
        | SanitizeMethod::ScsiSanitizeCrypto => {
            hardware::execute_hardware_sanitize_destructive(target, method.clone(), token)?;
            progress(1, 1, target.total_blocks(), target.total_blocks());
        }
    }

    Ok(())
}
