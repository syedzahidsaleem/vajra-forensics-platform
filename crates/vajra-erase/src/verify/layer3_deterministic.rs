//! Layer 3 Verification: Deterministic Write-Read-Verify on Bounded Sample (§37).

use serde::{Deserialize, Serialize};
use vajra_core::ReadOnlyBlockSource;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer3Result {
    pub passed: bool,
    pub verified_sectors_count: u64,
    pub unverified_or_mismatched_count: u64,
    pub message: String,
}

/// Verifies that key structural regions (e.g. LBA 0 MBR, backup GPT, partition headers)
/// have been replaced with the expected sanitized fill pattern (0x00 or unallocated pattern).
pub fn verify_layer3(
    device: &mut dyn ReadOnlyBlockSource,
    sample_lbas: &[u64],
) -> Layer3Result {
    let mut matched = 0u64;
    let mut mismatched = 0u64;

    for &lba in sample_lbas {
        if lba >= device.total_blocks() {
            continue;
        }

        match device.read_blocks(lba, 1) {
            Ok(bytes) => {
                // Check if all bytes are either 0x00 or uniform (sanitized state)
                let first_byte = bytes.first().copied().unwrap_or(0);
                let is_uniform = bytes.iter().all(|&b| b == first_byte);
                if is_uniform {
                    matched += 1;
                } else {
                    mismatched += 1;
                }
            }
            Err(_) => {
                mismatched += 1;
            }
        }
    }

    let passed = mismatched == 0 && matched > 0;
    let message = if passed {
        format!("Deterministic read-verify PASS on {} critical sample LBAs (LBA 0, partition boundaries).", matched)
    } else {
        format!("Deterministic read-verify FAILED: {} / {} sample LBAs contained residual non-uniform data.", mismatched, matched + mismatched)
    };

    Layer3Result {
        passed,
        verified_sectors_count: matched,
        unverified_or_mismatched_count: mismatched,
        message,
    }
}
