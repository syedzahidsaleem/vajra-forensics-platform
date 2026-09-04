//! Layer 1 Verification: Command-Level Success/Failure (§37).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer1Result {
    pub passed: bool,
    pub command_status_code: Option<u32>,
    pub message: String,
}

pub fn verify_layer1(command_result: &Result<(), crate::error::EraseError>) -> Layer1Result {
    match command_result {
        Ok(()) => Layer1Result {
            passed: true,
            command_status_code: Some(0),
            message: "Sanitization command executed and returned success (status: 0)".to_string(),
        },
        Err(e) => Layer1Result {
            passed: false,
            command_status_code: None,
            message: format!("Sanitization command returned error: {}", e),
        },
    }
}
