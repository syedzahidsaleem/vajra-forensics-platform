//! External anchoring and history-rewrite defense (§40).
//!
//! Adapted from the external anchoring architecture of `Ashish-Barmaiya/attest`.

use crate::chain::AuditChain;
use crate::error::AuditError;
use crate::pki::{verify_signature, OperatorKeyPair};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use vajra_case_db::CaseDb;

/// Signed chain-head checkpoint exported to external / write-once media (§40).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCheckpoint {
    pub case_id: String,
    pub sequence: u64,
    pub chain_head_hash: String,
    pub timestamp_utc: String,
    pub operator_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub certificate_pem: Option<String>,
    pub trusted_timestamp: Option<String>,
}

impl AnchorCheckpoint {
    /// Canonical byte string used for cryptographic signing and verification (§40).
    pub fn payload_for_signing(
        case_id: &str,
        sequence: u64,
        chain_head_hash: &str,
        timestamp_utc: &str,
        operator_id: &str,
    ) -> Vec<u8> {
        format!(
            "VAJRA_ANCHOR_V1:{}:{}:{}:{}:{}",
            case_id, sequence, chain_head_hash, timestamp_utc, operator_id
        )
        .into_bytes()
    }
}

/// Verification report resulting from validating an external anchor (§40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorVerificationReport {
    pub case_id: String,
    pub anchored_sequence: u64,
    pub anchored_hash: String,
    pub is_signature_valid: bool,
    pub is_chain_consistent: bool,
}

impl std::fmt::Display for AnchorVerificationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Anchor Verification: Case '{}' at Seq #{} [Hash: {}] — Signature Valid: {}, Chain Consistent: {}",
            self.case_id,
            self.anchored_sequence,
            self.anchored_hash,
            self.is_signature_valid,
            self.is_chain_consistent
        )
    }
}

/// Exports a signed external anchor checkpoint to a specified destination file (§40).
pub fn export_anchor<P: AsRef<Path>>(
    db: &CaseDb,
    case_id: &str,
    operator_id: &str,
    keypair: &OperatorKeyPair,
    destination_path: P,
) -> Result<AnchorCheckpoint, AuditError> {
    let entries = AuditChain::load_entries(db)?;
    if entries.is_empty() {
        return Err(AuditError::InvalidSignature(
            "Cannot export anchor for an empty audit log".to_string(),
        ));
    }

    // Filter to the specified case or take current head
    let latest = entries.last().unwrap();
    let timestamp_utc = Utc::now().to_rfc3339();

    let signable_payload = AnchorCheckpoint::payload_for_signing(
        case_id,
        latest.seq,
        &latest.entry_hash,
        &timestamp_utc,
        operator_id,
    );

    let signature = keypair.sign(&signable_payload);
    let signature_hex = hex::encode(signature);
    let public_key_hex = keypair.public_key_hex();
    let cert_pem = keypair.generate_self_signed_cert(operator_id).ok();

    let checkpoint = AnchorCheckpoint {
        case_id: case_id.to_string(),
        sequence: latest.seq,
        chain_head_hash: latest.entry_hash.clone(),
        timestamp_utc,
        operator_id: operator_id.to_string(),
        public_key_hex,
        signature_hex,
        certificate_pem: cert_pem,
        trusted_timestamp: None,
    };

    let serialized = serde_json::to_string_pretty(&checkpoint)?;
    fs::write(destination_path, serialized)?;

    Ok(checkpoint)
}

/// Verifies a live case audit chain against a previously-exported anchor checkpoint (§40).
///
/// Returns `Ok(AnchorVerificationReport)` if consistent, or `Err(AuditError::AnchorMismatch)` if tampered.
pub fn verify_anchor<P: AsRef<Path>>(
    db: &CaseDb,
    anchor_path: P,
) -> Result<AnchorVerificationReport, AuditError> {
    let content = fs::read_to_string(anchor_path)?;
    let checkpoint: AnchorCheckpoint = serde_json::from_str(&content)?;

    // 1. Verify digital signature on checkpoint
    let signable_payload = AnchorCheckpoint::payload_for_signing(
        &checkpoint.case_id,
        checkpoint.sequence,
        &checkpoint.chain_head_hash,
        &checkpoint.timestamp_utc,
        &checkpoint.operator_id,
    );

    let pk_bytes = hex::decode(&checkpoint.public_key_hex).map_err(|e| {
        AuditError::InvalidSignature(format!("Malformed public key hex: {}", e))
    })?;
    let sig_bytes = hex::decode(&checkpoint.signature_hex).map_err(|e| {
        AuditError::InvalidSignature(format!("Malformed signature hex: {}", e))
    })?;

    let sig_ok = verify_signature(&pk_bytes, &signable_payload, &sig_bytes)?;
    if !sig_ok {
        return Err(AuditError::InvalidSignature(
            "Anchor checkpoint cryptographic signature is INVALID".to_string(),
        ));
    }

    // 2. Load live chain and inspect matching sequence entry
    let entries = AuditChain::load_entries(db)?;
    let target_entry = entries
        .iter()
        .find(|e| e.seq == checkpoint.sequence);

    match target_entry {
        Some(live_entry) => {
            if live_entry.entry_hash != checkpoint.chain_head_hash {
                return Err(AuditError::AnchorMismatch {
                    seq: checkpoint.sequence,
                    live_hash: live_entry.entry_hash.clone(),
                    anchor_hash: checkpoint.chain_head_hash,
                });
            }
        }
        None => {
            return Err(AuditError::AnchorMismatch {
                seq: checkpoint.sequence,
                live_hash: "<DELETED / MISSING IN LIVE CHAIN>".to_string(),
                anchor_hash: checkpoint.chain_head_hash,
            });
        }
    }

    Ok(AnchorVerificationReport {
        case_id: checkpoint.case_id,
        anchored_sequence: checkpoint.sequence,
        anchored_hash: checkpoint.chain_head_hash,
        is_signature_valid: true,
        is_chain_consistent: true,
    })
}
