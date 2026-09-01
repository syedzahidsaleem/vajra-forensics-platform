//! AuditEntry data structure and hash-chain computation (§39).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Genesis block predecessor hash convention: 64 zero hex characters.
///
/// Matches reference implementation in `ShivangiDas-03/Tamper-Evident-Logging-System`.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Tamper-evident sequential audit log entry (§39).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number starting at 1
    pub seq: u64,
    /// UTC ISO-8601 timestamp
    pub timestamp_utc: String,
    /// Identifier of the examiner / operator who executed the operation
    pub operator_id: String,
    /// Case identifier
    pub case_id: String,
    /// Operation description or enum string (§22, §39)
    pub operation: String,
    /// Target device, file path, or subject descriptor
    pub target_descriptor: String,
    /// Execution result string (e.g. SUCCESS, FAILED: reason)
    pub result: String,
    /// SHA-256 hash of the immediate predecessor in the chain
    pub prev_hash: String,
    /// SHA-256 hash of (entry payload + prev_hash)
    pub entry_hash: String,
}

#[derive(Serialize)]
struct HashablePayload<'a> {
    seq: u64,
    timestamp_utc: &'a str,
    operator_id: &'a str,
    case_id: &'a str,
    operation: &'a str,
    target_descriptor: &'a str,
    result: &'a str,
}

impl AuditEntry {
    /// Computes the deterministic SHA-256 entry hash (§39).
    ///
    /// Formula: `SHA256(canonical_json(payload) || prev_hash)`
    #[allow(clippy::too_many_arguments)]
    pub fn calculate_hash(
        seq: u64,
        timestamp_utc: &str,
        operator_id: &str,
        case_id: &str,
        operation: &str,
        target_descriptor: &str,
        result: &str,
        prev_hash: &str,
    ) -> String {
        let payload = HashablePayload {
            seq,
            timestamp_utc,
            operator_id,
            case_id,
            operation,
            target_descriptor,
            result,
        };

        let serialized_payload = serde_json::to_string(&payload)
            .expect("Audit entry payload serialization must never fail");

        let mut hasher = Sha256::new();
        hasher.update(serialized_payload.as_bytes());
        hasher.update(b"||");
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Creates a new uncommitted audit entry, deriving its `entry_hash` from the given predecessor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seq: u64,
        timestamp_utc: String,
        operator_id: String,
        case_id: String,
        operation: String,
        target_descriptor: String,
        result: String,
        prev_hash: String,
    ) -> Self {
        let entry_hash = Self::calculate_hash(
            seq,
            &timestamp_utc,
            &operator_id,
            &case_id,
            &operation,
            &target_descriptor,
            &result,
            &prev_hash,
        );

        Self {
            seq,
            timestamp_utc,
            operator_id,
            case_id,
            operation,
            target_descriptor,
            result,
            prev_hash,
            entry_hash,
        }
    }

    /// Verifies whether the entry's stored `entry_hash` matches its recomputed content hash.
    pub fn verify_integrity(&self) -> bool {
        let recomputed = Self::calculate_hash(
            self.seq,
            &self.timestamp_utc,
            &self.operator_id,
            &self.case_id,
            &self.operation,
            &self.target_descriptor,
            &self.result,
            &self.prev_hash,
        );
        self.entry_hash == recomputed
    }
}
