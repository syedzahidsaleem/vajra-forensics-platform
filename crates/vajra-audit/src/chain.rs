//! Hash chain construction and verification engine (§39).

use crate::entry::{AuditEntry, GENESIS_PREV_HASH};
use crate::error::AuditError;
use chrono::Utc;
use vajra_case_db::CaseDb;

/// Report summarizing chain verification results (§39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub total_entries: usize,
    pub first_seq: u64,
    pub latest_seq: u64,
    pub latest_hash: String,
    pub is_valid: bool,
}

impl std::fmt::Display for ChainReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Chain Verification: {} entries [Seq #{} -> #{}], Head Hash: {}, Status: INTACT",
            self.total_entries, self.first_seq, self.latest_seq, self.latest_hash
        )
    }
}

/// Audit chain controller managing append and verification operations (§39).
pub struct AuditChain;

impl AuditChain {
    /// Appends a new event to the audit log table, linking it cryptographically to the current chain head (§39).
    pub fn append(
        db: &CaseDb,
        case_id: &str,
        operator_id: &str,
        operation: &str,
        target_descriptor: &str,
        result: &str,
    ) -> Result<AuditEntry, AuditError> {
        let timestamp_utc = Utc::now().to_rfc3339();

        let (seq, prev_hash) = match db.get_latest_audit_entry()? {
            Some(latest) => (latest.seq + 1, latest.entry_hash),
            None => (1, GENESIS_PREV_HASH.to_string()),
        };

        let entry = AuditEntry::new(
            seq,
            timestamp_utc,
            operator_id.to_string(),
            case_id.to_string(),
            operation.to_string(),
            target_descriptor.to_string(),
            result.to_string(),
            prev_hash.clone(),
        );

        let entry_json = serde_json::to_string(&entry)?;
        db.append_audit_log(seq, &entry_json, &entry.entry_hash, &prev_hash)?;

        Ok(entry)
    }

    /// Loads all audit entries from the database.
    pub fn load_entries(db: &CaseDb) -> Result<Vec<AuditEntry>, AuditError> {
        let records = db.get_audit_log_entries()?;
        let mut entries = Vec::with_capacity(records.len());
        for rec in records {
            let entry: AuditEntry = serde_json::from_str(&rec.entry_json)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Verifies the full audit log chain in the database (§39).
    pub fn verify_db(db: &CaseDb) -> Result<ChainReport, AuditError> {
        let entries = Self::load_entries(db)?;
        Self::verify_entries(&entries)
    }

    /// Walks a sequence of AuditEntry records and validates:
    /// 1. Sequential monotonicity (seq = 1, 2, 3, ...)
    /// 2. Genesis linkage (entry[0].prev_hash == GENESIS_PREV_HASH)
    /// 3. Backwards hash chaining (entry[i].prev_hash == entry[i-1].entry_hash)
    /// 4. Cryptographic integrity (entry[i].entry_hash == SHA256(payload || prev_hash))
    pub fn verify_entries(entries: &[AuditEntry]) -> Result<ChainReport, AuditError> {
        if entries.is_empty() {
            return Ok(ChainReport {
                total_entries: 0,
                first_seq: 0,
                latest_seq: 0,
                latest_hash: GENESIS_PREV_HASH.to_string(),
                is_valid: true,
            });
        }

        let mut expected_prev = GENESIS_PREV_HASH.to_string();

        for (i, entry) in entries.iter().enumerate() {
            let expected_seq = (i + 1) as u64;

            // 1. Sequence check
            if entry.seq != expected_seq {
                return Err(AuditError::SequenceGap {
                    expected: expected_seq,
                    found: entry.seq,
                });
            }

            // 2. Chain linkage check
            if entry.prev_hash != expected_prev {
                return Err(AuditError::ChainBrokenAtSeq {
                    seq: entry.seq,
                    expected_prev,
                    found_prev: entry.prev_hash.clone(),
                });
            }

            // 3. Payload hash integrity check
            if !entry.verify_integrity() {
                let computed = AuditEntry::calculate_hash(
                    entry.seq,
                    &entry.timestamp_utc,
                    &entry.operator_id,
                    &entry.case_id,
                    &entry.operation,
                    &entry.target_descriptor,
                    &entry.result,
                    &entry.prev_hash,
                );
                return Err(AuditError::HashMismatchAtSeq {
                    seq: entry.seq,
                    computed,
                    recorded: entry.entry_hash.clone(),
                });
            }

            expected_prev = entry.entry_hash.clone();
        }

        let first_seq = entries.first().unwrap().seq;
        let latest_entry = entries.last().unwrap();

        Ok(ChainReport {
            total_entries: entries.len(),
            first_seq,
            latest_seq: latest_entry.seq,
            latest_hash: latest_entry.entry_hash.clone(),
            is_valid: true,
        })
    }
}
