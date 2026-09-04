//! Error types for Chain of Custody tracking and validation (§21).

use thiserror::Error;
use vajra_case_db::DbError;

/// Canonical error type for Chain of Custody state-machine violations and persistence (§21).
#[derive(Debug, Error)]
pub enum CustodyError {
    /// Initial event violation: history must begin with Seized or Received (§21)
    #[error("Invalid initial custody event for evidence '{evidence_id}': found '{found_type}', expected 'Seized' or 'Received'")]
    InvalidInitialEvent {
        evidence_id: String,
        found_type: String,
    },

    /// Transfer event missing required party attributes
    #[error("Custody transfer requires both 'from_party' and 'to_party' to be specified")]
    MissingTransferParties,

    /// Custody transfer from-party does not match current custody holder
    #[error("Custody transfer party mismatch: evidence is currently held by '{current_holder}', but transfer lists from_party '{from_party}'")]
    CustodyHolderMismatch {
        current_holder: String,
        from_party: String,
    },

    /// State violation: attempting to log events after terminal disposal/return
    #[error("Cannot record custody event '{event_type}' on evidence that has already been '{terminal_state}'")]
    EventAfterTerminalState {
        event_type: String,
        terminal_state: String,
    },

    /// Chronological order violation
    #[error("Non-monotonic custody timestamp: event at '{current}' cannot precede previous event at '{previous}'")]
    NonMonotonicTimestamp {
        previous: String,
        current: String,
    },

    /// Evidence item not found
    #[error("Evidence item with ID '{0}' not found")]
    EvidenceNotFound(String),

    /// Database persistence error
    #[error("Database error in custody subsystem: {0}")]
    Db(#[from] DbError),
}
