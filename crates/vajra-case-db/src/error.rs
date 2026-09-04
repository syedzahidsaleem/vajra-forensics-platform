//! Error types for vajra-case-db (§17, §22).

use thiserror::Error;

/// Canonical error type for database and persistence operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// Low-level SQLite failure
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Schema migration error
    #[error("Database migration error: {0}")]
    Migration(String),

    /// Illegal lifecycle transition attempt on a case (§22)
    #[error("Illegal state transition on case '{case_id}': cannot transition from '{from}' to '{to}' ({reason})")]
    IllegalStateTransition {
        case_id: String,
        from: String,
        to: String,
        reason: String,
    },

    /// Operation rejected because case is closed/tombstoned (§22)
    #[error("Case '{case_id}' is closed/tombstoned and cannot be modified")]
    CaseClosed { case_id: String },

    /// Entity not found in database
    #[error("{entity} with ID '{id}' not found")]
    NotFound {
        entity: &'static str,
        id: String,
    },

    /// Key derivation or encryption error
    #[error("Key derivation or cipher error: {0}")]
    KeyError(String),

    /// JSON serialization/deserialization error
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// General integrity constraint violation
    #[error("Database integrity constraint violation: {0}")]
    ConstraintViolation(String),
}
