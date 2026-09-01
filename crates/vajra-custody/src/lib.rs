//! # vajra-custody
//!
//! Chain of custody ledger recording and state machine validation for the
//! Vajra Digital Forensics Platform (§21).
//!
//! Enforces:
//! - Strict state machine invariants (initial intake, party consistency, terminal disposal)
//! - Honest framing: records operator-reported custody events and checks internal consistency
//!   without overclaiming physical real-world verification.

pub mod error;
pub mod events;
pub mod tracker;

pub use error::CustodyError;
pub use events::{CustodyEvent, CustodyEventType};
pub use tracker::CustodyTracker;
