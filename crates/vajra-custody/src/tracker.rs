//! Chain of Custody tracking, state machine validation, and report formatting (§21).

use crate::error::CustodyError;
use crate::events::{CustodyEvent, CustodyEventType};
use chrono::DateTime;
use vajra_case_db::{CaseDb, CustodyEventRecord};

/// Chain of Custody manager enforcing state machine invariants and reporting (§21).
pub struct CustodyTracker;

impl CustodyTracker {
    /// Records a new custody event after validating it against state machine invariants (§21).
    pub fn record_event(db: &CaseDb, event: &CustodyEvent) -> Result<(), CustodyError> {
        let history = Self::get_history(db, &event.evidence_id)?;

        // 1. Validate the candidate event against prior history
        Self::validate_candidate_event(&history, event)?;

        // 2. Insert into database
        let record = CustodyEventRecord {
            event_id: event.event_id.clone(),
            evidence_id: event.evidence_id.clone(),
            event_type: event.event_type.to_string(),
            from_party: event.from_party.clone(),
            to_party: event.to_party.clone(),
            timestamp_utc: event.timestamp_utc.clone(),
            location: event.location.clone(),
            purpose: event.purpose.clone(),
            evidence_condition: event.evidence_condition.clone(),
            signature_ref: event.signature_ref.clone(),
        };

        db.record_custody_event(&record)?;

        // 3. Update current custody owner and location on the evidence item record
        let new_owner = event
            .to_party
            .as_ref()
            .or(event.from_party.as_ref())
            .map(|s| s.as_str());

        let new_loc = event.location.as_deref();

        if new_owner.is_some() || new_loc.is_some() {
            let mut sql_parts = Vec::new();
            if let Some(owner) = new_owner {
                sql_parts.push(format!("current_custody_owner = '{}'", owner));
            }
            if let Some(loc) = new_loc {
                sql_parts.push(format!("current_location = '{}'", loc));
            }
            let update_sql = format!(
                "UPDATE evidence_items SET {} WHERE evidence_id = '{}';",
                sql_parts.join(", "),
                event.evidence_id
            );
            db.execute_raw(&update_sql).ok();
        }

        Ok(())
    }

    /// Fetches all recorded custody events for an evidence item in chronological order.
    pub fn get_history(db: &CaseDb, evidence_id: &str) -> Result<Vec<CustodyEvent>, CustodyError> {
        let records = db.list_custody_events_for_evidence(evidence_id)?;
        let mut events = Vec::with_capacity(records.len());

        for r in records {
            let event_type: CustodyEventType = r.event_type.parse().map_err(|_| {
                CustodyError::InvalidInitialEvent {
                    evidence_id: evidence_id.to_string(),
                    found_type: r.event_type.clone(),
                }
            })?;

            events.push(CustodyEvent {
                event_id: r.event_id,
                evidence_id: r.evidence_id,
                event_type,
                from_party: r.from_party,
                to_party: r.to_party,
                timestamp_utc: r.timestamp_utc,
                location: r.location,
                purpose: r.purpose,
                evidence_condition: r.evidence_condition,
                signature_ref: r.signature_ref,
            });
        }

        Ok(events)
    }

    /// Validates an incoming candidate event against existing custody history (§21).
    fn validate_candidate_event(
        history: &[CustodyEvent],
        candidate: &CustodyEvent,
    ) -> Result<(), CustodyError> {
        if history.is_empty() {
            // Rule 1: History must begin with Seized or Received
            if candidate.event_type != CustodyEventType::Seized
                && candidate.event_type != CustodyEventType::Received
            {
                return Err(CustodyError::InvalidInitialEvent {
                    evidence_id: candidate.evidence_id.clone(),
                    found_type: candidate.event_type.to_string(),
                });
            }
            return Ok(());
        }

        let last_event = history.last().unwrap();

        // Rule 2: Cannot record events after evidence has entered a terminal state (Returned/Disposed)
        if last_event.event_type.is_terminal() {
            return Err(CustodyError::EventAfterTerminalState {
                event_type: candidate.event_type.to_string(),
                terminal_state: last_event.event_type.to_string(),
            });
        }

        // Rule 3: Transferred requires both from_party and to_party
        if candidate.event_type == CustodyEventType::Transferred
            && (candidate.from_party.is_none() || candidate.to_party.is_none())
        {
            return Err(CustodyError::MissingTransferParties);
        }

        // Rule 4: Monotonic timestamp validation
        if let (Ok(t_prev), Ok(t_cand)) = (
            DateTime::parse_from_rfc3339(&last_event.timestamp_utc),
            DateTime::parse_from_rfc3339(&candidate.timestamp_utc),
        ) {
            if t_cand < t_prev {
                return Err(CustodyError::NonMonotonicTimestamp {
                    previous: last_event.timestamp_utc.clone(),
                    current: candidate.timestamp_utc.clone(),
                });
            }
        }

        Ok(())
    }

    /// Formats the custody event sequence into the human-readable table specified in §21.
    pub fn format_history_report(
        evidence_id: &str,
        device_descriptor: &str,
        events: &[CustodyEvent],
    ) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str(&format!(
            "            CHAIN OF CUSTODY LEDGER: Evidence #{} ({})\n",
            evidence_id, device_descriptor
        ));
        out.push_str("================================================================================\n");

        if events.is_empty() {
            out.push_str("  No custody events recorded for this evidence item.\n");
        } else {
            for e in events {
                let time_display = if let Ok(dt) = DateTime::parse_from_rfc3339(&e.timestamp_utc) {
                    dt.format("%H:%M UTC (%Y-%m-%d)").to_string()
                } else {
                    e.timestamp_utc.clone()
                };

                let mut desc = format!("  {:<25} {}", time_display, e.event_type);

                if let (Some(from), Some(to)) = (&e.from_party, &e.to_party) {
                    desc.push_str(&format!(" from {} to {}", from, to));
                } else if let Some(to) = &e.to_party {
                    desc.push_str(&format!(" by {}", to));
                } else if let Some(from) = &e.from_party {
                    desc.push_str(&format!(" by {}", from));
                }

                if let Some(loc) = &e.location {
                    desc.push_str(&format!(" [Loc: {}]", loc));
                }
                if let Some(purp) = &e.purpose {
                    desc.push_str(&format!(" (Purpose: {})", purp));
                }
                if let Some(cond) = &e.evidence_condition {
                    desc.push_str(&format!(" [Cond: {}]", cond));
                }

                out.push_str(&desc);
                out.push('\n');
            }
        }

        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("NOTE: This interface records operator-reported custody events and validates\n");
        out.push_str("internal sequence and timestamp consistency. It does not independently verify\n");
        out.push_str("physical transfer events occurring outside the application boundary (§21).\n");
        out.push_str("================================================================================\n");

        out
    }
}
