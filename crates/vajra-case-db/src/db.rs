//! Case database repository and connection manager (§17, §22).

use crate::error::DbError;
use crate::key::DatabaseKey;
use crate::models::{
    AuditLogRecord, CaseRecord, CaseStatus, CustodyEventRecord, EvidenceItemRecord,
    ForensicImageRecord, OperationRecord, RecoveredArtifactRecord,
    SanitizationEventRecord,
};
use crate::schema::INITIAL_SCHEMA_SQL;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

/// Case Database interface managing encrypted persistence and schema integrity (§17, §22).
pub struct CaseDb {
    conn: Mutex<Connection>,
}

impl CaseDb {
    /// Opens an in-memory SQLite database instance (primarily for testing and volatile operations).
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_connection(None)?;
        db.run_migrations()?;
        Ok(db)
    }

    /// Opens an on-disk database file with optional encryption key (§17).
    pub fn open_file<P: AsRef<Path>>(path: P, key: Option<&DatabaseKey>) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_connection(key)?;
        db.run_migrations()?;
        Ok(db)
    }

    fn init_connection(&self, key: Option<&DatabaseKey>) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        // Enable Foreign Keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        // If encryption key is supplied, apply cipher key pragma (for SQLCipher builds)
        if let Some(k) = key {
            conn.execute(&format!("PRAGMA key = \"x'{}'\";", k.as_hex()), [])?;
        }

        Ok(())
    }

    /// Executes database schema migrations up to the current SCHEMA_VERSION (§22).
    fn run_migrations(&self) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();

        // 1. Ensure migrations tracking table exists
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )?;

        let current_version: i32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM _schema_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current_version < 1 {
            conn.execute_batch(INITIAL_SCHEMA_SQL)?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO _schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![1, now],
            )?;
        }

        Ok(())
    }

    // =========================================================================
    // Cases API (§22)
    // =========================================================================

    /// Creates a new active case record.
    pub fn create_case(
        &self,
        case_id: &str,
        case_name: &str,
        investigator_id: &str,
    ) -> Result<CaseRecord, DbError> {
        let created_at = Utc::now().to_rfc3339();
        let status = CaseStatus::Active;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator_id, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![case_id, case_name, investigator_id, created_at, status.as_str()],
        )?;

        Ok(CaseRecord {
            case_id: case_id.to_string(),
            case_name: case_name.to_string(),
            investigator_id: investigator_id.to_string(),
            created_at,
            status,
        })
    }

    /// Closes and tombstones an active case record (§22).
    ///
    /// Once closed, a case cannot be reopened or deleted.
    pub fn close_case(&self, case_id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();

        // Verify current status first
        let current_status: String = conn
            .query_row(
                "SELECT status FROM cases WHERE case_id = ?1",
                params![case_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound {
                    entity: "Case",
                    id: case_id.to_string(),
                },
                other => DbError::Sqlite(other),
            })?;

        if current_status == "Closed" {
            return Err(DbError::IllegalStateTransition {
                case_id: case_id.to_string(),
                from: "Closed".to_string(),
                to: "Closed".to_string(),
                reason: "Case is already closed/tombstoned".to_string(),
            });
        }

        conn.execute(
            "UPDATE cases SET status = 'Closed' WHERE case_id = ?1",
            params![case_id],
        )?;

        Ok(())
    }

    /// Fetches a case by ID.
    pub fn get_case(&self, case_id: &str) -> Result<CaseRecord, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT case_id, case_name, investigator_id, created_at, status FROM cases WHERE case_id = ?1",
            params![case_id],
            |row| {
                let status_str: String = row.get(4)?;
                let status = status_str.parse().map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e))))?;
                Ok(CaseRecord {
                    case_id: row.get(0)?,
                    case_name: row.get(1)?,
                    investigator_id: row.get(2)?,
                    created_at: row.get(3)?,
                    status,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound {
                entity: "Case",
                id: case_id.to_string(),
            },
            other => DbError::Sqlite(other),
        })
    }

    /// Lists all case records.
    pub fn list_cases(&self) -> Result<Vec<CaseRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT case_id, case_name, investigator_id, created_at, status FROM cases ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let status_str: String = row.get(4)?;
            let status = status_str.parse().map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e))))?;
            Ok(CaseRecord {
                case_id: row.get(0)?,
                case_name: row.get(1)?,
                investigator_id: row.get(2)?,
                created_at: row.get(3)?,
                status,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // =========================================================================
    // Evidence Items API (§22)
    // =========================================================================

    /// Adds an evidence item record.
    pub fn add_evidence(&self, item: &EvidenceItemRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence_items (
                evidence_id, case_id, item_type, device_serial, manufacturer, model,
                capacity_bytes, interface, filesystem, device_fingerprint_hash,
                source_location, physical_condition, write_block_status,
                current_custody_owner, current_location
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                item.evidence_id,
                item.case_id,
                item.item_type,
                item.device_serial,
                item.manufacturer,
                item.model,
                item.capacity_bytes as i64,
                item.interface,
                item.filesystem,
                item.device_fingerprint_hash,
                item.source_location,
                item.physical_condition,
                item.write_block_status,
                item.current_custody_owner,
                item.current_location
            ],
        )?;
        Ok(())
    }

    /// Fetches an evidence item by ID.
    pub fn get_evidence(&self, evidence_id: &str) -> Result<EvidenceItemRecord, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT evidence_id, case_id, item_type, device_serial, manufacturer, model,
                    capacity_bytes, interface, filesystem, device_fingerprint_hash,
                    source_location, physical_condition, write_block_status,
                    current_custody_owner, current_location
             FROM evidence_items WHERE evidence_id = ?1",
            params![evidence_id],
            |row| {
                let capacity: i64 = row.get(6)?;
                Ok(EvidenceItemRecord {
                    evidence_id: row.get(0)?,
                    case_id: row.get(1)?,
                    item_type: row.get(2)?,
                    device_serial: row.get(3)?,
                    manufacturer: row.get(4)?,
                    model: row.get(5)?,
                    capacity_bytes: capacity as u64,
                    interface: row.get(7)?,
                    filesystem: row.get(8)?,
                    device_fingerprint_hash: row.get(9)?,
                    source_location: row.get(10)?,
                    physical_condition: row.get(11)?,
                    write_block_status: row.get(12)?,
                    current_custody_owner: row.get(13)?,
                    current_location: row.get(14)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound {
                entity: "EvidenceItem",
                id: evidence_id.to_string(),
            },
            other => DbError::Sqlite(other),
        })
    }

    /// Lists evidence items for a given case.
    pub fn list_evidence_for_case(&self, case_id: &str) -> Result<Vec<EvidenceItemRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT evidence_id, case_id, item_type, device_serial, manufacturer, model,
                    capacity_bytes, interface, filesystem, device_fingerprint_hash,
                    source_location, physical_condition, write_block_status,
                    current_custody_owner, current_location
             FROM evidence_items WHERE case_id = ?1",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            let capacity: i64 = row.get(6)?;
            Ok(EvidenceItemRecord {
                evidence_id: row.get(0)?,
                case_id: row.get(1)?,
                item_type: row.get(2)?,
                device_serial: row.get(3)?,
                manufacturer: row.get(4)?,
                model: row.get(5)?,
                capacity_bytes: capacity as u64,
                interface: row.get(7)?,
                filesystem: row.get(8)?,
                device_fingerprint_hash: row.get(9)?,
                source_location: row.get(10)?,
                physical_condition: row.get(11)?,
                write_block_status: row.get(12)?,
                current_custody_owner: row.get(13)?,
                current_location: row.get(14)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // =========================================================================
    // Operations & Artifacts API (§22)
    // =========================================================================

    /// Records an operation.
    pub fn record_operation(&self, op: &OperationRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO operations (
                op_id, case_id, evidence_id, op_type, parameters_json,
                tool_version, build_id, started_at, completed_at, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                op.op_id,
                op.case_id,
                op.evidence_id,
                op.op_type,
                op.parameters_json,
                op.tool_version,
                op.build_id,
                op.started_at,
                op.completed_at,
                op.status
            ],
        )?;
        Ok(())
    }

    /// Records a forensic image metadata record (§17, §22).
    pub fn record_forensic_image(&self, img: &ForensicImageRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO forensic_images (
                image_id, evidence_id, image_format, file_path, acquisition_hash,
                verification_hash, bad_sector_map_json, acquired_at, operator
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                img.image_id,
                img.evidence_id,
                img.image_format,
                img.file_path,
                img.acquisition_hash,
                img.verification_hash,
                img.bad_sector_map_json,
                img.acquired_at,
                img.operator
            ],
        )?;
        Ok(())
    }

    /// Gets an operation by ID.
    pub fn get_operation(&self, op_id: &str) -> Result<OperationRecord, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT op_id, case_id, evidence_id, op_type, parameters_json,
                    tool_version, build_id, started_at, completed_at, status
             FROM operations WHERE op_id = ?1",
            params![op_id],
            |row| {
                Ok(OperationRecord {
                    op_id: row.get(0)?,
                    case_id: row.get(1)?,
                    evidence_id: row.get(2)?,
                    op_type: row.get(3)?,
                    parameters_json: row.get(4)?,
                    tool_version: row.get(5)?,
                    build_id: row.get(6)?,
                    started_at: row.get(7)?,
                    completed_at: row.get(8)?,
                    status: row.get(9)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound {
                entity: "Operation",
                id: op_id.to_string(),
            },
            other => DbError::Sqlite(other),
        })
    }

    /// Updates operation checkpoint parameters and status.
    pub fn update_operation_checkpoint(
        &self,
        op_id: &str,
        parameters_json: &str,
        status: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE operations SET parameters_json = ?1, status = ?2 WHERE op_id = ?3",
            params![parameters_json, status, op_id],
        )?;
        if rows == 0 {
            return Err(DbError::NotFound {
                entity: "Operation",
                id: op_id.to_string(),
            });
        }
        Ok(())
    }

    /// Marks an operation as completed.
    pub fn complete_operation(
        &self,
        op_id: &str,
        completed_at: &str,
        status: &str,
        parameters_json: Option<&str>,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        let rows = if let Some(params_str) = parameters_json {
            conn.execute(
                "UPDATE operations SET completed_at = ?1, status = ?2, parameters_json = ?3 WHERE op_id = ?4",
                params![completed_at, status, params_str, op_id],
            )?
        } else {
            conn.execute(
                "UPDATE operations SET completed_at = ?1, status = ?2 WHERE op_id = ?3",
                params![completed_at, status, op_id],
            )?
        };
        if rows == 0 {
            return Err(DbError::NotFound {
                entity: "Operation",
                id: op_id.to_string(),
            });
        }
        Ok(())
    }

    /// Gets a forensic image record by image ID.
    pub fn get_forensic_image(&self, image_id: &str) -> Result<ForensicImageRecord, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT image_id, evidence_id, image_format, file_path, acquisition_hash,
                    verification_hash, bad_sector_map_json, acquired_at, operator
             FROM forensic_images WHERE image_id = ?1",
            params![image_id],
            |row| {
                Ok(ForensicImageRecord {
                    image_id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    image_format: row.get(2)?,
                    file_path: row.get(3)?,
                    acquisition_hash: row.get(4)?,
                    verification_hash: row.get(5)?,
                    bad_sector_map_json: row.get(6)?,
                    acquired_at: row.get(7)?,
                    operator: row.get(8)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound {
                entity: "ForensicImage",
                id: image_id.to_string(),
            },
            other => DbError::Sqlite(other),
        })
    }

    /// Lists all forensic images registered for an evidence item.
    pub fn list_forensic_images_for_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Vec<ForensicImageRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT image_id, evidence_id, image_format, file_path, acquisition_hash,
                    verification_hash, bad_sector_map_json, acquired_at, operator
             FROM forensic_images WHERE evidence_id = ?1",
        )?;
        let rows = stmt.query_map(params![evidence_id], |row| {
            Ok(ForensicImageRecord {
                image_id: row.get(0)?,
                evidence_id: row.get(1)?,
                image_format: row.get(2)?,
                file_path: row.get(3)?,
                acquisition_hash: row.get(4)?,
                verification_hash: row.get(5)?,
                bad_sector_map_json: row.get(6)?,
                acquired_at: row.get(7)?,
                operator: row.get(8)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Records a recovered artifact metadata record (§17, §22).
    pub fn record_recovered_artifact(
        &self,
        artifact: &RecoveredArtifactRecord,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovered_artifacts (
                artifact_id, op_id, original_path, recovered_path, file_type,
                recovery_tier, confidence_score, confidence_breakdown_json, provenance_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact.artifact_id,
                artifact.op_id,
                artifact.original_path,
                artifact.recovered_path,
                artifact.file_type,
                artifact.recovery_tier,
                artifact.confidence_score,
                artifact.confidence_breakdown_json,
                artifact.provenance_json
            ],
        )?;
        Ok(())
    }

    /// Records a sanitization event record (§22, §35).
    pub fn record_sanitization_event(
        &self,
        san: &SanitizationEventRecord,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sanitization_events (
                san_id, op_id, method, standard_reference, verification_layers_json, assurance_level
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                san.san_id,
                san.op_id,
                san.method,
                san.standard_reference,
                san.verification_layers_json,
                san.assurance_level
            ],
        )?;
        Ok(())
    }

    // =========================================================================
    // Custody Events API (§21, §22)
    // =========================================================================

    /// Records a custody event in the ledger.
    pub fn record_custody_event(&self, event: &CustodyEventRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO custody_events (
                event_id, evidence_id, event_type, from_party, to_party,
                timestamp_utc, location, purpose, evidence_condition, signature_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.event_id,
                event.evidence_id,
                event.event_type,
                event.from_party,
                event.to_party,
                event.timestamp_utc,
                event.location,
                event.purpose,
                event.evidence_condition,
                event.signature_ref
            ],
        )?;
        Ok(())
    }

    /// Lists custody events for a specific evidence item in chronological order.
    pub fn list_custody_events_for_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Vec<CustodyEventRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_id, evidence_id, event_type, from_party, to_party,
                    timestamp_utc, location, purpose, evidence_condition, signature_ref
             FROM custody_events WHERE evidence_id = ?1 ORDER BY timestamp_utc ASC",
        )?;
        let rows = stmt.query_map(params![evidence_id], |row| {
            Ok(CustodyEventRecord {
                event_id: row.get(0)?,
                evidence_id: row.get(1)?,
                event_type: row.get(2)?,
                from_party: row.get(3)?,
                to_party: row.get(4)?,
                timestamp_utc: row.get(5)?,
                location: row.get(6)?,
                purpose: row.get(7)?,
                evidence_condition: row.get(8)?,
                signature_ref: row.get(9)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    // =========================================================================
    // Audit Log API (§22, §39)
    // =========================================================================

    /// Appends an entry to the audit log table.
    pub fn append_audit_log(
        &self,
        seq: u64,
        entry_json: &str,
        entry_hash: &str,
        prev_hash: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (seq, entry_json, entry_hash, prev_hash) VALUES (?1, ?2, ?3, ?4)",
            params![seq as i64, entry_json, entry_hash, prev_hash],
        )?;
        Ok(())
    }

    /// Retrieves all audit log records in sequential order.
    pub fn get_audit_log_entries(&self) -> Result<Vec<AuditLogRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, entry_json, entry_hash, prev_hash FROM audit_log ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let seq_i64: i64 = row.get(0)?;
            Ok(AuditLogRecord {
                seq: seq_i64 as u64,
                entry_json: row.get(1)?,
                entry_hash: row.get(2)?,
                prev_hash: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Retrieves the latest audit log entry (chain head).
    pub fn get_latest_audit_entry(&self) -> Result<Option<AuditLogRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, entry_json, entry_hash, prev_hash FROM audit_log ORDER BY seq DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |row| {
            let seq_i64: i64 = row.get(0)?;
            Ok(AuditLogRecord {
                seq: seq_i64 as u64,
                entry_json: row.get(1)?,
                entry_hash: row.get(2)?,
                prev_hash: row.get(3)?,
            })
        })?;

        if let Some(entry) = rows.next() {
            Ok(Some(entry?))
        } else {
            Ok(None)
        }
    }

    /// Helper for tests or diagnostic tooling to execute raw SQL directly.
    pub fn execute_raw(&self, sql: &str) -> Result<usize, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(sql)?;
        Ok(0)
    }

    // =========================================================================
    // Reports API (§22, §41)
    // =========================================================================

    /// Records a generated report record in the database (§22, §41).
    pub fn record_report(&self, report: &crate::models::ReportRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO reports (
                report_id, case_id, report_type, file_path_pdf, file_path_json,
                signature, certificate_chain, trusted_timestamp
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                report.report_id,
                report.case_id,
                report.report_type,
                report.file_path_pdf,
                report.file_path_json,
                report.signature,
                report.certificate_chain,
                report.trusted_timestamp
            ],
        )?;
        Ok(())
    }

    /// Retrieves a specific report record by ID.
    pub fn get_report(&self, report_id: &str) -> Result<Option<crate::models::ReportRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT report_id, case_id, report_type, file_path_pdf, file_path_json,
                    signature, certificate_chain, trusted_timestamp
             FROM reports WHERE report_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![report_id], |row| {
            Ok(crate::models::ReportRecord {
                report_id: row.get(0)?,
                case_id: row.get(1)?,
                report_type: row.get(2)?,
                file_path_pdf: row.get(3)?,
                file_path_json: row.get(4)?,
                signature: row.get(5)?,
                certificate_chain: row.get(6)?,
                trusted_timestamp: row.get(7)?,
            })
        })?;

        if let Some(res) = rows.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    /// Lists all reports generated for a given case.
    pub fn list_reports_for_case(&self, case_id: &str) -> Result<Vec<crate::models::ReportRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT report_id, case_id, report_type, file_path_pdf, file_path_json,
                    signature, certificate_chain, trusted_timestamp
             FROM reports WHERE case_id = ?1 ORDER BY report_id ASC",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            Ok(crate::models::ReportRecord {
                report_id: row.get(0)?,
                case_id: row.get(1)?,
                report_type: row.get(2)?,
                file_path_pdf: row.get(3)?,
                file_path_json: row.get(4)?,
                signature: row.get(5)?,
                certificate_chain: row.get(6)?,
                trusted_timestamp: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Retrieves all operations recorded for a given case.
    pub fn get_operations_for_case(&self, case_id: &str) -> Result<Vec<crate::models::OperationRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT op_id, case_id, evidence_id, op_type, parameters_json,
                    tool_version, build_id, started_at, completed_at, status
             FROM operations WHERE case_id = ?1 ORDER BY started_at ASC",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            Ok(crate::models::OperationRecord {
                op_id: row.get(0)?,
                case_id: row.get(1)?,
                evidence_id: row.get(2)?,
                op_type: row.get(3)?,
                parameters_json: row.get(4)?,
                tool_version: row.get(5)?,
                build_id: row.get(6)?,
                started_at: row.get(7)?,
                completed_at: row.get(8)?,
                status: row.get(9)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Retrieves all recovered artifacts recorded across operations for a case.
    pub fn get_recovered_artifacts_for_case(&self, case_id: &str) -> Result<Vec<crate::models::RecoveredArtifactRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ra.artifact_id, ra.op_id, ra.original_path, ra.recovered_path,
                    ra.file_type, ra.recovery_tier, ra.confidence_score,
                    ra.confidence_breakdown_json, ra.provenance_json
             FROM recovered_artifacts ra
             JOIN operations op ON ra.op_id = op.op_id
             WHERE op.case_id = ?1
             ORDER BY ra.artifact_id ASC",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            Ok(crate::models::RecoveredArtifactRecord {
                artifact_id: row.get(0)?,
                op_id: row.get(1)?,
                original_path: row.get(2)?,
                recovered_path: row.get(3)?,
                file_type: row.get(4)?,
                recovery_tier: row.get(5)?,
                confidence_score: row.get(6)?,
                confidence_breakdown_json: row.get(7)?,
                provenance_json: row.get(8)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Retrieves all forensic images recorded for evidence items in a case.
    pub fn get_forensic_images_for_case(&self, case_id: &str) -> Result<Vec<crate::models::ForensicImageRecord>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT fi.image_id, fi.evidence_id, fi.image_format, fi.file_path,
                    fi.acquisition_hash, fi.verification_hash, fi.bad_sector_map_json,
                    fi.acquired_at, fi.operator
             FROM forensic_images fi
             JOIN evidence_items ei ON fi.evidence_id = ei.evidence_id
             WHERE ei.case_id = ?1
             ORDER BY fi.acquired_at ASC",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            Ok(crate::models::ForensicImageRecord {
                image_id: row.get(0)?,
                evidence_id: row.get(1)?,
                image_format: row.get(2)?,
                file_path: row.get(3)?,
                acquisition_hash: row.get(4)?,
                verification_hash: row.get(5)?,
                bad_sector_map_json: row.get(6)?,
                acquired_at: row.get(7)?,
                operator: row.get(8)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}

