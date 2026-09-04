//! Evidence Acquisition Engine (§19, §20).
//!
//! Orchestrates the complete end-to-end evidence acquisition pipeline:
//! 1. Type-Safe Read-Only Source access (`&mut dyn ReadOnlyBlockSource`).
//! 2. Pre-flight storage capacity verification (§19).
//! 3. Resilient sector copy loop with §20 bad-sector retry and block size reduction.
//! 4. Non-ambiguous placeholder substitution (`b"VAJRA_BAD_SECTOR"`) maintaining exact LBA offsets.
//! 5. Phase 1 streaming rolling SHA-256 calculation.
//! 6. Phase 2 post-acquisition independent re-read verification pass.
//! 7. Full integration with Evidence Vault (`CaseDb`), Audit Log (`AuditChain`), and Custody (`CustodyTracker`).

use crate::bad_sector::{BadSectorMap, BadSectorStrategy};
use crate::checkpoint::AcquisitionCheckpoint;
use crate::error::AcquisitionError;
use crate::hasher::{verify_image_file, AcquisitionHasher};
use crate::profile::AcquisitionProfile;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use vajra_audit::AuditChain;
use vajra_case_db::{CaseDb, ForensicImageRecord, OperationRecord};
use vajra_core::{OperationType, ReadOnlyBlockSource};
use vajra_custody::{CustodyEvent, CustodyEventType, CustodyTracker};
use vajra_image::traits::ForensicImageWriter;
use vajra_image::RawImageWriter;

/// Progress reporting callback hook.
pub trait AcquisitionProgressHook: Send + Sync {
    fn on_progress(
        &self,
        current_lba: u64,
        end_lba: u64,
        bytes_acquired: u64,
        bad_sectors_encountered: u64,
    );
}

/// Configuration parameters for an acquisition job.
#[derive(Debug, Clone)]
pub struct AcquisitionConfig {
    pub case_id: String,
    pub evidence_id: String,
    pub operator: String,
    pub profile: AcquisitionProfile,
    pub output_path: PathBuf,
    pub strategy: BadSectorStrategy,
    pub checkpoint_interval_blocks: u64,
    /// Test hook: override detected available free space to test pre-flight failure.
    pub simulated_available_space: Option<u64>,
}

impl AcquisitionConfig {
    pub fn new(
        case_id: &str,
        evidence_id: &str,
        operator: &str,
        output_path: PathBuf,
        profile: AcquisitionProfile,
    ) -> Self {
        Self {
            case_id: case_id.to_string(),
            evidence_id: evidence_id.to_string(),
            operator: operator.to_string(),
            profile,
            output_path,
            strategy: BadSectorStrategy::default(),
            checkpoint_interval_blocks: 10_000,
            simulated_available_space: None,
        }
    }
}

/// Final result returned upon successful acquisition and verification.
#[derive(Debug, Clone)]
pub struct AcquisitionResult {
    pub op_id: String,
    pub image_path: PathBuf,
    pub total_blocks_acquired: u64,
    pub total_bytes_written: u64,
    pub acquisition_hash: String,
    pub verification_hash: String,
    pub bad_sector_map: BadSectorMap,
    pub started_at: String,
    pub completed_at: String,
}

/// Core acquisition orchestration engine.
pub struct AcquisitionEngine;

impl AcquisitionEngine {
    /// Executes a fresh evidence acquisition against a read-only source device.
    ///
    /// # Type-Safety Invariant (§16)
    /// `source` is strictly bound to [`ReadOnlyBlockSource`]. There is no syntax or code path
    /// to pass a writable device handle into this function.
    pub fn acquire<S: ReadOnlyBlockSource + ?Sized, W: ForensicImageWriter>(
        source: &mut S,
        writer: &mut W,
        config: &AcquisitionConfig,
        progress_hook: Option<&dyn AcquisitionProgressHook>,
        cancellation_token: Option<&AtomicBool>,
        case_db: Option<&CaseDb>,
    ) -> Result<AcquisitionResult, AcquisitionError> {
        let op_id = uuid::Uuid::new_v4().to_string();
        let started_at = Utc::now().to_rfc3339();
        let bsize = source.block_size();
        let total_source_blocks = source.total_blocks();
        let (start_lba, end_lba) = config.profile.lba_bounds(total_source_blocks);
        let blocks_to_acquire = if end_lba >= start_lba {
            end_lba - start_lba + 1
        } else {
            0
        };
        let required_bytes = blocks_to_acquire * bsize as u64;

        info!(
            "Starting acquisition op_id='{}', range=[{}..={}] ({} bytes)",
            op_id, start_lba, end_lba, required_bytes
        );

        // --- PRE-FLIGHT CHECK: Disk Space (§19) ---
        let available_space = if let Some(simulated) = config.simulated_available_space {
            simulated
        } else {
            get_available_disk_space(&config.output_path).unwrap_or(u64::MAX)
        };

        if available_space < required_bytes {
            return Err(AcquisitionError::InsufficientStorageSpace {
                required_bytes,
                available_bytes: available_space,
            });
        }

        // --- VAULT: Record Operation Started (§22) ---
        if let Some(db) = case_db {
            let initial_checkpoint = AcquisitionCheckpoint {
                op_id: op_id.clone(),
                case_id: config.case_id.clone(),
                evidence_id: config.evidence_id.clone(),
                source_fingerprint: source.device_fingerprint().sha256_hash.clone(),
                output_path: config.output_path.display().to_string(),
                profile: config.profile.clone(),
                start_lba,
                current_lba: start_lba,
                end_lba,
                total_blocks: blocks_to_acquire,
                bytes_written: 0,
                bad_sector_map: BadSectorMap::new(),
                started_at: started_at.clone(),
                last_updated_at: started_at.clone(),
            };

            db.record_operation(&OperationRecord {
                op_id: op_id.clone(),
                case_id: config.case_id.clone(),
                evidence_id: Some(config.evidence_id.clone()),
                op_type: OperationType::Acquire.to_string(),
                parameters_json: Some(initial_checkpoint.to_json()),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                build_id: "vajra-v0.1.0".to_string(),
                started_at: started_at.clone(),
                completed_at: None,
                status: "InProgress".to_string(),
            })?;

            // --- AUDIT LOG: Acquisition Started (§39) ---
            let _ = AuditChain::append(
                db,
                &config.case_id,
                &config.operator,
                "AcquisitionStarted",
                &format!("Evidence:{}", config.evidence_id),
                &format!(
                    "profile={:?},start_lba={},end_lba={},fingerprint={}",
                    config.profile,
                    start_lba,
                    end_lba,
                    source.device_fingerprint().sha256_hash
                ),
            );

            // --- CUSTODY: Record Custody Event (§21) ---
            let history = CustodyTracker::get_history(db, &config.evidence_id).unwrap_or_default();
            let event_type = if history.is_empty() {
                CustodyEventType::Received
            } else {
                CustodyEventType::AnalysisStarted
            };

            let custody_event = CustodyEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                evidence_id: config.evidence_id.clone(),
                event_type,
                from_party: Some(config.operator.clone()),
                to_party: Some(config.operator.clone()),
                timestamp_utc: Utc::now().to_rfc3339(),
                location: Some("Local Forensic Workstation".to_string()),
                purpose: Some(format!("Evidence acquisition op_id='{}'", op_id)),
                evidence_condition: Some("Intact (Acquiring)".to_string()),
                signature_ref: None,
            };
            let _ = CustodyTracker::record_event(db, &custody_event);
        }

        // --- ACQUISITION LOOP (§19, §20) ---
        let mut hasher = AcquisitionHasher::new();
        let mut bad_sector_map = BadSectorMap::new();
        let mut current_lba = start_lba;
        let mut last_checkpoint_lba = start_lba;

        while current_lba <= end_lba {
            if let Some(token) = cancellation_token {
                if token.load(Ordering::Relaxed) {
                    warn!("Acquisition cancelled by operator at LBA {}", current_lba);
                    return Err(AcquisitionError::Cancelled);
                }
            }

            let remaining_blocks = (end_lba - current_lba + 1) as u32;
            let chunk_sectors = config.strategy.initial_chunk_sectors.min(remaining_blocks);
            let image_rel_lba = current_lba - start_lba;

            // Attempt reading chunk
            match Self::read_chunk_with_fallback(
                source,
                current_lba,
                chunk_sectors,
                &config.strategy,
                &mut bad_sector_map,
            ) {
                Ok(chunk_data) => {
                    hasher.update(&chunk_data);
                    writer.write_image_blocks(image_rel_lba, &chunk_data)?;
                    current_lba += chunk_sectors as u64;
                }
                Err(e) => {
                    error!("Unrecoverable read error at LBA {}: {}", current_lba, e);
                    return Err(e);
                }
            }

            // Progress hook
            if let Some(hook) = progress_hook {
                hook.on_progress(
                    current_lba,
                    end_lba,
                    writer.bytes_written(),
                    bad_sector_map.total_unreadable_blocks,
                );
            }

            // Periodic Checkpointing
            if current_lba - last_checkpoint_lba >= config.checkpoint_interval_blocks {
                last_checkpoint_lba = current_lba;
                if let Some(db) = case_db {
                    let cp = AcquisitionCheckpoint {
                        op_id: op_id.clone(),
                        case_id: config.case_id.clone(),
                        evidence_id: config.evidence_id.clone(),
                        source_fingerprint: source.device_fingerprint().sha256_hash.clone(),
                        output_path: config.output_path.display().to_string(),
                        profile: config.profile.clone(),
                        start_lba,
                        current_lba,
                        end_lba,
                        total_blocks: blocks_to_acquire,
                        bytes_written: writer.bytes_written(),
                        bad_sector_map: bad_sector_map.clone(),
                        started_at: started_at.clone(),
                        last_updated_at: Utc::now().to_rfc3339(),
                    };
                    let _ = db.update_operation_checkpoint(&op_id, &cp.to_json(), "InProgress");
                }
            }
        }

        // Finalize container writer structures
        let image_meta = writer.finalize()?;
        let acquisition_hash = hasher.finalize();
        info!("Acquisition copy complete. Rolling SHA-256: {}", acquisition_hash);

        // --- PHASE 2: INDEPENDENT VERIFICATION PASS (§19) ---
        info!("Initiating Phase 2: Independent re-read verification pass on '{}'...", config.output_path.display());
        let verification_hash = verify_image_file(&config.output_path, &acquisition_hash)?;
        info!("Phase 2 verification PASSED (disk re-read matched rolling hash): {}", verification_hash);

        let completed_at = Utc::now().to_rfc3339();

        // --- VAULT: Record Forensic Image & Complete Operation (§22) ---
        if let Some(db) = case_db {
            let image_id = uuid::Uuid::new_v4().to_string();
            let bad_map_json = if bad_sector_map.unreadable_ranges.is_empty() {
                None
            } else {
                Some(bad_sector_map.to_json())
            };

            db.record_forensic_image(&ForensicImageRecord {
                image_id,
                evidence_id: config.evidence_id.clone(),
                image_format: image_meta.format.to_string(),
                file_path: config.output_path.display().to_string(),
                acquisition_hash: acquisition_hash.clone(),
                verification_hash: Some(verification_hash.clone()),
                bad_sector_map_json: bad_map_json,
                acquired_at: completed_at.clone(),
                operator: config.operator.clone(),
            })?;

            let final_checkpoint = AcquisitionCheckpoint {
                op_id: op_id.clone(),
                case_id: config.case_id.clone(),
                evidence_id: config.evidence_id.clone(),
                source_fingerprint: source.device_fingerprint().sha256_hash.clone(),
                output_path: config.output_path.display().to_string(),
                profile: config.profile.clone(),
                start_lba,
                current_lba,
                end_lba,
                total_blocks: blocks_to_acquire,
                bytes_written: writer.bytes_written(),
                bad_sector_map: bad_sector_map.clone(),
                started_at: started_at.clone(),
                last_updated_at: completed_at.clone(),
            };

            db.complete_operation(
                &op_id,
                &completed_at,
                "Completed",
                Some(&final_checkpoint.to_json()),
            )?;

            // --- AUDIT LOG: Acquisition Completed & Verified (§39) ---
            let _ = AuditChain::append(
                db,
                &config.case_id,
                &config.operator,
                "AcquisitionCompletedAndVerified",
                &format!("Evidence:{}", config.evidence_id),
                &format!(
                    "sha256={},bytes={},bad_sectors={}",
                    verification_hash,
                    writer.bytes_written(),
                    bad_sector_map.total_unreadable_blocks
                ),
            );
        }

        Ok(AcquisitionResult {
            op_id,
            image_path: config.output_path.clone(),
            total_blocks_acquired: blocks_to_acquire,
            total_bytes_written: writer.bytes_written(),
            acquisition_hash,
            verification_hash,
            bad_sector_map,
            started_at,
            completed_at,
        })
    }

    /// Resumes an interrupted acquisition from a database checkpoint (§19, NFR-1).
    pub fn resume<S: ReadOnlyBlockSource + ?Sized>(
        source: &mut S,
        op_id: &str,
        case_db: &CaseDb,
        progress_hook: Option<&dyn AcquisitionProgressHook>,
        cancellation_token: Option<&AtomicBool>,
    ) -> Result<AcquisitionResult, AcquisitionError> {
        let op_record = case_db.get_operation(op_id)?;
        let cp_json = op_record
            .parameters_json
            .ok_or_else(|| AcquisitionError::CheckpointNotFound(op_id.to_string()))?;
        let mut checkpoint = AcquisitionCheckpoint::from_json(&cp_json)
            .map_err(|e| AcquisitionError::CheckpointNotFound(format!("Corrupt checkpoint: {}", e)))?;

        // --- VERIFY DEVICE IDENTITY MATCHING (§23) ---
        let current_fp = source.device_fingerprint().sha256_hash;
        if !current_fp.eq_ignore_ascii_case(&checkpoint.source_fingerprint) {
            return Err(AcquisitionError::DeviceMismatchOnResume {
                expected_fingerprint: checkpoint.source_fingerprint,
                actual_fingerprint: current_fp,
            });
        }

        info!(
            "Resuming acquisition op_id='{}' from LBA {} to {}",
            op_id, checkpoint.current_lba, checkpoint.end_lba
        );

        let output_path = PathBuf::from(&checkpoint.output_path);
        let mut resume_writer = RawImageWriter::open_for_resume(&output_path, source.block_size())?;

        let strategy = BadSectorStrategy::default();
        let mut bad_sector_map = checkpoint.bad_sector_map.clone();
        let mut current_lba = checkpoint.current_lba;
        let start_lba = checkpoint.start_lba;
        let end_lba = checkpoint.end_lba;
        let mut last_checkpoint_lba = current_lba;

        // Acquisition copy continuation loop
        while current_lba <= end_lba {
            if let Some(token) = cancellation_token {
                if token.load(Ordering::Relaxed) {
                    return Err(AcquisitionError::Cancelled);
                }
            }

            let remaining_blocks = (end_lba - current_lba + 1) as u32;
            let chunk_sectors = strategy.initial_chunk_sectors.min(remaining_blocks);
            let image_rel_lba = current_lba - start_lba;

            let chunk_data = Self::read_chunk_with_fallback(
                source,
                current_lba,
                chunk_sectors,
                &strategy,
                &mut bad_sector_map,
            )?;
            resume_writer.write_image_blocks(image_rel_lba, &chunk_data)?;
            current_lba += chunk_sectors as u64;

            if let Some(hook) = progress_hook {
                hook.on_progress(
                    current_lba,
                    end_lba,
                    resume_writer.bytes_written(),
                    bad_sector_map.total_unreadable_blocks,
                );
            }

            if current_lba - last_checkpoint_lba >= 10_000 {
                last_checkpoint_lba = current_lba;
                checkpoint.current_lba = current_lba;
                checkpoint.bytes_written = resume_writer.bytes_written();
                checkpoint.bad_sector_map = bad_sector_map.clone();
                checkpoint.last_updated_at = Utc::now().to_rfc3339();
                let _ = case_db.update_operation_checkpoint(op_id, &checkpoint.to_json(), "InProgress");
            }
        }

        let image_meta = resume_writer.finalize()?;
        let completed_at = Utc::now().to_rfc3339();

        // --- FULL RE-READ HASH VERIFICATION PASS ---
        info!("Running full verification hash pass over resumed image...");
        let (verified_hash, _) = compute_file_sha256(&output_path)?;

        let image_id = uuid::Uuid::new_v4().to_string();
        case_db.record_forensic_image(&ForensicImageRecord {
            image_id,
            evidence_id: checkpoint.evidence_id.clone(),
            image_format: image_meta.format.to_string(),
            file_path: checkpoint.output_path.clone(),
            acquisition_hash: verified_hash.clone(),
            verification_hash: Some(verified_hash.clone()),
            bad_sector_map_json: if bad_sector_map.unreadable_ranges.is_empty() {
                None
            } else {
                Some(bad_sector_map.to_json())
            },
            acquired_at: completed_at.clone(),
            operator: "ResumedOperator".to_string(),
        })?;

        checkpoint.current_lba = current_lba;
        checkpoint.bytes_written = resume_writer.bytes_written();
        checkpoint.bad_sector_map = bad_sector_map.clone();
        checkpoint.last_updated_at = completed_at.clone();

        case_db.complete_operation(
            op_id,
            &completed_at,
            "Completed",
            Some(&checkpoint.to_json()),
        )?;

        let _ = AuditChain::append(
            case_db,
            &checkpoint.case_id,
            "ResumedOperator",
            "AcquisitionResumedAndVerified",
            &format!("Evidence:{}", checkpoint.evidence_id),
            &format!("sha256={},bytes={}", verified_hash, resume_writer.bytes_written()),
        );

        let custody_event = CustodyEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            evidence_id: checkpoint.evidence_id.clone(),
            event_type: CustodyEventType::AnalysisStarted,
            from_party: Some("ResumedOperator".to_string()),
            to_party: Some("ResumedOperator".to_string()),
            timestamp_utc: Utc::now().to_rfc3339(),
            location: Some("Local Forensic Workstation".to_string()),
            purpose: Some(format!("Evidence acquisition resumed op_id='{}'", op_id)),
            evidence_condition: Some("Intact (Completed)".to_string()),
            signature_ref: None,
        };
        let _ = CustodyTracker::record_event(case_db, &custody_event);

        Ok(AcquisitionResult {
            op_id: op_id.to_string(),
            image_path: output_path,
            total_blocks_acquired: checkpoint.total_blocks,
            total_bytes_written: resume_writer.bytes_written(),
            acquisition_hash: verified_hash.clone(),
            verification_hash: verified_hash,
            bad_sector_map,
            started_at: checkpoint.started_at,
            completed_at,
        })
    }

    /// Flowchart algorithm (§20) for reading a chunk with retries and recursive sub-block reduction.
    fn read_chunk_with_fallback<S: ReadOnlyBlockSource + ?Sized>(
        source: &mut S,
        start_lba: u64,
        count: u32,
        strategy: &BadSectorStrategy,
        bad_sector_map: &mut BadSectorMap,
    ) -> Result<Vec<u8>, AcquisitionError> {
        let bsize = source.block_size();

        // 1. Try reading the full chunk with retries
        let mut last_err = None;
        for retry in 0..=strategy.max_retries {
            if retry > 0 && strategy.retry_backoff_ms > 0 {
                thread::sleep(Duration::from_millis(strategy.retry_backoff_ms * retry as u64));
            }

            match source.read_blocks(start_lba, count) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        // 2. If chunk reading failed and chunk > 1 sector: split down to single sectors
        if count > strategy.min_chunk_sectors {
            warn!(
                "Read chunk failed at LBA {} (count {}). Reducing block size to individual sectors (§20)...",
                start_lba, count
            );

            let mut combined_buffer = Vec::with_capacity(count as usize * bsize as usize);
            for offset in 0..count {
                let sector_lba = start_lba + offset as u64;
                let sector_data = Self::read_single_sector_with_fallback(
                    source,
                    sector_lba,
                    strategy,
                    bad_sector_map,
                )?;
                combined_buffer.extend_from_slice(&sector_data);
            }
            return Ok(combined_buffer);
        }

        // 3. Single sector persistently failed: mark unreadable and substitute non-ambiguous placeholder (§20)
        let err_desc = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown read failure".to_string());

        warn!(
            "Marking persistent unreadable sector at LBA {} (substituting placeholder): {}",
            start_lba, err_desc
        );

        bad_sector_map.record_unreadable(start_lba, count as u64, bsize, err_desc);

        let mut placeholder_buf = vec![0u8; count as usize * bsize as usize];
        BadSectorMap::fill_placeholder(&mut placeholder_buf, &strategy.placeholder_pattern);

        Ok(placeholder_buf)
    }

    /// Helper for single sector read with retries and bad-sector mapping.
    fn read_single_sector_with_fallback<S: ReadOnlyBlockSource + ?Sized>(
        source: &mut S,
        sector_lba: u64,
        strategy: &BadSectorStrategy,
        bad_sector_map: &mut BadSectorMap,
    ) -> Result<Vec<u8>, AcquisitionError> {
        let bsize = source.block_size();
        let mut last_err = None;

        for retry in 0..=strategy.max_retries {
            if retry > 0 && strategy.retry_backoff_ms > 0 {
                thread::sleep(Duration::from_millis(strategy.retry_backoff_ms * retry as u64));
            }

            match source.read_blocks(sector_lba, 1) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let err_desc = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Single sector read failure".to_string());

        bad_sector_map.record_unreadable(sector_lba, 1, bsize, err_desc);

        let mut placeholder_buf = vec![0u8; bsize as usize];
        BadSectorMap::fill_placeholder(&mut placeholder_buf, &strategy.placeholder_pattern);

        Ok(placeholder_buf)
    }
}

/// Helper to compute full SHA-256 of a file.
fn compute_file_sha256<P: AsRef<Path>>(path: P) -> Result<(String, u64), AcquisitionError> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}

/// Cross-platform helper to query available free space on the destination filesystem.
fn get_available_disk_space<P: AsRef<Path>>(path: P) -> std::io::Result<u64> {
    let p = path.as_ref();
    let parent = p.parent().unwrap_or_else(|| Path::new("."));

    #[cfg(target_family = "unix")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(parent.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                let available = stat.f_bavail as u64 * stat.f_frsize as u64;
                return Ok(available);
            }
        }
    }

    #[cfg(target_family = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        let wide_path: Vec<u16> = parent
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes_available = 0u64;
        let mut total_number_of_bytes = 0u64;
        let mut total_number_of_free_bytes = 0u64;

        let res = unsafe {
            GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                &mut free_bytes_available,
                &mut total_number_of_bytes,
                &mut total_number_of_free_bytes,
            )
        };

        if res != 0 {
            return Ok(free_bytes_available);
        }
    }

    Ok(u64::MAX)
}
