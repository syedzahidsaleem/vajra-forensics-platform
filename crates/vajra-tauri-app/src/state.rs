//! Thread-Safe Background Job Manager and Safety Gate Registry (§19, §20, §43).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use vajra_erase::{PendingSanitization, SanitizationAuthorizationToken};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    pub job_id: String,
    pub job_type: String, // "acquisition" or "sanitization"
    pub state: String,    // "queued", "running", "completed", "failed", "cancelled"
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub progress_percent: u32,
    pub current_speed_mbps: f64,
    pub elapsed_seconds: u64,
    pub estimated_remaining_seconds: u64,
    pub bad_sectors_count: u64,
    pub sha256_checksum: Option<String>,
    pub error_message: Option<String>,
    pub target_device: String,
    pub updated_at: String,
}

pub struct JobManager {
    jobs: Arc<Mutex<HashMap<String, JobProgress>>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_job(&self, progress: JobProgress) {
        let mut map = self.jobs.lock().unwrap();
        map.insert(progress.job_id.clone(), progress);
    }

    pub fn update_job<F>(&self, job_id: &str, update_fn: F)
    where
        F: FnOnce(&mut JobProgress),
    {
        let mut map = self.jobs.lock().unwrap();
        if let Some(job) = map.get_mut(job_id) {
            update_fn(job);
            job.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn get_job(&self, job_id: &str) -> Option<JobProgress> {
        let map = self.jobs.lock().unwrap();
        map.get(job_id).cloned()
    }
}

pub struct GateRegistry {
    pending_gates: Arc<Mutex<HashMap<String, PendingSanitization>>>,
    authorized_tokens: Arc<Mutex<HashMap<String, SanitizationAuthorizationToken>>>,
}

impl GateRegistry {
    pub fn new() -> Self {
        Self {
            pending_gates: Arc::new(Mutex::new(HashMap::new())),
            authorized_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn store_pending(&self, gate_id: String, pending: PendingSanitization) {
        let mut map = self.pending_gates.lock().unwrap();
        map.insert(gate_id, pending);
    }

    pub fn finalize_gate(
        &self,
        gate_id: &str,
        pre_exec_confirm: bool,
    ) -> Result<SanitizationAuthorizationToken, String> {
        let mut pending_map = self.pending_gates.lock().unwrap();
        let pending = pending_map
            .remove(gate_id)
            .ok_or_else(|| format!("Invalid or expired sanitization gate ID: {}", gate_id))?;

        let token = pending
            .finalize(pre_exec_confirm)
            .map_err(|e| e.to_string())?;

        let mut tokens_map = self.authorized_tokens.lock().unwrap();
        tokens_map.insert(token.token_id().to_string(), token.clone());

        Ok(token)
    }

    pub fn get_token(&self, token_id: &str) -> Option<SanitizationAuthorizationToken> {
        let map = self.authorized_tokens.lock().unwrap();
        map.get(token_id).cloned()
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_JOB_MANAGER: JobManager = JobManager::new();
    pub static ref GLOBAL_GATE_REGISTRY: GateRegistry = GateRegistry::new();
}
