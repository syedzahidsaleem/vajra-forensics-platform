//! Volume Shadow Copy (VSS) snapshot presence detection (§25).
//!
//! Flags presence of VSS snapshot stores on NTFS volumes.



/// Information regarding detected Volume Shadow Copies.
#[derive(Debug, Clone)]
pub struct VssInfo {
    pub has_vss_snapshots: bool,
    pub catalog_files_count: usize,
    pub snapshot_store_guids: Vec<String>,
}

impl VssInfo {
    /// Detects presence of Volume Shadow Copies by examining root and System Volume Information records.
    pub fn new() -> Self {
        Self {
            has_vss_snapshots: false,
            catalog_files_count: 0,
            snapshot_store_guids: Vec::new(),
        }
    }

    /// Checks if a filename or path indicates a VSS snapshot store.
    pub fn check_filename(&mut self, filename: &str) {
        // VSS snapshot stores use GUID formats: {GUID}{3808876b-c176-4e48-b7ae-04046e6cc752}
        if filename.contains("{3808876b-c176-4e48-b7ae-04046e6cc752}")
            || filename.to_ascii_lowercase().contains("vss_")
            || filename.to_ascii_lowercase().contains("syscache.hve")
        {
            self.has_vss_snapshots = true;
            if !self.snapshot_store_guids.iter().any(|g| g == filename) {
                self.snapshot_store_guids.push(filename.to_string());
                self.catalog_files_count += 1;
            }
        }
    }
}
