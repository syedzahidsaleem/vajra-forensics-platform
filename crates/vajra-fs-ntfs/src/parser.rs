//! NTFS filesystem parser and Tier-1 recovery engine (§25).

use crate::bitmap::NtfsBitmap;
use crate::boot::NtfsBoot;
use crate::error::NtfsError;
use crate::mft::{
    apply_mft_fixup, parse_mft_record, MftRecord, MFT_MAGIC_FILE,
};
use crate::vss::VssInfo;
use vajra_core::{
    DataLocation, FilesystemType, MetadataConfidence, ReadOnlyBlockSource, RecoverableFileEntry,
};

/// High-performance NTFS filesystem analyzer and Tier-1 recovery parser.
pub struct NtfsParser<'a> {
    source: &'a mut dyn ReadOnlyBlockSource,
    boot: NtfsBoot,
    mft_extents: Vec<(u64, u64)>, // Physical LBAs of $MFT
    bitmap: Option<NtfsBitmap>,
    vss_info: VssInfo,
}

impl<'a> NtfsParser<'a> {
    /// Initialize parser from a block source at `partition_start_lba`.
    pub fn new(
        source: &'a mut dyn ReadOnlyBlockSource,
        partition_start_lba: u64,
    ) -> Result<Self, NtfsError> {
        let boot_bytes = source.read_blocks(partition_start_lba, 1)?;
        let boot = NtfsBoot::parse(partition_start_lba, &boot_bytes)?;

        // Read MFT record 0 ($MFT itself) at mft_start_lcn
        let mft_lba = boot.lcn_to_lba(boot.mft_start_lcn);
        let sectors_per_record = (boot.mft_record_size / boot.bytes_per_sector as u32).max(1);

        let mut mft0_bytes = source.read_blocks(mft_lba, sectors_per_record)?;
        let _ = apply_mft_fixup(&mut mft0_bytes, 0);
        let mft0 = parse_mft_record(0, &mft0_bytes, &boot)?;

        // Extract $MFT data extents from record 0 $DATA stream
        let mut mft_extents = Vec::new();
        if let Some(data_attr) = mft0.default_data_stream() {
            match &data_attr.location {
                DataLocation::Contiguous { start_lba, block_count } => {
                    mft_extents.push((*start_lba, *block_count));
                }
                DataLocation::Fragmented(exts) => {
                    mft_extents.extend(exts.clone());
                }
                _ => {}
            }
        }

        // Fallback: If $MFT data runs couldn't be extracted, use mft_start_lcn
        if mft_extents.is_empty() {
            mft_extents.push((mft_lba, 2048 * sectors_per_record as u64));
        }

        let mut parser = Self {
            source,
            boot,
            mft_extents,
            bitmap: None,
            vss_info: VssInfo::new(),
        };

        // Load $Bitmap from MFT record 6
        parser.load_bitmap();

        Ok(parser)
    }

    /// Loads `$Bitmap` allocation status from MFT record 6.
    fn load_bitmap(&mut self) {
        if let Ok(Some(rec6)) = self.read_mft_record(6) {
            if let Some(data_attr) = rec6.default_data_stream() {
                match &data_attr.location {
                    DataLocation::Resident(bytes) => {
                        self.bitmap = Some(NtfsBitmap::new(bytes.clone()));
                    }
                    DataLocation::Contiguous { start_lba, block_count } => {
                        if let Ok(bytes) = self.source.read_blocks(*start_lba, (*block_count).min(4096) as u32) {
                            self.bitmap = Some(NtfsBitmap::new(bytes));
                        }
                    }
                    DataLocation::Fragmented(exts) => {
                        let mut all_bytes = Vec::new();
                        for &(start_lba, block_count) in exts {
                            if let Ok(bytes) = self.source.read_blocks(start_lba, block_count.min(4096) as u32) {
                                all_bytes.extend(bytes);
                                if all_bytes.len() >= 1024 * 1024 {
                                    break;
                                }
                            }
                        }
                        self.bitmap = Some(NtfsBitmap::new(all_bytes));
                    }
                    _ => {}
                }
            }
        }
    }

    /// Enumerate all active and recoverable deleted files on the volume.
    pub fn enumerate_all(&mut self) -> Result<Vec<RecoverableFileEntry>, NtfsError> {
        let mut results = Vec::new();
        let mut record_map = std::collections::HashMap::new();

        // 1. Scan primary $MFT records
        self.scan_mft_records(&mut record_map, &mut results)?;

        // 2. Scan entire partition for orphaned MFT records surviving from previous filesystem / quick-format (§25)
        self.scan_unallocated_mft_records(&record_map, &mut results)?;

        Ok(results)
    }

    /// Scans standard $MFT records in sequential order.
    fn scan_mft_records(
        &mut self,
        record_map: &mut std::collections::HashMap<u64, (String, u64)>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), NtfsError> {
        let sectors_per_record = (self.boot.mft_record_size / self.boot.bytes_per_sector as u32).max(1) as u64;
        let mut current_record_num: u64 = 0;

        let extents = self.mft_extents.clone();

        for &(start_lba, block_count) in &extents {
            let total_records_in_extent = block_count / sectors_per_record;

            for r in 0..total_records_in_extent {
                let rec_num = current_record_num + r;
                let rec_lba = start_lba + (r * sectors_per_record);

                if let Ok(mut rec_bytes) = self.source.read_blocks(rec_lba, sectors_per_record as u32) {
                    if rec_bytes.len() >= 4 && (&rec_bytes[0..4] == MFT_MAGIC_FILE || &rec_bytes[0..4] == b"BAAD") {
                        let _ = apply_mft_fixup(&mut rec_bytes, rec_num);
                        if let Ok(record) = parse_mft_record(rec_num, &rec_bytes, &self.boot) {
                            if let Some(name) = record.display_name() {
                                self.vss_info.check_filename(&name);
                                let parent_ref = record.file_names.first().map(|f| f.parent_mft_ref).unwrap_or(0);
                                record_map.insert(rec_num, (name.clone(), parent_ref));

                                if let Some(rec_entry) = self.build_recoverable_entry(&record, &name, rec_num, false) {
                                    results.push(rec_entry);
                                }
                            }
                        }
                    }
                }
            }
            current_record_num += total_records_in_extent;
        }

        Ok(())
    }

    /// Scans raw cluster data across the partition for surviving MFT records (Quick-Format recovery §25).
    fn scan_unallocated_mft_records(
        &mut self,
        known_records: &std::collections::HashMap<u64, (String, u64)>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), NtfsError> {
        let sectors_per_cluster = self.boot.sectors_per_cluster as u32;
        let total_clusters = (self.boot.total_sectors / sectors_per_cluster as u64).min(200_000); // Bounded search limit

        for clus in 0..total_clusters {
            // If cluster is unallocated according to $Bitmap or outside primary MFT, check for "FILE" headers
            let is_free = self.bitmap.as_ref().map(|bm| bm.is_cluster_free(clus)).unwrap_or(true);
            if is_free {
                let lba = self.boot.lcn_to_lba(clus);
                if let Ok(cluster_bytes) = self.source.read_blocks(lba, sectors_per_cluster) {
                    let record_size = self.boot.mft_record_size as usize;
                    for (chunk_idx, chunk) in cluster_bytes.chunks_exact(record_size).enumerate() {
                        if chunk.len() >= 4 && &chunk[0..4] == MFT_MAGIC_FILE {
                            let mut raw_rec = chunk.to_vec();
                            let pseudo_rec_num = (clus * (sectors_per_cluster as u64 / (self.boot.mft_record_size as u64 / 512))) + chunk_idx as u64;
                            let _ = apply_mft_fixup(&mut raw_rec, pseudo_rec_num);

                            if let Ok(record) = parse_mft_record(pseudo_rec_num, &raw_rec, &self.boot) {
                                if let Some(name) = record.display_name() {
                                    // Check if this record is already known from primary $MFT
                                    if !known_records.values().any(|(n, _)| n == &name)
                                        && !results.iter().any(|r| r.filename.as_deref() == Some(&name))
                                    {
                                        if let Some(rec_entry) = self.build_recoverable_entry(&record, &name, pseudo_rec_num, true) {
                                            results.push(rec_entry);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Read a specific MFT record by number.
    pub fn read_mft_record(&mut self, record_num: u64) -> Result<Option<MftRecord>, NtfsError> {
        let sectors_per_record = (self.boot.mft_record_size / self.boot.bytes_per_sector as u32).max(1) as u64;
        let mut target_lba = None;
        let mut accumulated_records: u64 = 0;

        for &(start_lba, block_count) in &self.mft_extents {
            let records_in_extent = block_count / sectors_per_record;
            if record_num >= accumulated_records && record_num < accumulated_records + records_in_extent {
                let offset_in_extent = record_num - accumulated_records;
                target_lba = Some(start_lba + (offset_in_extent * sectors_per_record));
                break;
            }
            accumulated_records += records_in_extent;
        }

        let lba = match target_lba {
            Some(l) => l,
            None => return Ok(None),
        };

        let mut rec_bytes = self.source.read_blocks(lba, sectors_per_record as u32)?;
        if rec_bytes.len() < 4 || (&rec_bytes[0..4] != MFT_MAGIC_FILE && &rec_bytes[0..4] != b"BAAD") {
            return Ok(None);
        }

        let _ = apply_mft_fixup(&mut rec_bytes, record_num);
        let record = parse_mft_record(record_num, &rec_bytes, &self.boot)?;
        Ok(Some(record))
    }

    /// Builds a canonical `RecoverableFileEntry` from an `MftRecord`.
    fn build_recoverable_entry(
        &self,
        record: &MftRecord,
        name: &str,
        record_id: u64,
        force_deleted: bool,
    ) -> Option<RecoverableFileEntry> {
        // Skip system metadata records $MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, etc. (0..=15)
        // unless they represent user files or deleted targets
        if record.record_num < 16 && name.starts_with('$') {
            return None;
        }

        let is_deleted = !record.is_in_use || force_deleted;
        let std_info = record.standard_info.as_ref();
        let fn_attr = record.file_names.first();

        let created = std_info.and_then(|s| s.created).or_else(|| fn_attr.and_then(|f| f.created));
        let modified = std_info.and_then(|s| s.modified).or_else(|| fn_attr.and_then(|f| f.modified));
        let accessed = std_info.and_then(|s| s.accessed).or_else(|| fn_attr.and_then(|f| f.accessed));

        let data_stream = record.default_data_stream();
        let size_bytes = data_stream.map(|d| d.real_size).or_else(|| fn_attr.map(|f| f.real_size));
        let location = data_stream.map(|d| d.location.clone()).unwrap_or(DataLocation::Unresolved);

        let confidence = match &location {
            DataLocation::Resident(_) => {
                if is_deleted {
                    MetadataConfidence::Confirmed // Resident data inside deleted MFT record is 100% intact!
                } else {
                    MetadataConfidence::Confirmed
                }
            }
            DataLocation::Contiguous { start_lba, block_count } => {
                if let Some(ref bm) = self.bitmap {
                    if is_deleted {
                        bm.evaluate_extents_confidence(&[(*start_lba, *block_count)], &self.boot)
                    } else {
                        MetadataConfidence::Confirmed
                    }
                } else {
                    MetadataConfidence::Partial
                }
            }
            DataLocation::Fragmented(exts) => {
                if let Some(ref bm) = self.bitmap {
                    if is_deleted {
                        bm.evaluate_extents_confidence(exts, &self.boot)
                    } else {
                        MetadataConfidence::Confirmed
                    }
                } else {
                    MetadataConfidence::Partial
                }
            }
            DataLocation::Unresolved => MetadataConfidence::Low,
        };

        let path = format!("/{}", name);

        Some(RecoverableFileEntry {
            id: record_id,
            original_path: Some(path),
            filename: Some(name.to_string()),
            size_bytes,
            created,
            modified,
            accessed,
            deleted: is_deleted,
            data_location: location,
            metadata_confidence: confidence,
            source_filesystem: FilesystemType::Ntfs,
        })
    }

    /// Access detected Volume Shadow Copy presence status.
    pub fn vss_info(&self) -> &VssInfo {
        &self.vss_info
    }
}
