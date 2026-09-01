//! Complete FAT filesystem parser and Tier-1 deleted/active file recovery engine (§25).

use crate::bpb::FatBpb;
use crate::dir_entry::{parse_standard_entry, FatDirEntry, LfnAccumulator};
use crate::error::FatError;
use crate::fat_table::FatTable;
use vajra_core::{
    DataLocation, FilesystemType, MetadataConfidence, ReadOnlyBlockSource, RecoverableFileEntry,
};

/// High-performance FAT filesystem scanner and recovery parser.
pub struct FatParser<'a> {
    source: &'a mut dyn ReadOnlyBlockSource,
    bpb: FatBpb,
    fat_table: FatTable,
}

impl<'a> FatParser<'a> {
    /// Initialize parser from a block source at `partition_start_lba`.
    pub fn new(
        source: &'a mut dyn ReadOnlyBlockSource,
        partition_start_lba: u64,
    ) -> Result<Self, FatError> {
        let boot_bytes = source.read_blocks(partition_start_lba, 1)?;
        let bpb = FatBpb::parse(partition_start_lba, &boot_bytes)?;
        let fat_table = FatTable::load(source, &bpb)?;

        Ok(Self {
            source,
            bpb,
            fat_table,
        })
    }

    /// Enumerate all active and recoverable deleted file entries on the volume.
    pub fn enumerate_all(&mut self) -> Result<Vec<RecoverableFileEntry>, FatError> {
        let mut results = Vec::new();
        let mut visited_dirs = std::collections::HashSet::new();

        // 1. Scan root directory
        match self.bpb.fat_type {
            FilesystemType::Fat32 => {
                let root_cluster = self.bpb.root_cluster;
                self.scan_directory_cluster_chain(root_cluster, "/", &mut visited_dirs, &mut results)?;
            }
            FilesystemType::Fat16 | FilesystemType::Fat12 => {
                self.scan_fat16_root_dir("/", &mut visited_dirs, &mut results)?;
            }
            _ => {}
        }

        // 2. Scan all data clusters for unreferenced / deleted directory fragments in slack space
        self.scan_unallocated_directory_slack(&mut results)?;

        Ok(results)
    }

    /// Scan FAT32 directory cluster chain recursively.
    fn scan_directory_cluster_chain(
        &mut self,
        start_cluster: u32,
        current_path: &str,
        visited_dirs: &mut std::collections::HashSet<u32>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), FatError> {
        if start_cluster < 2 || !visited_dirs.insert(start_cluster) {
            return Ok(());
        }

        let clusters = self.fat_table.follow_chain(start_cluster)?;
        let mut dir_entries = Vec::new();

        for &clus in &clusters {
            let lba = self.bpb.cluster_to_lba(clus)?;
            let data = self.source.read_blocks(lba, self.bpb.sectors_per_cluster as u32)?;
            self.parse_dir_block(&data, &mut dir_entries);
        }

        for entry in dir_entries {
            if entry.is_volume_label || entry.name_83 == "." || entry.name_83 == ".." {
                continue;
            }

            let entry_name = entry.display_name();
            let full_path = if current_path == "/" {
                format!("/{}", entry_name)
            } else {
                format!("{}/{}", current_path, entry_name)
            };

            let rec_entry = self.build_recoverable_entry(&entry, &full_path)?;
            results.push(rec_entry);

            if entry.is_directory && entry.start_cluster >= 2 && !entry.is_deleted {
                self.scan_directory_cluster_chain(
                    entry.start_cluster,
                    &full_path,
                    visited_dirs,
                    results,
                )?;
            }
        }

        Ok(())
    }

    /// Scan FAT12/16 dedicated root directory sector range.
    fn scan_fat16_root_dir(
        &mut self,
        current_path: &str,
        visited_dirs: &mut std::collections::HashSet<u32>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), FatError> {
        let root_lba = self.bpb.root_dir_lba;
        let root_sectors = self.bpb.root_dir_sectors;
        let data = self.source.read_blocks(root_lba, root_sectors)?;

        let mut dir_entries = Vec::new();
        self.parse_dir_block(&data, &mut dir_entries);

        for entry in dir_entries {
            if entry.is_volume_label || entry.name_83 == "." || entry.name_83 == ".." {
                continue;
            }

            let entry_name = entry.display_name();
            let full_path = if current_path == "/" {
                format!("/{}", entry_name)
            } else {
                format!("{}/{}", current_path, entry_name)
            };

            let rec_entry = self.build_recoverable_entry(&entry, &full_path)?;
            results.push(rec_entry);

            if entry.is_directory && entry.start_cluster >= 2 && !entry.is_deleted {
                self.scan_directory_cluster_chain(
                    entry.start_cluster,
                    &full_path,
                    visited_dirs,
                    results,
                )?;
            }
        }

        Ok(())
    }

    /// Scans raw cluster data for orphaned or deleted directory blocks.
    fn scan_unallocated_directory_slack(
        &mut self,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), FatError> {
        let total_clusters = self.bpb.total_clusters.min(100_000); // Bounded scan limit
        let mut lfn_acc = LfnAccumulator::new();

        for clus in 2..total_clusters + 2 {
            if self.fat_table.is_cluster_free(clus) {
                let lba = match self.bpb.cluster_to_lba(clus) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                if let Ok(data) = self.source.read_blocks(lba, self.bpb.sectors_per_cluster as u32) {
                    // Check if block looks like a directory block (contains 0xE5 or valid timestamps/attributes)
                    let mut found_deleted = Vec::new();
                    for chunk in data.chunks_exact(32) {
                        if chunk[11] == 0x0F {
                            lfn_acc.feed(chunk);
                        } else {
                            let lfn = lfn_acc.finalize();
                            if let Some(entry) = parse_standard_entry(chunk, lfn) {
                                if entry.is_deleted && entry.start_cluster >= 2 && entry.file_size > 0 {
                                    found_deleted.push(entry);
                                }
                            }
                        }
                    }

                    for entry in found_deleted {
                        let name = entry.display_name();
                        let path = format!("/[DELETED_SLACK]/{}", name);
                        // Avoid duplicates if already recovered
                        if !results.iter().any(|r| r.filename.as_deref() == Some(&name) && r.size_bytes == Some(entry.file_size)) {
                            if let Ok(rec) = self.build_recoverable_entry(&entry, &path) {
                                results.push(rec);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parses a directory data block into directory entries, handling LFN sequences.
    fn parse_dir_block(&self, block_data: &[u8], entries: &mut Vec<FatDirEntry>) {
        let mut lfn_acc = LfnAccumulator::new();

        for chunk in block_data.chunks_exact(32) {
            if chunk[0] == 0x00 {
                // End of directory block
                lfn_acc.clear();
                break;
            }

            if chunk[11] == 0x0F {
                lfn_acc.feed(chunk);
            } else {
                let lfn = lfn_acc.finalize();
                if let Some(entry) = parse_standard_entry(chunk, lfn) {
                    entries.push(entry);
                }
            }
        }
    }

    /// Converts a `FatDirEntry` into a canonical `RecoverableFileEntry`.
    fn build_recoverable_entry(
        &self,
        entry: &FatDirEntry,
        full_path: &str,
    ) -> Result<RecoverableFileEntry, FatError> {
        let (data_loc, confidence) = if entry.start_cluster < 2 {
            if entry.file_size == 0 {
                (DataLocation::Contiguous { start_lba: 0, block_count: 0 }, MetadataConfidence::Confirmed)
            } else {
                (DataLocation::Unresolved, MetadataConfidence::Low)
            }
        } else if entry.is_deleted {
            // Deleted file: check if FAT chain survived or if we should reconstruct from contiguous cluster run
            let chain = self.fat_table.follow_chain(entry.start_cluster)?;
            if !chain.is_empty() {
                // FAT chain survived!
                let extents = self.clusters_to_extents(&chain)?;
                let all_free = chain.iter().all(|&c| self.fat_table.is_cluster_free(c));
                let conf = if all_free {
                    MetadataConfidence::Confirmed
                } else {
                    MetadataConfidence::Partial
                };
                (self.extents_to_location(extents), conf)
            } else {
                // FAT chain was zeroed on deletion: reconstruct contiguous run from starting cluster
                let cluster_size = self.bpb.cluster_size_bytes();
                let needed_clusters = if cluster_size > 0 {
                    ((entry.file_size + cluster_size - 1) / cluster_size).max(1) as u32
                } else {
                    1
                };

                let mut contiguous_chain = Vec::with_capacity(needed_clusters as usize);
                let mut all_free = true;

                for c in entry.start_cluster..(entry.start_cluster + needed_clusters) {
                    if c >= self.bpb.total_clusters + 2 {
                        break;
                    }
                    if !self.fat_table.is_cluster_free(c) {
                        all_free = false;
                    }
                    contiguous_chain.push(c);
                }

                let extents = self.clusters_to_extents(&contiguous_chain)?;
                let conf = if all_free {
                    MetadataConfidence::Confirmed
                } else {
                    MetadataConfidence::Partial
                };
                (self.extents_to_location(extents), conf)
            }
        } else {
            // Active live file: follow intact FAT chain
            let chain = self.fat_table.follow_chain(entry.start_cluster)?;
            let extents = self.clusters_to_extents(&chain)?;
            (self.extents_to_location(extents), MetadataConfidence::Confirmed)
        };

        Ok(RecoverableFileEntry {
            id: entry.start_cluster as u64,
            original_path: Some(full_path.to_string()),
            filename: Some(entry.display_name()),
            size_bytes: Some(entry.file_size),
            created: entry.created_at,
            modified: entry.modified_at,
            accessed: entry.accessed_at,
            deleted: entry.is_deleted,
            data_location: data_loc,
            metadata_confidence: confidence,
            source_filesystem: self.bpb.fat_type,
        })
    }

    /// Converts a slice of clusters into contiguous LBA extent runs.
    fn clusters_to_extents(&self, clusters: &[u32]) -> Result<Vec<(u64, u64)>, FatError> {
        let mut extents = Vec::new();
        if clusters.is_empty() {
            return Ok(extents);
        }

        let spc = self.bpb.sectors_per_cluster as u64;
        let mut current_start_lba = self.bpb.cluster_to_lba(clusters[0])?;
        let mut current_block_count = spc;

        for window in clusters.windows(2) {
            let prev = window[0];
            let next = window[1];

            if next == prev + 1 {
                current_block_count += spc;
            } else {
                extents.push((current_start_lba, current_block_count));
                current_start_lba = self.bpb.cluster_to_lba(next)?;
                current_block_count = spc;
            }
        }

        extents.push((current_start_lba, current_block_count));
        Ok(extents)
    }

    /// Formats extents into `DataLocation`.
    fn extents_to_location(&self, extents: Vec<(u64, u64)>) -> DataLocation {
        if extents.is_empty() {
            DataLocation::Unresolved
        } else if extents.len() == 1 {
            DataLocation::Contiguous {
                start_lba: extents[0].0,
                block_count: extents[0].1,
            }
        } else {
            DataLocation::Fragmented(extents)
        }
    }
}
