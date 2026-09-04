//! ext4 filesystem parser and Tier-1 recovery engine (§25).

use crate::bitmap::Ext4BlockBitmap;
use crate::dir::parse_dir_block;
use crate::error::Ext4Error;
use crate::group_desc::BlockGroupDescriptor;
use crate::inode::Ext4Inode;
use crate::superblock::{Ext4Superblock, EXT4_SUPERBLOCK_OFFSET_BYTES};
use vajra_core::{
    DataLocation, FilesystemType, MetadataConfidence, ReadOnlyBlockSource, RecoverableFileEntry,
};

/// High-performance ext4 filesystem analyzer and recovery parser.
pub struct Ext4Parser<'a> {
    source: &'a mut dyn ReadOnlyBlockSource,
    sb: Ext4Superblock,
    group_descriptors: Vec<BlockGroupDescriptor>,
    bitmap: Option<Ext4BlockBitmap>,
}

impl<'a> Ext4Parser<'a> {
    /// Initialize parser from a block source at `partition_start_lba`.
    pub fn new(
        source: &'a mut dyn ReadOnlyBlockSource,
        partition_start_lba: u64,
    ) -> Result<Self, Ext4Error> {
        // Read superblock at byte offset 1024 (LBA 2 for 512B sectors)
        let sb_lba = partition_start_lba + (EXT4_SUPERBLOCK_OFFSET_BYTES / 512);
        let sb_bytes = source.read_blocks(sb_lba, 2)?;
        let sb = Ext4Superblock::parse(partition_start_lba, &sb_bytes)?;
        let group_descriptors = BlockGroupDescriptor::load_all(source, &sb)?;
        let bitmap = Ext4BlockBitmap::load_all(source, &sb, &group_descriptors).ok();

        Ok(Self {
            source,
            sb,
            group_descriptors,
            bitmap,
        })
    }

    /// Enumerate all active files and recoverable deleted files on the volume.
    pub fn enumerate_all(&mut self) -> Result<Vec<RecoverableFileEntry>, Ext4Error> {
        let mut results = Vec::new();
        let mut inode_name_map = std::collections::HashMap::new();
        let mut visited_inodes = std::collections::HashSet::new();

        // 1. Scan directory tree starting at root inode (inum 2)
        self.scan_directory_tree(2, "/", &mut inode_name_map, &mut visited_inodes, &mut results)?;

        // 2. Scan all inode tables across all block groups to find unlinked / deleted inodes
        self.scan_all_inode_tables(&inode_name_map, &visited_inodes, &mut results)?;

        Ok(results)
    }

    /// Recursively traverses ext4 directory hierarchy.
    fn scan_directory_tree(
        &mut self,
        dir_inum: u64,
        current_path: &str,
        name_map: &mut std::collections::HashMap<u64, (String, String)>,
        visited_inodes: &mut std::collections::HashSet<u64>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), Ext4Error> {
        if !visited_inodes.insert(dir_inum) {
            return Ok(());
        }

        let inode = match self.read_inode(dir_inum)? {
            Some(ino) => ino,
            None => return Ok(()),
        };

        if !inode.is_directory {
            return Ok(());
        }

        let extents = inode.get_block_extents(self.source, &self.sb)?;
        let sectors_per_block = (self.sb.block_size / 512) as u32;

        let mut subdirs_to_visit = Vec::new();

        for (start_block, count) in extents {
            for b in 0..count {
                let lba = self.sb.block_to_lba(start_block + b);
                if let Ok(block_data) = self.source.read_blocks(lba, sectors_per_block) {
                    let entries = parse_dir_block(&block_data);
                    for ent in entries {
                        if ent.name == "." || ent.name == ".." {
                            continue;
                        }

                        let full_path = if current_path == "/" {
                            format!("/{}", ent.name)
                        } else {
                            format!("{}/{}", current_path, ent.name)
                        };

                        name_map.insert(ent.inode, (ent.name.clone(), full_path.clone()));

                        if ent.file_type == 2 && !ent.is_unlinked_slack {
                            subdirs_to_visit.push((ent.inode, full_path.clone()));
                        }

                        // Process this entry
                        if let Ok(Some(target_inode)) = self.read_inode(ent.inode) {
                            if !target_inode.is_directory || ent.is_unlinked_slack {
                                let rec = self.build_entry_from_inode(&target_inode, Some(&ent.name), Some(&full_path), ent.is_unlinked_slack)?;
                                results.push(rec);
                                visited_inodes.insert(ent.inode);
                            }
                        }
                    }
                }
            }
        }

        for (subdir_inum, subdir_path) in subdirs_to_visit {
            self.scan_directory_tree(subdir_inum, &subdir_path, name_map, visited_inodes, results)?;
        }

        Ok(())
    }

    /// Scans all inode tables across all block groups to locate unlinked/deleted inodes.
    fn scan_all_inode_tables(
        &mut self,
        name_map: &std::collections::HashMap<u64, (String, String)>,
        visited_inodes: &std::collections::HashSet<u64>,
        results: &mut Vec<RecoverableFileEntry>,
    ) -> Result<(), Ext4Error> {
        let inodes_per_group = self.sb.inodes_per_group as u64;
        let inode_size = self.sb.inode_size as usize;
        let sectors_per_block = (self.sb.block_size / 512) as u32;
        let inodes_per_block = (self.sb.block_size as usize / inode_size) as u64;

        let bg_list = self.group_descriptors.clone();

        for bg in &bg_list {
            let table_start_block = bg.inode_table_block;
            let blocks_for_table = (inodes_per_group + inodes_per_block - 1) / inodes_per_block;

            for b in 0..blocks_for_table {
                let block_lba = self.sb.block_to_lba(table_start_block + b);
                if let Ok(block_data) = self.source.read_blocks(block_lba, sectors_per_block) {
                    for i in 0..inodes_per_block {
                        let relative_inum = (b * inodes_per_block) + i;
                        if relative_inum >= inodes_per_group {
                            break;
                        }
                        let inum = (bg.group_num as u64 * inodes_per_group) + relative_inum + 1;

                        // Skip system reserved inodes 1..=10 unless needed
                        if inum < 11 || visited_inodes.contains(&inum) {
                            continue;
                        }

                        let offset = i as usize * inode_size;
                        if offset + inode_size <= block_data.len() {
                            let inode = Ext4Inode::parse(inum, &block_data[offset..offset + inode_size]);
                            if (inode.is_deleted || inode.links_count == 0) && (inode.size > 0 || inode.blocks_count > 0) {
                                let (name, path) = match name_map.get(&inum) {
                                    Some((n, p)) => (Some(n.as_str()), Some(p.as_str())),
                                    None => (None, None),
                                };

                                let fallback_path = format!("/[ORPHAN_INODE_{}]", inum);
                                let effective_path = path.unwrap_or(&fallback_path);

                                if let Ok(rec) = self.build_entry_from_inode(&inode, name, Some(effective_path), true) {
                                    results.push(rec);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Read a specific inode by number.
    pub fn read_inode(&mut self, inum: u64) -> Result<Option<Ext4Inode>, Ext4Error> {
        if inum == 0 || inum > self.sb.inodes_count as u64 {
            return Ok(None);
        }

        let inodes_per_group = self.sb.inodes_per_group as u64;
        let group_idx = (inum - 1) / inodes_per_group;
        let inode_idx = (inum - 1) % inodes_per_group;

        if group_idx >= self.group_descriptors.len() as u64 {
            return Ok(None);
        }

        let bg = &self.group_descriptors[group_idx as usize];
        let inode_size = self.sb.inode_size as u64;
        let byte_offset_in_table = inode_idx * inode_size;
        let block_offset = byte_offset_in_table / self.sb.block_size as u64;
        let byte_in_block = (byte_offset_in_table % self.sb.block_size as u64) as usize;

        let block_num = bg.inode_table_block + block_offset;
        let lba = self.sb.block_to_lba(block_num);
        let sectors_per_block = (self.sb.block_size / 512) as u32;

        let block_data = self.source.read_blocks(lba, sectors_per_block)?;
        if byte_in_block + inode_size as usize > block_data.len() {
            return Ok(None);
        }

        let raw_inode = &block_data[byte_in_block..byte_in_block + inode_size as usize];
        let inode = Ext4Inode::parse(inum, raw_inode);
        Ok(Some(inode))
    }

    /// Builds canonical `RecoverableFileEntry` from an `Ext4Inode`.
    fn build_entry_from_inode(
        &mut self,
        inode: &Ext4Inode,
        name: Option<&str>,
        path: Option<&str>,
        force_deleted: bool,
    ) -> Result<RecoverableFileEntry, Ext4Error> {
        let is_del = inode.is_deleted || force_deleted;
        let extents = inode.get_block_extents(self.source, &self.sb)?;

        let (data_loc, confidence) = if extents.is_empty() {
            if inode.size == 0 {
                (DataLocation::Contiguous { start_lba: 0, block_count: 0 }, MetadataConfidence::Confirmed)
            } else {
                (DataLocation::Unresolved, MetadataConfidence::Low)
            }
        } else {
            let lba_extents = self.block_extents_to_lba_extents(&extents);
            let loc = if lba_extents.len() == 1 {
                DataLocation::Contiguous {
                    start_lba: lba_extents[0].0,
                    block_count: lba_extents[0].1,
                }
            } else {
                DataLocation::Fragmented(lba_extents)
            };
            let conf = if is_del {
                if let Some(ref bm) = self.bitmap {
                    bm.evaluate_extents_confidence(&extents)
                } else {
                    MetadataConfidence::Partial
                }
            } else {
                MetadataConfidence::Confirmed
            };
            (loc, conf)
        };

        Ok(RecoverableFileEntry {
            id: inode.inum,
            original_path: path.map(|p| p.to_string()),
            filename: name.map(|n| n.to_string()),
            size_bytes: Some(inode.size),
            created: inode.ctime, // ext4 ctime = metadata change / creation
            modified: inode.mtime,
            accessed: inode.atime,
            deleted: is_del,
            data_location: data_loc,
            metadata_confidence: confidence,
            source_filesystem: FilesystemType::Ext4,
        })
    }

    /// Converts filesystem block extents to physical LBA extents.
    fn block_extents_to_lba_extents(&self, extents: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let sectors_per_block = (self.sb.block_size / 512) as u64;
        extents
            .iter()
            .map(|&(blk, count)| {
                let start_lba = self.sb.block_to_lba(blk);
                let block_count = count * sectors_per_block;
                (start_lba, block_count)
            })
            .collect()
    }
}
