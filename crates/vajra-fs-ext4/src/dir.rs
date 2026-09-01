//! ext4 Directory entry parsing and unallocated directory slack scanning (§25).
//!
//! Reference: SleuthKit `tsk/fs/ext2fs_dent.c`.

/// Parsed ext4 directory entry.
#[derive(Debug, Clone)]
pub struct Ext4DirEntry {
    pub inode: u64,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: String,
    pub is_unlinked_slack: bool,
}

/// Parses active and unlinked directory entries from a directory block.
pub fn parse_dir_block(block_data: &[u8]) -> Vec<Ext4DirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + 8 <= block_data.len() {
        let inum = u32::from_le_bytes([
            block_data[offset],
            block_data[offset + 1],
            block_data[offset + 2],
            block_data[offset + 3],
        ]) as u64;
        let rec_len = u16::from_le_bytes([block_data[offset + 4], block_data[offset + 5]]);
        let name_len = block_data[offset + 6];
        let file_type = block_data[offset + 7];

        if rec_len < 8 || offset + rec_len as usize > block_data.len() {
            break;
        }

        let actual_entry_len = 8 + (name_len as usize);
        let aligned_entry_len = (actual_entry_len + 3) & !3;

        if inum > 0 && name_len > 0 && offset + 8 + name_len as usize <= block_data.len() {
            let name = String::from_utf8_lossy(&block_data[offset + 8..offset + 8 + name_len as usize]).to_string();
            entries.push(Ext4DirEntry {
                inode: inum,
                rec_len,
                name_len,
                file_type,
                name,
                is_unlinked_slack: false,
            });
        }

        // Check unallocated slack space within this entry (where rec_len was expanded on unlink)
        if rec_len as usize > aligned_entry_len + 8 {
            let mut slack_offset = offset + aligned_entry_len;
            while slack_offset + 8 <= offset + rec_len as usize {
                let slack_inum = u32::from_le_bytes([
                    block_data[slack_offset],
                    block_data[slack_offset + 1],
                    block_data[slack_offset + 2],
                    block_data[slack_offset + 3],
                ]) as u64;
                let slack_rec_len = u16::from_le_bytes([
                    block_data[slack_offset + 4],
                    block_data[slack_offset + 5],
                ]);
                let slack_name_len = block_data[slack_offset + 6];
                let slack_file_type = block_data[slack_offset + 7];

                if slack_inum > 0
                    && slack_name_len > 0
                    && slack_offset + 8 + slack_name_len as usize <= offset + rec_len as usize
                    && slack_file_type <= 7
                {
                    let slack_name = String::from_utf8_lossy(
                        &block_data[slack_offset + 8..slack_offset + 8 + slack_name_len as usize],
                    ).to_string();

                    // Ensure name looks like valid ASCII/UTF-8 filename
                    if slack_name.chars().all(|c| !c.is_control()) {
                        entries.push(Ext4DirEntry {
                            inode: slack_inum,
                            rec_len: slack_rec_len,
                            name_len: slack_name_len,
                            file_type: slack_file_type,
                            name: slack_name,
                            is_unlinked_slack: true,
                        });
                    }
                }
                slack_offset += 4; // Advance aligned byte boundary in slack scan
            }
        }

        offset += rec_len as usize;
    }

    entries
}
