//! # vajra-fs-ext4
//!
//! Fourth Extended Filesystem (ext4/ext3/ext2) analysis and Tier-1 recovery parser (§25).
//!
//! Provides superblock parsing, 32-bit and 64-bit block group descriptors, inode table parsing,
//! modern extent tree (`0xF30A`) and legacy indirect block mapping, directory entry and slack space
//! scanning, and unlinked/deleted inode recovery.
//!
//! # Safety
//! Operates strictly against [`vajra_core::ReadOnlyBlockSource`]. Syntactically incapable of issuing writes.

pub mod bitmap;
pub mod dir;
pub mod error;
pub mod group_desc;
pub mod inode;
pub mod journal;
pub mod parser;
pub mod superblock;

pub use bitmap::Ext4BlockBitmap;
pub use dir::{parse_dir_block, Ext4DirEntry};
pub use error::Ext4Error;
pub use group_desc::BlockGroupDescriptor;
pub use inode::Ext4Inode;
pub use journal::Jbd2JournalInfo;
pub use parser::Ext4Parser;
pub use superblock::Ext4Superblock;

use vajra_core::{ReadOnlyBlockSource, RecoverableFileEntry};

/// Enumerates all active and recoverable deleted entries from an ext4 filesystem (§25).
pub fn enumerate_entries(
    source: &mut dyn ReadOnlyBlockSource,
    partition_start_lba: u64,
) -> Result<Vec<RecoverableFileEntry>, Ext4Error> {
    let mut parser = Ext4Parser::new(source, partition_start_lba)?;
    parser.enumerate_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_parsing() {
        let mut raw_sb = vec![0u8; 1024];
        // Superblock magic at 0x38..0x3A = 0xEF53
        raw_sb[0x38] = 0x53;
        raw_sb[0x39] = 0xEF;
        // Inodes count at 0x00 = 2048
        raw_sb[0..4].copy_from_slice(&2048u32.to_le_bytes());
        // Blocks count lo at 0x04 = 8192
        raw_sb[4..8].copy_from_slice(&8192u32.to_le_bytes());
        // Log block size at 0x18 = 2 (1024 << 2 = 4096 bytes)
        raw_sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        // Blocks per group at 0x20 = 8192
        raw_sb[0x20..0x24].copy_from_slice(&8192u32.to_le_bytes());
        // Inodes per group at 0x28 = 2048
        raw_sb[0x28..0x2C].copy_from_slice(&2048u32.to_le_bytes());
        // Inode size at 0x58 = 256
        raw_sb[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());
        // Incompat flags at 0x60 = 0x0040 (EXTENTS) | 0x0080 (64BIT)
        raw_sb[0x60..0x64].copy_from_slice(&0x00C0u32.to_le_bytes());

        let sb = Ext4Superblock::parse(0, &raw_sb).unwrap();
        assert_eq!(sb.inodes_count, 2048);
        assert_eq!(sb.blocks_count, 8192);
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.inode_size, 256);
        assert!(sb.has_extents);
        assert!(sb.is_64bit);
        assert_eq!(sb.block_groups_count, 1);
    }

    #[test]
    fn test_dir_block_parsing_and_slack_recovery() {
        let mut dir_block = vec![0u8; 4096];

        // Active entry 1: inum = 2, rec_len = 12, name_len = 1, file_type = 2, name = "."
        dir_block[0..4].copy_from_slice(&2u32.to_le_bytes());
        dir_block[4..6].copy_from_slice(&12u16.to_le_bytes());
        dir_block[6] = 1;
        dir_block[7] = 2;
        dir_block[8] = b'.';

        // Active entry 2: inum = 2, rec_len = 12, name_len = 2, file_type = 2, name = ".."
        dir_block[12..16].copy_from_slice(&2u32.to_le_bytes());
        dir_block[16..18].copy_from_slice(&12u16.to_le_bytes());
        dir_block[18] = 2;
        dir_block[19] = 2;
        dir_block[20..22].copy_from_slice(b"..");

        // Active entry 3: inum = 12, rec_len = 200 (expanded to absorb unlinked deleted file!),
        // name_len = 8, file_type = 1, name = "live.txt"
        dir_block[24..28].copy_from_slice(&12u32.to_le_bytes());
        dir_block[28..30].copy_from_slice(&200u16.to_le_bytes()); // Expanded rec_len
        dir_block[30] = 8;
        dir_block[31] = 1;
        dir_block[32..40].copy_from_slice(b"live.txt");

        // Unlinked deleted entry hidden in slack space of entry 3:
        // Offset = 24 + aligned_len (8 + 8 = 16) = 40
        // inum = 15, rec_len = 184, name_len = 11, file_type = 1, name = "deleted.dat"
        dir_block[40..44].copy_from_slice(&15u32.to_le_bytes());
        dir_block[44..46].copy_from_slice(&184u16.to_le_bytes());
        dir_block[46] = 11;
        dir_block[47] = 1;
        dir_block[48..59].copy_from_slice(b"deleted.dat");

        let entries = parse_dir_block(&dir_block);
        assert_eq!(entries.len(), 4);

        assert_eq!(entries[2].name, "live.txt");
        assert!(!entries[2].is_unlinked_slack);

        assert_eq!(entries[3].name, "deleted.dat");
        assert!(entries[3].is_unlinked_slack);
        assert_eq!(entries[3].inode, 15);
    }
}
