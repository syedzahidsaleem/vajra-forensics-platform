//! ext4 jbd2 Journal basic detection and superblock inspection (§25).
//!
//! Reference: SleuthKit `tsk/fs/ext2fs_journal.c`.

pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B3998;

/// Basic JBD2 journal information.
#[derive(Debug, Clone)]
pub struct Jbd2JournalInfo {
    pub is_present: bool,
    pub block_size: u32,
    pub total_blocks: u32,
    pub first_log_block: u32,
    pub start_transaction_seq: u32,
}

impl Jbd2JournalInfo {
    /// Parse JBD2 journal superblock header bytes.
    pub fn parse(header_bytes: &[u8]) -> Self {
        if header_bytes.len() < 1024 {
            return Self {
                is_present: false,
                block_size: 0,
                total_blocks: 0,
                first_log_block: 0,
                start_transaction_seq: 0,
            };
        }

        let magic = u32::from_be_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        if magic != JBD2_MAGIC_NUMBER {
            return Self {
                is_present: false,
                block_size: 0,
                total_blocks: 0,
                first_log_block: 0,
                start_transaction_seq: 0,
            };
        }

        let block_size = u32::from_be_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        let total_blocks = u32::from_be_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]);
        let first_log_block = u32::from_be_bytes([
            header_bytes[12],
            header_bytes[13],
            header_bytes[14],
            header_bytes[15],
        ]);
        let start_transaction_seq = u32::from_be_bytes([
            header_bytes[16],
            header_bytes[17],
            header_bytes[18],
            header_bytes[19],
        ]);

        Self {
            is_present: true,
            block_size,
            total_blocks,
            first_log_block,
            start_transaction_seq,
        }
    }
}
