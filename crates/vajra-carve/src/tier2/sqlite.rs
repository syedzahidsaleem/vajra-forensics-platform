//! SQLite 3 Structural & B-Tree Validator (§26.2, §28).
//!
//! Validates 16-byte magic string, page size geometry (power of 2), database size in pages,
//! and root b-tree page header structure (page type, cell counts, cell offset bounds).
//! Flags: `err_is_prefix: false`, `appended_data_ignored: true`, `no_zblocks: false`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};

const SQLITE_HEADER_MAGIC: &[u8] = b"SQLite format 3\0";

#[derive(Debug, Default, Clone)]
pub struct SqliteValidator;

impl StructuralValidator for SqliteValidator {
    fn file_type(&self) -> &'static str {
        "sqlite"
    }

    fn flags(&self) -> ValidatorFlags {
        ValidatorFlags {
            err_is_prefix: false,
            appended_data_ignored: true,
            no_zblocks: false,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if data.len() < 100 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        // Magic header check
        if &data[0..16] != SQLITE_HEADER_MAGIC {
            return ValidationResult::Err("Invalid SQLite header magic string".to_string());
        }

        // Page size at offset 16 (2 bytes, big-endian)
        let raw_page_size = u16::from_be_bytes([data[16], data[17]]);
        let page_size = if raw_page_size == 1 {
            65536u32
        } else {
            raw_page_size as u32
        };

        // Page size must be a power of 2 between 512 and 65536
        if !(512..=65536).contains(&page_size) || (page_size & (page_size - 1)) != 0 {
            return ValidationResult::Err(format!("Invalid SQLite page size: {}", page_size));
        }

        // File change counter at offset 24..28
        // Database size in pages at offset 28..32
        let db_size_in_pages = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as u64;

        // Page 1 b-tree header starts at byte offset 100
        if data.len() < 108 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        let page_type = data[100];
        // Valid page types: 0x02 (Interior Index), 0x05 (Interior Table), 0x0A (Leaf Index), 0x0D (Leaf Table)
        if page_type != 0x02 && page_type != 0x05 && page_type != 0x0A && page_type != 0x0D {
            return ValidationResult::Err(format!("Invalid SQLite Page 1 b-tree type flag: 0x{:02X}", page_type));
        }

        let _num_cells = u16::from_be_bytes([data[103], data[104]]) as usize;
        let cell_content_offset = u16::from_be_bytes([data[105], data[106]]) as u32;

        let actual_cell_offset = if cell_content_offset == 0 {
            65536u32
        } else {
            cell_content_offset
        };

        if actual_cell_offset > page_size {
            return ValidationResult::Err(format!(
                "Invalid SQLite cell content offset {} > page size {}",
                actual_cell_offset, page_size
            ));
        }

        // Determine expected total size
        let expected_bytes = if db_size_in_pages > 0 {
            db_size_in_pages * (page_size as u64)
        } else {
            page_size as u64
        };

        if (data.len() as u64) < expected_bytes {
            ValidationResult::Eof { partial_length: data.len() as u64 }
        } else {
            ValidationResult::Ok { object_length: Some(expected_bytes) }
        }
    }
}
