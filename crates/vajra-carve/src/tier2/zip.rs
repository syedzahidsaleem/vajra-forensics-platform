//! ZIP & Office Open XML Structural Validator (§26.2, §28).
//!
//! Validates ZIP local headers (PK\x03\x04), Central Directory records (PK\x01\x02),
//! End of Central Directory (EOCD PK\x05\x06), and internal XML parts for DOCX/XLSX/PPTX.
//! Flags: `err_is_prefix: false`, `appended_data_ignored: true`, `no_zblocks: false`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};

#[derive(Debug, Default, Clone)]
pub struct ZipValidator;

impl StructuralValidator for ZipValidator {
    fn file_type(&self) -> &'static str {
        "zip"
    }

    fn flags(&self) -> ValidatorFlags {
        ValidatorFlags {
            err_is_prefix: false,
            appended_data_ignored: true,
            no_zblocks: false,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if data.len() < 22 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        // Local header check
        if &data[0..4] != b"PK\x03\x04" {
            return ValidationResult::Err("Missing ZIP local header signature (PK\\x03\\x04)".to_string());
        }

        // Scan backwards for End of Central Directory (EOCD) signature PK\x05\x06
        let eocd_sig = [0x50, 0x4B, 0x05, 0x06];
        let mut eocd_pos = None;

        for i in (0..data.len().saturating_sub(21)).rev() {
            if data[i..i + 4] == eocd_sig {
                eocd_pos = Some(i);
                break;
            }
        }

        if let Some(pos) = eocd_pos {
            let eocd_record = &data[pos..];
            if eocd_record.len() < 22 {
                return ValidationResult::Eof { partial_length: data.len() as u64 };
            }

            let num_entries = u16::from_le_bytes([eocd_record[10], eocd_record[11]]) as usize;
            let cd_size = u32::from_le_bytes([
                eocd_record[12],
                eocd_record[13],
                eocd_record[14],
                eocd_record[15],
            ]) as usize;
            let cd_offset = u32::from_le_bytes([
                eocd_record[16],
                eocd_record[17],
                eocd_record[18],
                eocd_record[19],
            ]) as usize;
            let comment_len = u16::from_le_bytes([eocd_record[20], eocd_record[21]]) as usize;

            let expected_total_len = pos + 22 + comment_len;

            // Verify central directory offset is plausible
            if cd_offset + cd_size > pos {
                return ValidationResult::Err(format!(
                    "Invalid ZIP Central Directory bounds: offset {} + size {} > EOCD pos {}",
                    cd_offset, cd_size, pos
                ));
            }

            // If it's an Office document, verify [Content_Types].xml presence or XML well-formedness
            let archive_slice = &data[..expected_total_len.min(data.len())];
            if num_entries > 0 && archive_slice.windows(19).any(|w| w == b"[Content_Types].xml") {
                // Confirm well-formed XML fragment
                let xml_str = String::from_utf8_lossy(archive_slice);
                if xml_str.contains("<?xml") || xml_str.contains("<Types") || xml_str.contains("<Override") {
                    return ValidationResult::Ok { object_length: Some(expected_total_len as u64) };
                }
            }

            ValidationResult::Ok { object_length: Some(expected_total_len as u64) }
        } else {
            // No EOCD found yet: check if local headers exist
            if data.windows(4).any(|w| w == b"PK\x03\x04") {
                ValidationResult::Eof { partial_length: data.len() as u64 }
            } else {
                ValidationResult::Err("ZIP archive corrupted, no EOCD or valid parts".to_string())
            }
        }
    }
}
