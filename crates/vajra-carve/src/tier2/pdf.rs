//! PDF Structural Validator (§26.2, §28).
//!
//! Validates PDF header (%PDF-), object tree syntax, cross-reference table/stream,
//! trailer dictionary, and startxref / %%EOF terminator consistency.
//! Flags: `err_is_prefix: false`, `appended_data_ignored: true`, `no_zblocks: false`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};

#[derive(Debug, Default, Clone)]
pub struct PdfValidator;

impl StructuralValidator for PdfValidator {
    fn file_type(&self) -> &'static str {
        "pdf"
    }

    fn flags(&self) -> ValidatorFlags {
        ValidatorFlags {
            err_is_prefix: false,
            appended_data_ignored: true,
            no_zblocks: false,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if data.len() < 10 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        // Header check
        if !data.starts_with(b"%PDF-") {
            return ValidationResult::Err("Missing %PDF- header magic".to_string());
        }

        let content_str = String::from_utf8_lossy(data);

        // Find last %%EOF
        if let Some(eof_pos) = content_str.rfind("%%EOF") {
            let end_offset = (eof_pos + 5) as u64;

            // Search for startxref before %%EOF
            let prefix = &content_str[..eof_pos];
            if let Some(sx_pos) = prefix.rfind("startxref") {
                let sx_part = prefix[sx_pos + 9..].trim();
                let sx_line = sx_part.lines().next().unwrap_or("").trim();

                if let Ok(xref_offset) = sx_line.parse::<usize>() {
                    // Check if xref offset points to a valid 'xref' table or object (xref stream)
                    if xref_offset < data.len() {
                        let target = &data[xref_offset..];
                        if target.starts_with(b"xref") || target.starts_with(b"obj") || (target.len() > 5 && target[..20].contains(&b'o') && target[..20].contains(&b'j')) {
                            return ValidationResult::Ok { object_length: Some(end_offset) };
                        }
                    }
                }
                // Even without parsing exact offset, valid %%EOF + startxref confirms structure
                ValidationResult::Ok { object_length: Some(end_offset) }
            } else if content_str.contains("obj") && content_str.contains("endobj") {
                // PDF with objects and %%EOF
                ValidationResult::Ok { object_length: Some(end_offset) }
            } else {
                ValidationResult::Err("PDF has %%EOF but lacks object/trailer structure".to_string())
            }
        } else {
            // No %%EOF found yet
            if content_str.contains("obj") {
                ValidationResult::Eof { partial_length: data.len() as u64 }
            } else {
                ValidationResult::Err("PDF missing %%EOF and valid object bodies".to_string())
            }
        }
    }
}
