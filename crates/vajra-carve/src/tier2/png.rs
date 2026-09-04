//! PNG Syntactic & Structural Validator (§26.2, §28).
//!
//! Implements sequential chunk validation and CRC32 verification per Hilgert et al. (2019).
//! Flags: `err_is_prefix: true`, `appended_data_ignored: true`, `no_zblocks: true`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};
use crc32fast::Hasher as Crc32Hasher;

const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

#[derive(Debug, Default, Clone)]
pub struct PngValidator;

impl StructuralValidator for PngValidator {
    fn file_type(&self) -> &'static str {
        "png"
    }

    fn flags(&self) -> ValidatorFlags {
        // Reasoned engineering rationale:
        // - err_is_prefix: true (sequential chunk structure with mandatory CRC32 and DEFLATE stream)
        // - appended_data_ignored: true (standard decoders stop cleanly at IEND)
        // - no_zblocks: true (IDAT compressed payloads never produce all-zero 512-byte blocks)
        ValidatorFlags {
            err_is_prefix: true,
            appended_data_ignored: true,
            no_zblocks: true,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if data.len() < 8 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        if data[0..8] != PNG_MAGIC {
            return ValidationResult::Err("Invalid PNG 8-byte magic header".to_string());
        }

        let mut offset = 8;
        let mut found_ihdr = false;
        let mut found_iend = false;

        while offset + 8 <= data.len() {
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            let chunk_type = &data[offset + 4..offset + 8];

            // PNG chunk type MUST consist of 4 ASCII alphabetic letters (ISO/IEC 15948 / RFC 2083)
            if !chunk_type.iter().all(|b| b.is_ascii_alphabetic()) {
                // Encountered sector padding or trailing non-chunk bytes before IEND -> V_EOF
                return ValidationResult::Eof { partial_length: offset as u64 };
            }

            if !found_ihdr {
                if chunk_type != b"IHDR" {
                    return ValidationResult::Err("First PNG chunk must be IHDR".to_string());
                }
                found_ihdr = true;
            }

            // Total chunk size = 4 (len) + 4 (type) + chunk_len (data) + 4 (crc)
            let total_chunk_len = 12 + chunk_len;
            if offset + total_chunk_len > data.len() {
                return ValidationResult::Eof { partial_length: offset as u64 };
            }

            let chunk_data = &data[offset + 8..offset + 8 + chunk_len];
            let recorded_crc = u32::from_be_bytes([
                data[offset + 8 + chunk_len],
                data[offset + 8 + chunk_len + 1],
                data[offset + 8 + chunk_len + 2],
                data[offset + 8 + chunk_len + 3],
            ]);

            // Compute CRC32 over chunk_type + chunk_data
            let mut hasher = Crc32Hasher::new();
            hasher.update(chunk_type);
            hasher.update(chunk_data);
            let calculated_crc = hasher.finalize();

            if calculated_crc != recorded_crc {
                return ValidationResult::Err(format!(
                    "PNG chunk '{:?}' CRC32 mismatch: recorded 0x{:08X}, calculated 0x{:08X}",
                    String::from_utf8_lossy(chunk_type),
                    recorded_crc,
                    calculated_crc
                ));
            }

            offset += total_chunk_len;

            if chunk_type == b"IEND" {
                found_iend = true;
                break;
            }
        }

        if found_iend {
            ValidationResult::Ok { object_length: Some(offset as u64) }
        } else {
            ValidationResult::Eof { partial_length: offset as u64 }
        }
    }
}
