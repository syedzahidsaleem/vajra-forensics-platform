//! JPEG Structural Validator (§26.2, §28).
//!
//! Implements marker segment walk and scan-data bitstream validation (SOI -> DQT/SOF/DHT -> SOS -> EOI).
//! Flags: `err_is_prefix: true`, `appended_data_ignored: false`, `no_zblocks: true` (Garfinkel 2007).

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};

#[derive(Debug, Default, Clone)]
pub struct JpegValidator;

impl StructuralValidator for JpegValidator {
    fn file_type(&self) -> &'static str {
        "jpeg"
    }

    fn flags(&self) -> ValidatorFlags {
        ValidatorFlags {
            err_is_prefix: true,
            appended_data_ignored: false,
            no_zblocks: true,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if data.len() < 4 {
            return ValidationResult::Eof { partial_length: data.len() as u64 };
        }

        // SOI check
        if data[0] != 0xFF || data[1] != 0xD8 {
            return ValidationResult::Err("Missing JPEG Start of Image (0xFFD8)".to_string());
        }

        let mut offset = 2;
        let mut found_sof = false;
        let mut found_sos = false;

        while offset + 1 < data.len() {
            // Find next marker: must start with 0xFF
            if data[offset] != 0xFF {
                return ValidationResult::Err(format!("Expected 0xFF marker prefix at offset {}", offset));
            }

            // Skip fill bytes 0xFF
            while offset < data.len() && data[offset] == 0xFF {
                offset += 1;
            }

            if offset >= data.len() {
                return ValidationResult::Eof { partial_length: offset as u64 };
            }

            let marker = data[offset];
            offset += 1;

            // Standalone markers without length
            if marker == 0xD8 {
                // SOI inside body
                return ValidationResult::Err("Unexpected duplicate SOI marker".to_string());
            } else if marker == 0xD9 {
                // EOI
                return ValidationResult::Ok { object_length: Some(offset as u64) };
            } else if (0xD0..=0xD7).contains(&marker) {
                // RST0..RST7
                continue;
            }

            // Markers with length field
            if offset + 2 > data.len() {
                return ValidationResult::Eof { partial_length: offset as u64 };
            }

            let marker_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            if marker_len < 2 {
                return ValidationResult::Err(format!("Invalid marker length {} at offset {}", marker_len, offset));
            }

            if marker == 0xC0 || marker == 0xC2 {
                found_sof = true;
            }

            if marker == 0xDA {
                // SOS (Start of Scan) - scan data begins after marker header
                found_sos = true;
                offset += marker_len;

                // Walk scan data until EOI or invalid byte sequence
                while offset < data.len() {
                    // Fast zero-block detection per no_zblocks flag: if an all-zero block is encountered,
                    // the scan data ended prematurely in disk padding/unallocated space -> V_EOF
                    if offset + 512 <= data.len() && data[offset..offset + 512].iter().all(|&b| b == 0) {
                        return ValidationResult::Eof { partial_length: offset.max(1) as u64 };
                    }

                    if data[offset] == 0xFF {
                        if offset + 1 >= data.len() {
                            return ValidationResult::Eof { partial_length: offset as u64 };
                        }
                        let next_b = data[offset + 1];
                        if next_b == 0x00 {
                            // Byte stuffing (literal 0xFF)
                            offset += 2;
                        } else if (0xD0..=0xD7).contains(&next_b) {
                            // Restart marker
                            offset += 2;
                        } else if next_b == 0xD9 {
                            // EOI found!
                            return ValidationResult::Ok { object_length: Some((offset + 2) as u64) };
                        } else if next_b == 0xFF {
                            // Extra padding byte
                            offset += 1;
                        } else {
                            // Found another marker or corrupted bitstream
                            break;
                        }
                    } else {
                        offset += 1;
                    }
                }

                if offset >= data.len() {
                    return ValidationResult::Eof { partial_length: offset as u64 };
                }
                continue;
            }

            if offset + marker_len > data.len() {
                return ValidationResult::Eof { partial_length: offset as u64 };
            }

            offset += marker_len;
        }

        if !found_sof || !found_sos {
            ValidationResult::Err("JPEG missing required SOF or SOS segment".to_string())
        } else {
            ValidationResult::Eof { partial_length: offset as u64 }
        }
    }
}
