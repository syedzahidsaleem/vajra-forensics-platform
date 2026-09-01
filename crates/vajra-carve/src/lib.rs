//! # vajra-carve
//!
//! File Carving & Recovery Engine (§25–§32).
//!
//! Implements:
//! - **Tier 1**: Thin orchestration wrapping `vajra-fs-ntfs`, `vajra-fs-ext4`, and `vajra-fs-fat` (§25).
//! - **Tier 2**: Extensible signature database + Garfinkel (DFRWS 2007) fast structural validators for JPEG, PNG, PDF, ZIP/DOCX, and SQLite (§26).
//! - **Tier 3**: Bifragment Gap Carving (BGC) with empirical gap-size search order (`8, 16, 32, 4, 64, 24, 40` sectors) (§27).
//! - **Confidence Scoring**: 6-signal composite weighted formula with named tunable constants (§29).
//! - **Provenance**: Canonical `RecoveredArtifact` data model capturing complete forensic provenance (§31).
//!
//! # Safety Invariant (§16)
//! Operates strictly on `&mut dyn ReadOnlyBlockSource`. Syntactically incapable of issuing writes to source evidence.

pub mod confidence;
pub mod entropy;
pub mod error;
pub mod pipeline;
pub mod tier1;
pub mod tier2;
pub mod tier3;
pub mod types;

pub use confidence::{
    ConfidenceBreakdown, WEIGHT_ENTROPY, WEIGHT_FRAGMENTATION, WEIGHT_HEADER_FOOTER,
    WEIGHT_METADATA, WEIGHT_OVERWRITE, WEIGHT_STRUCTURAL,
};
pub use entropy::{calculate_shannon_entropy, EntropyAnalyzer, HeuristicEntropyAnalyzer};
pub use error::CarveError;
pub use pipeline::{PipelineOptions, RecoveryPipeline};
pub use tier1::{recover_tier1, AllocatedBlockMap};
pub use tier2::{
    carve_tier2, FileSignature, JpegValidator, PdfValidator, PngValidator, SignatureDb,
    SqliteValidator, StructuralValidator, ValidationResult, ValidatorFlags, ValidatorRegistry,
    ZipValidator,
};
pub use tier3::{
    bifragment_gap_carve, carve_tier3, DEFAULT_MAX_SEARCH_RADIUS, EMPIRICAL_GAP_SEARCH_ORDER,
};
pub use types::{FragmentationDetail, RecoveredArtifact, RecoveryTier};

#[cfg(test)]
mod tests {
    use super::*;

    // --- 1. PNG Validator Tests (Hilgert et al. 2019) ---
    #[test]
    fn test_png_validator_intact_and_corrupted_crc() {
        let validator = PngValidator;

        // Build minimal valid 1x1 PNG
        let mut valid_png = Vec::new();
        valid_png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // Magic
        
        // IHDR chunk (13 bytes data)
        let ihdr_data = [
            0x00, 0x00, 0x00, 0x01, // width: 1
            0x00, 0x00, 0x00, 0x01, // height: 1
            0x08, 0x02, 0x00, 0x00, 0x00, // 8-bit RGB, deflate, filter 0, no interlace
        ];
        valid_png.extend_from_slice(&13u32.to_be_bytes());
        valid_png.extend_from_slice(b"IHDR");
        valid_png.extend_from_slice(&ihdr_data);
        
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(b"IHDR");
        hasher.update(&ihdr_data);
        valid_png.extend_from_slice(&hasher.finalize().to_be_bytes());

        // IEND chunk (0 bytes data)
        valid_png.extend_from_slice(&0u32.to_be_bytes());
        valid_png.extend_from_slice(b"IEND");
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(b"IEND");
        valid_png.extend_from_slice(&hasher.finalize().to_be_bytes());

        // 1. Intact PNG -> V_OK
        let res = validator.validate(&valid_png);
        assert!(res.is_ok(), "Valid PNG must yield V_OK");

        // 2. Truncated PNG (missing IEND) -> V_EOF
        let truncated = &valid_png[..valid_png.len() - 12];
        let res_eof = validator.validate(truncated);
        assert!(res_eof.is_eof(), "Truncated PNG must yield V_EOF");

        // 3. Corrupted PNG (bit-flip in IHDR data) -> V_ERR (CRC mismatch!)
        let mut corrupted = valid_png.clone();
        corrupted[16] ^= 0xFF; // flip bit in width
        let res_err = validator.validate(&corrupted);
        assert!(res_err.is_err(), "Bit-flipped PNG must fail CRC and yield V_ERR");
    }

    // --- 2. JPEG Validator Tests (Garfinkel 2007) ---
    #[test]
    fn test_jpeg_validator_intact_and_corrupted() {
        let validator = JpegValidator;

        // Minimal synthetic JPEG: SOI -> SOF0 -> SOS -> Scan Data -> EOI
        let mut valid_jpeg = Vec::new();
        valid_jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI

        // SOF0 (baseline DCT, length = 11)
        valid_jpeg.extend_from_slice(&[0xFF, 0xC0]);
        valid_jpeg.extend_from_slice(&11u16.to_be_bytes());
        valid_jpeg.extend_from_slice(&[0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00]);

        // SOS (Start of Scan, length = 6)
        valid_jpeg.extend_from_slice(&[0xFF, 0xDA]);
        valid_jpeg.extend_from_slice(&6u16.to_be_bytes());
        valid_jpeg.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);

        // Scan data with byte-stuffed 0xFF00 and regular entropy bytes
        valid_jpeg.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56, 0x78]);

        // EOI
        valid_jpeg.extend_from_slice(&[0xFF, 0xD9]);

        // 1. Intact JPEG -> V_OK
        let res = validator.validate(&valid_jpeg);
        assert!(res.is_ok(), "Valid JPEG must yield V_OK");

        // 2. Truncated JPEG (missing EOI) -> V_EOF
        let truncated = &valid_jpeg[..valid_jpeg.len() - 2];
        let res_eof = validator.validate(truncated);
        assert!(res_eof.is_eof(), "Truncated JPEG must yield V_EOF");

        // 3. Corrupted marker -> V_ERR
        let mut corrupted = valid_jpeg.clone();
        corrupted[2] = 0xAA; // not 0xFF
        let res_err = validator.validate(&corrupted);
        assert!(res_err.is_err(), "Invalid marker prefix must yield V_ERR");
    }

    // --- 3. PDF Validator Tests ---
    #[test]
    fn test_pdf_validator_intact_and_truncated() {
        let validator = PdfValidator;

        let valid_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n49\n%%EOF\n";

        let res = validator.validate(valid_pdf);
        assert!(res.is_ok(), "Valid PDF must yield V_OK");

        let truncated = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let res_eof = validator.validate(truncated);
        assert!(res_eof.is_eof(), "Truncated PDF must yield V_EOF");
    }

    // --- 4. SQLite Validator Tests ---
    #[test]
    fn test_sqlite_validator_intact_and_corrupted() {
        let validator = SqliteValidator;

        let mut valid_db = vec![0u8; 1024]; // 1 page of 1024 bytes
        valid_db[0..16].copy_from_slice(b"SQLite format 3\0");
        valid_db[16..18].copy_from_slice(&1024u16.to_be_bytes()); // Page size
        valid_db[28..32].copy_from_slice(&1u32.to_be_bytes()); // Database size = 1 page
        valid_db[100] = 0x0D; // Leaf table b-tree
        valid_db[103..105].copy_from_slice(&0u16.to_be_bytes()); // 0 cells
        valid_db[105..107].copy_from_slice(&1024u16.to_be_bytes()); // Cell content offset

        let res = validator.validate(&valid_db);
        assert!(res.is_ok(), "Valid SQLite db must yield V_OK");

        let mut corrupted = valid_db.clone();
        corrupted[100] = 0xFF; // invalid b-tree type
        let res_err = validator.validate(&corrupted);
        assert!(res_err.is_err(), "Invalid b-tree page type must yield V_ERR");
    }

    // --- 5. Confidence Formula Verification (§29) ---
    #[test]
    fn test_confidence_composite_score_calculation() {
        let breakdown = ConfidenceBreakdown {
            header_footer_integrity: 1.0,
            structural_validity: 1.0,
            metadata_cross_reference: 1.0,
            entropy_consistency: 1.0,
            entropy_explainability: None,
            fragmentation_confidence: 1.0,
            overwrite_probability: 1.0,
        };

        let score = breakdown.composite_score();
        assert!((score - 1.0).abs() < 1e-5, "All-1.0 signals must sum to 1.0");

        // Verify exact weight constants
        let total_weights = WEIGHT_HEADER_FOOTER
            + WEIGHT_STRUCTURAL
            + WEIGHT_METADATA
            + WEIGHT_ENTROPY
            + WEIGHT_FRAGMENTATION
            + WEIGHT_OVERWRITE;
        assert!((total_weights - 1.0).abs() < 1e-5, "Weights must sum to 1.0");
    }
}
