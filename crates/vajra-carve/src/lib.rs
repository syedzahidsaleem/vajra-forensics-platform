//! # vajra-carve
//!
//! File Carving & Recovery Engine (§25–§32).
//!
//! Implements:
//! - **Tier 1**: Thin orchestration wrapping `vajra-fs-ntfs`, `vajra-fs-ext4`, and `vajra-fs-fat` (§25).
//! - **Tier 2**: Extensible signature database + Garfinkel (DFRWS 2007) fast structural validators for JPEG, PNG, PDF, ZIP/DOCX, SQLite, and legacy OLE2/CFB (DOC/XLS/PPT) (§26).
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
    carve_tier2, FileSignature, JpegValidator, Ole2Validator, PdfValidator, PngValidator,
    SignatureDb, SqliteValidator, StructuralValidator, ValidationResult, ValidatorFlags,
    ValidatorRegistry, ZipValidator,
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

    // --- 4a. OLE2 / Compound File Binary (CFB) Validator Tests (§26.2, §28) ---

    // [MS-CFB] reserved sector ids, mirrored locally so the tests do not depend on
    // private constants inside the validator module.
    const T_DIFSECT: u32 = 0xFFFF_FFFC;
    const T_FATSECT: u32 = 0xFFFF_FFFD;
    const T_ENDOFCHAIN: u32 = 0xFFFF_FFFE;
    const T_FREESECT: u32 = 0xFFFF_FFFF;
    const T_NOSTREAM: u32 = 0xFFFF_FFFF;

    fn w16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn w32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn w64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Writes a UTF-16LE directory entry name, returning the [MS-CFB] name length
    /// (bytes used, including the two-byte null terminator).
    fn w_name(buf: &mut [u8], off: usize, name: &str) -> u16 {
        let mut used = 0usize;
        for (i, unit) in name.encode_utf16().enumerate() {
            buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            used += 2;
        }
        (used + 2) as u16
    }

    /// Builds a minimal but genuinely well-formed OLE2 v3 compound file:
    ///
    /// - 512-byte header sector
    /// - sector 0: the single FAT sector
    /// - sector 1: the directory sector (4 entries)
    /// - sectors 2..=10: a 4608-byte regular stream ("Data"), above the 4096-byte
    ///   mini-stream cutoff so its payload is chained through the FAT itself
    ///
    /// Total length: 512 + 11 * 512 = 6144 bytes, which is exactly what the
    /// validator must derive from the allocation table alone.
    fn build_valid_ole2() -> Vec<u8> {
        const SECTOR: usize = 512;
        const STREAM_SIZE: u64 = 4608; // 9 sectors
        let mut img = vec![0u8; SECTOR * 12]; // header + sectors 0..=10

        // ---- Header ----
        img[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        w16(&mut img, 0x18, 0x003E); // minor version
        w16(&mut img, 0x1A, 3); // major version 3
        w16(&mut img, 0x1C, 0xFFFE); // little-endian byte order mark
        w16(&mut img, 0x1E, 9); // sector shift -> 512-byte sectors
        w16(&mut img, 0x20, 6); // mini sector shift -> 64-byte mini sectors
        w32(&mut img, 0x28, 0); // directory sector count (must be 0 in v3)
        w32(&mut img, 0x2C, 1); // FAT sector count
        w32(&mut img, 0x30, 1); // first directory sector
        w32(&mut img, 0x38, 4096); // mini stream cutoff
        w32(&mut img, 0x3C, T_ENDOFCHAIN); // first MiniFAT sector
        w32(&mut img, 0x40, 0); // MiniFAT sector count
        w32(&mut img, 0x44, T_ENDOFCHAIN); // first DIFAT sector
        w32(&mut img, 0x48, 0); // DIFAT sector count

        // DIFAT: slot 0 points at the FAT in sector 0, remaining 108 slots free.
        w32(&mut img, 0x4C, 0);
        for i in 1..109 {
            w32(&mut img, 0x4C + i * 4, T_FREESECT);
        }

        // ---- FAT (sector 0, byte offset 512) ----
        let fat_off = SECTOR;
        for i in 0..(SECTOR / 4) {
            w32(&mut img, fat_off + i * 4, T_FREESECT);
        }
        w32(&mut img, fat_off, T_FATSECT); // sector 0 is the FAT itself
        w32(&mut img, fat_off + 4, T_ENDOFCHAIN); // sector 1: directory, single sector
        for s in 2..10u32 {
            w32(&mut img, fat_off + (s as usize) * 4, s + 1); // 2->3 ... 9->10
        }
        w32(&mut img, fat_off + 10 * 4, T_ENDOFCHAIN); // sector 10 ends the stream

        // ---- Directory (sector 1, byte offset 1024) ----
        let dir_off = SECTOR * 2;

        // Entry 0: root storage.
        let root = dir_off;
        let root_name_len = w_name(&mut img, root, "Root Entry");
        w16(&mut img, root + 0x40, root_name_len);
        img[root + 0x42] = 0x05; // object type: root
        img[root + 0x43] = 0x01; // colour: black
        w32(&mut img, root + 0x44, T_NOSTREAM); // left sibling
        w32(&mut img, root + 0x48, T_NOSTREAM); // right sibling
        w32(&mut img, root + 0x4C, 1); // child -> entry 1
        w32(&mut img, root + 0x74, T_ENDOFCHAIN); // no mini stream
        w64(&mut img, root + 0x78, 0);

        // Entry 1: a regular stream above the mini-stream cutoff.
        let data = dir_off + 128;
        let data_name_len = w_name(&mut img, data, "Data");
        w16(&mut img, data + 0x40, data_name_len);
        img[data + 0x42] = 0x02; // object type: stream
        img[data + 0x43] = 0x01; // colour: black
        w32(&mut img, data + 0x44, T_NOSTREAM);
        w32(&mut img, data + 0x48, T_NOSTREAM);
        w32(&mut img, data + 0x4C, T_NOSTREAM);
        w32(&mut img, data + 0x74, 2); // starting sector
        w64(&mut img, data + 0x78, STREAM_SIZE);

        // Entries 2 and 3 stay all-zero => object type 0x00 (unallocated).

        // ---- Stream payload, sectors 2..=10 ----
        // Structured text records followed by zero padding to the sector boundary —
        // the characteristically LOW-entropy profile a real legacy Office stream has,
        // and the same property behind this format's `no_zblocks: false` flag (§26.2).
        let filler = b"Vajra legacy OLE2 compound file ground-truth stream payload. ";
        for s in 2..=10usize {
            let off = SECTOR * (s + 1);
            for (i, b) in img[off..off + SECTOR].iter_mut().enumerate() {
                *b = if i < 384 { filler[i % filler.len()] } else { 0 };
            }
        }

        img
    }

    #[test]
    fn test_ole2_validator_accepts_intact_compound_file() {
        let validator = Ole2Validator;
        let ole2 = build_valid_ole2();

        let res = validator.validate(&ole2);
        assert!(
            res.is_ok(),
            "Intact OLE2/CFB compound file must yield V_OK, got: {}",
            res
        );

        // The object length must be derived exactly from the Sector Allocation Table
        // (Garfinkel 2007's MSOLE example), not from the buffer length.
        match res {
            ValidationResult::Ok { object_length } => assert_eq!(
                object_length,
                Some(6144),
                "OLE2 object_length must be computed from the FAT (header sector + sectors 0..=10)"
            ),
            other => panic!("expected V_OK, got {}", other),
        }

        // appended_data_ignored: true — a sector-padded carving window must still
        // resolve to the same exact object length.
        let mut padded = ole2.clone();
        padded.extend_from_slice(&[0xAB; 4096]);
        match validator.validate(&padded) {
            ValidationResult::Ok { object_length } => assert_eq!(
                object_length,
                Some(6144),
                "Trailing carving padding must not change the derived object length"
            ),
            other => panic!("padded OLE2 must still yield V_OK, got {}", other),
        }
    }

    #[test]
    fn test_ole2_validator_flags_match_section_26_2() {
        // §26.2 states all three of these directly for MSOLE.
        let flags = Ole2Validator.flags();
        assert!(
            !flags.err_is_prefix,
            "MSOLE has no sequential-scan property (§26.2)"
        );
        assert!(
            flags.appended_data_ignored,
            "The SAT gives an exact extent, so trailing bytes are ignored (§26.2)"
        );
        assert!(
            !flags.no_zblocks,
            "MSOLE frequently contains all-null sectors (§26.2)"
        );
        assert_eq!(Ole2Validator.file_type(), "ole2");
    }

    #[test]
    fn test_ole2_validator_rejects_wrong_signature() {
        let validator = Ole2Validator;
        let mut ole2 = build_valid_ole2();
        ole2[0] = 0x00; // break the D0 CF 11 E0 magic

        let res = validator.validate(&ole2);
        assert!(
            res.is_err(),
            "Wrong OLE2 signature must yield V_ERR, got: {}",
            res
        );

        // A ZIP-based OOXML document must never be accepted by the OLE2 validator.
        let not_ole2 = b"PK\x03\x04-------------------------------------------------";
        assert!(
            validator.validate(not_ole2).is_eof() || validator.validate(not_ole2).is_err(),
            "Non-OLE2 input must never yield V_OK"
        );
    }

    #[test]
    fn test_ole2_validator_truncated_yields_eof() {
        let validator = Ole2Validator;
        let ole2 = build_valid_ole2();

        // 1. Shorter than the 512-byte header: cannot decide anything yet.
        let res_short = validator.validate(&ole2[..100]);
        assert!(
            res_short.is_eof(),
            "Sub-header-length OLE2 must yield V_EOF, got: {}",
            res_short
        );

        // 2. Header + FAT + directory present, stream payload cut off. The allocation
        //    table says the object is 6144 bytes; we hold fewer. That is truncation,
        //    not corruption.
        let res_mid = validator.validate(&ole2[..3000]);
        assert!(
            res_mid.is_eof(),
            "OLE2 truncated below its FAT-derived object length must yield V_EOF, got: {}",
            res_mid
        );
        match res_mid {
            ValidationResult::Eof { partial_length } => {
                assert_eq!(partial_length, 3000, "V_EOF must report the bytes reached")
            }
            other => panic!("expected V_EOF, got {}", other),
        }

        // 3. Header present but the FAT sector itself is missing.
        let res_no_fat = validator.validate(&ole2[..600]);
        assert!(
            res_no_fat.is_eof(),
            "OLE2 whose FAT sector is not present must yield V_EOF, got: {}",
            res_no_fat
        );
    }

    #[test]
    fn test_ole2_validator_rejects_corrupted_fat_and_sector_references() {
        let validator = Ole2Validator;
        const FAT: usize = 512; // FAT sector 0 begins at byte 512

        // 1. Out-of-bounds sector reference: FAT entry 2 points past the 128-entry FAT.
        let mut oob = build_valid_ole2();
        w32(&mut oob, FAT + 2 * 4, 9999);
        let res_oob = validator.validate(&oob);
        assert!(
            res_oob.is_err(),
            "FAT entry referencing a sector beyond the FAT must yield V_ERR, got: {}",
            res_oob
        );

        // 2. Circular chain: 2 -> 3 -> 4 -> 5 -> 2.
        let mut looped = build_valid_ole2();
        w32(&mut looped, FAT + 5 * 4, 2);
        let res_loop = validator.validate(&looped);
        assert!(
            res_loop.is_err(),
            "Looping FAT chain must yield V_ERR, got: {}",
            res_loop
        );

        // 3. The FAT sector itself is no longer self-marked FATSECT.
        let mut unmarked = build_valid_ole2();
        w32(&mut unmarked, FAT, T_ENDOFCHAIN);
        let res_unmarked = validator.validate(&unmarked);
        assert!(
            res_unmarked.is_err(),
            "FAT sector not marked FATSECT must yield V_ERR, got: {}",
            res_unmarked
        );

        // 4. Stream chain shorter than the declared stream size implies.
        let mut short_chain = build_valid_ole2();
        w32(&mut short_chain, FAT + 4 * 4, T_ENDOFCHAIN); // truncate 2->3->4 chain early
        let res_short_chain = validator.validate(&short_chain);
        assert!(
            res_short_chain.is_err(),
            "Stream chain inconsistent with its declared size must yield V_ERR, got: {}",
            res_short_chain
        );

        // 5. Directory chain pointing at a reserved sector id.
        let mut bad_dir = build_valid_ole2();
        w32(&mut bad_dir, 0x30, T_DIFSECT);
        let res_bad_dir = validator.validate(&bad_dir);
        assert!(
            res_bad_dir.is_err(),
            "Directory sector pointer holding a reserved id must yield V_ERR, got: {}",
            res_bad_dir
        );

        // 6. Root directory entry is not actually a root object.
        let mut bad_root = build_valid_ole2();
        bad_root[512 * 2 + 0x42] = 0x02; // entry 0 claims to be a plain stream
        let res_bad_root = validator.validate(&bad_root);
        assert!(
            res_bad_root.is_err(),
            "Directory entry 0 that is not the root entry must yield V_ERR, got: {}",
            res_bad_root
        );
    }

    #[test]
    fn test_ole2_validator_rejects_invalid_header_fields() {
        let validator = Ole2Validator;

        // 1. Impossible sector shift for a v3 file (would imply 128-byte sectors).
        let mut bad_shift = build_valid_ole2();
        w16(&mut bad_shift, 0x1E, 7);
        assert!(
            validator.validate(&bad_shift).is_err(),
            "Invalid sector shift must yield V_ERR"
        );

        // 2. Mini-sector shift other than the specification-mandated 6.
        let mut bad_mini = build_valid_ole2();
        w16(&mut bad_mini, 0x20, 5);
        assert!(
            validator.validate(&bad_mini).is_err(),
            "Invalid mini-sector shift must yield V_ERR"
        );

        // 3. Wrong byte-order mark.
        let mut bad_order = build_valid_ole2();
        w16(&mut bad_order, 0x1C, 0x1234);
        assert!(
            validator.validate(&bad_order).is_err(),
            "Invalid byte-order mark must yield V_ERR"
        );

        // 4. Mini-stream cutoff other than 4096.
        let mut bad_cutoff = build_valid_ole2();
        w32(&mut bad_cutoff, 0x38, 512);
        assert!(
            validator.validate(&bad_cutoff).is_err(),
            "Invalid mini-stream cutoff must yield V_ERR"
        );

        // 5. Unsupported major version.
        let mut bad_version = build_valid_ole2();
        w16(&mut bad_version, 0x1A, 9);
        assert!(
            validator.validate(&bad_version).is_err(),
            "Unsupported major version must yield V_ERR"
        );

        // 6. Non-zero reserved field ([MS-CFB] 2.2 requires zeroes).
        let mut bad_reserved = build_valid_ole2();
        bad_reserved[0x24] = 0x77;
        assert!(
            validator.validate(&bad_reserved).is_err(),
            "Non-zero header reserved field must yield V_ERR"
        );

        // 7. Zero declared FAT sectors — no compound file has none.
        let mut no_fat = build_valid_ole2();
        w32(&mut no_fat, 0x2C, 0);
        assert!(
            validator.validate(&no_fat).is_err(),
            "Zero declared FAT sectors must yield V_ERR"
        );

        // 8. Implausible FAT sector count must be rejected, not allocated for.
        let mut huge_fat = build_valid_ole2();
        w32(&mut huge_fat, 0x2C, 0xFFFF_FFF0);
        assert!(
            validator.validate(&huge_fat).is_err(),
            "Implausible FAT sector count must yield V_ERR without unbounded allocation"
        );

        // 9. v3 file illegally declaring directory sectors in the header.
        let mut dir_count = build_valid_ole2();
        w32(&mut dir_count, 0x28, 4);
        assert!(
            validator.validate(&dir_count).is_err(),
            "v3 header declaring a non-zero directory sector count must yield V_ERR"
        );
    }

    #[test]
    fn test_ole2_registered_in_validator_registry_and_signature_db() {
        // The validator must be reachable by the `validator_id` used in signatures.json.
        let registry = ValidatorRegistry::default();
        let v = registry
            .get("ole2")
            .expect("ValidatorRegistry must expose the 'ole2' validator id");
        assert_eq!(v.file_type(), "ole2");

        // And the signature database must carry the CFB magic at offset 0.
        let db = SignatureDb::standard_forensic_signatures();
        let sig = db
            .signatures
            .iter()
            .find(|s| s.file_type == "ole2")
            .expect("signatures.json must contain an 'ole2' entry");
        assert_eq!(
            sig.header,
            vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        );
        assert_eq!(sig.validator_id, "ole2");

        // End-to-end: the signature's own magic must front a candidate the registered
        // validator accepts.
        let ole2 = build_valid_ole2();
        assert!(ole2.starts_with(&sig.header));
        assert!(v.validate(&ole2).is_ok());
    }

    #[test]
    fn test_ole2_entropy_profile_prefers_low_entropy() {
        let analyzer = HeuristicEntropyAnalyzer;

        // A real compound file: structured records plus zero padding -> low entropy.
        let ole2 = build_valid_ole2();
        let structured = analyzer.evaluate_consistency(&ole2, "ole2");

        // High-entropy random content is not what a legacy Office document looks like.
        let mut pseudo_random = Vec::with_capacity(8192);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..8192 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pseudo_random.push((state >> 24) as u8);
        }
        let random_score = analyzer.evaluate_consistency(&pseudo_random, "ole2");

        assert!(
            structured > random_score,
            "OLE2 entropy profile must score structured low-entropy content ({}) above high-entropy content ({})",
            structured,
            random_score
        );
        assert_eq!(
            analyzer.evaluate_consistency(&ole2, "doc"),
            structured,
            "'doc' must share the OLE2 entropy profile"
        );
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
