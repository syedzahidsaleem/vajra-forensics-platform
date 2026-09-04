//! # vajra-carve
//!
//! File Carving & Recovery Engine (§25–§32).
//!
//! Implements:
//! - **Tier 1**: Thin orchestration wrapping `vajra-fs-ntfs`, `vajra-fs-ext4`, and `vajra-fs-fat` (§25).
//! - **Tier 2**: Extensible signature database + Garfinkel (DFRWS 2007) fast structural validators for JPEG, PNG, PDF, ZIP/DOCX, SQLite, legacy OLE2/CFB (DOC/XLS/PPT), and MP4/MOV ISO-BMFF (§26).
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
    carve_tier2, FileSignature, JpegValidator, Mp4Validator, Ole2Validator, PdfValidator,
    PngValidator, SignatureDb, SqliteValidator, StructuralValidator, ValidationResult,
    ValidatorFlags, ValidatorRegistry, ZipValidator,
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

    // --- 4b. Signature Header-Offset Plumbing Tests (§26.1) ---
    //
    // Shared plumbing that lets a signature declare that its identifying magic begins
    // at a non-zero byte offset within the candidate. The motivating case is ISO-BMFF
    // (MP4/MOV), whose `ftyp` magic starts at byte 4 after a 4-byte big-endian box
    // size. No MP4 validator exists yet — these tests cover the matching layer only.

    /// Builds a signature with no `header_offset`, i.e. the pre-existing shape that
    /// every entry in `config/signatures.json` had before the field was introduced.
    fn legacy_signature(file_type: &str, header: Vec<u8>) -> FileSignature {
        FileSignature {
            file_type: file_type.to_string(),
            header,
            footer: None,
            max_size_bytes: 1024,
            validator_id: file_type.to_string(),
            header_offset: None,
        }
    }

    #[test]
    fn test_signature_without_header_offset_still_matches_at_byte_zero() {
        // Backward compatibility: absent offset must behave exactly as offset 0 did.
        let png = legacy_signature("png", vec![0x89, 0x50, 0x4E, 0x47]);
        assert_eq!(png.resolved_header_offset(), 0);

        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(
            png.matches_header(&data),
            "A signature with no header_offset must match its magic at byte 0"
        );

        // And must still reject a candidate that does not begin with the magic.
        assert!(
            !png.matches_header(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
            "A signature with no header_offset must not match unrelated data"
        );

        // Equivalence with the previous `starts_with` test, across a spread of inputs.
        for candidate in [
            &[][..],
            &[0x89][..],
            &[0x89, 0x50, 0x4E][..],
            &[0x89, 0x50, 0x4E, 0x47][..],
            &[0x89, 0x50, 0x4E, 0x47, 0x00, 0x00][..],
            &[0x00, 0x89, 0x50, 0x4E, 0x47][..],
        ] {
            assert_eq!(
                png.matches_header(candidate),
                candidate.starts_with(&png.header),
                "matches_header must be identical to starts_with for an offset-less signature (input {:02X?})",
                candidate
            );
        }
    }

    #[test]
    fn test_signature_with_header_offset_matches_at_that_offset() {
        // ISO-BMFF shape: 4-byte big-endian box size, then the 'ftyp' magic at byte 4.
        let mut mp4 = legacy_signature("mp4", b"ftyp".to_vec());
        mp4.header_offset = Some(4);
        assert_eq!(mp4.resolved_header_offset(), 4);

        let mut candidate = Vec::new();
        candidate.extend_from_slice(&32u32.to_be_bytes()); // box size
        candidate.extend_from_slice(b"ftypisom");
        candidate.extend_from_slice(&[0u8; 16]);

        assert!(
            mp4.matches_header(&candidate),
            "A signature with header_offset = 4 must match magic beginning at byte 4"
        );

        // Exactly-sized buffer: magic ends flush with the end of the data.
        assert!(
            mp4.matches_header(&[0x00, 0x00, 0x00, 0x20, b'f', b't', b'y', b'p']),
            "A buffer ending exactly at the end of the magic must still match"
        );
    }

    #[test]
    fn test_header_offset_signature_does_not_falsely_match_at_byte_zero() {
        let mut mp4 = legacy_signature("mp4", b"ftyp".to_vec());
        mp4.header_offset = Some(4);

        // The magic is present, but at byte 0 rather than byte 4. This is the false
        // positive an offset-unaware matcher would accept, and it must be rejected.
        let magic_at_zero = b"ftypisomAAAAAAAA";
        assert!(
            !mp4.matches_header(magic_at_zero),
            "Magic at byte 0 must NOT satisfy a signature declaring header_offset = 4"
        );

        // Magic one byte early and one byte late must both be rejected.
        assert!(!mp4.matches_header(b"AAAftypisom"));
        assert!(!mp4.matches_header(b"AAAAAftypisom"));

        // The same bytes as an offset-less signature would, of course, match at 0 —
        // proving the two signatures are genuinely discriminated by the offset alone.
        let offsetless = legacy_signature("mp4", b"ftyp".to_vec());
        assert!(offsetless.matches_header(magic_at_zero));
    }

    #[test]
    fn test_header_offset_matching_is_panic_free_on_short_input() {
        let mut mp4 = legacy_signature("mp4", b"ftyp".to_vec());
        mp4.header_offset = Some(4);

        // Every truncation shorter than offset + header length must return false
        // rather than panic on an out-of-range slice.
        let full = [0x00, 0x00, 0x00, 0x20, b'f', b't', b'y', b'p'];
        for len in 0..full.len() {
            assert!(
                !mp4.matches_header(&full[..len]),
                "Truncated input of {} bytes must not match and must not panic",
                len
            );
        }
        assert!(mp4.matches_header(&full), "The full 8 bytes must match");

        // An offset beyond any plausible buffer must also be handled, not panic.
        let mut absurd = legacy_signature("absurd", b"XYZ".to_vec());
        absurd.header_offset = Some(u32::MAX);
        assert!(!absurd.matches_header(&[0u8; 64]));
        assert!(!absurd.matches_header(&[]));

        // An offset-less signature on an empty buffer, for completeness.
        let png = legacy_signature("png", vec![0x89, 0x50]);
        assert!(!png.matches_header(&[]));
    }

    #[test]
    fn test_existing_signature_database_still_parses_and_is_unchanged() {
        // The shipped database must still load, and every format that predates the
        // header_offset field must still resolve to offset 0 — i.e. introducing the
        // field changed no existing format's behaviour.
        //
        // Scoped to the six offset-0 formats by name rather than asserting over every
        // entry, because the database now also carries the deliberately offset-4 'mp4'
        // signature. The property under test is "pre-existing formats are untouched",
        // not "no signature anywhere uses an offset".
        const OFFSET_ZERO_FORMATS: [&str; 6] = ["jpeg", "png", "pdf", "zip", "sqlite", "ole2"];

        let db = SignatureDb::standard_forensic_signatures();
        assert!(
            !db.signatures.is_empty(),
            "The signature database must load and be non-empty"
        );

        for sig in db
            .signatures
            .iter()
            .filter(|s| OFFSET_ZERO_FORMATS.contains(&s.file_type.as_str()))
        {
            assert_eq!(
                sig.header_offset, None,
                "Existing signature '{}' must not have acquired a header_offset",
                sig.file_type
            );
            assert_eq!(sig.resolved_header_offset(), 0);
        }

        // All six shipped formats must still be present and detected at byte 0.
        for (file_type, magic) in [
            ("jpeg", vec![0xFF, 0xD8, 0xFF]),
            ("png", vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            ("pdf", b"%PDF-".to_vec()),
            ("zip", b"PK\x03\x04".to_vec()),
            ("sqlite", b"SQLite format 3\0".to_vec()),
            ("ole2", vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        ] {
            let sig = db
                .signatures
                .iter()
                .find(|s| s.file_type == file_type)
                .unwrap_or_else(|| panic!("signature database must contain '{}'", file_type));
            assert_eq!(sig.header, magic, "'{}' magic must be unchanged", file_type);

            // A candidate fronted by the magic must match, exactly as before.
            let mut candidate = magic.clone();
            candidate.extend_from_slice(&[0u8; 32]);
            assert!(
                sig.matches_header(&candidate),
                "'{}' must still be detected at byte 0",
                file_type
            );

            // And the same magic pushed off byte 0 must not match.
            let mut shifted = vec![0xAA];
            shifted.extend_from_slice(&candidate);
            assert!(
                !sig.matches_header(&shifted),
                "'{}' must not match when its magic is not at byte 0",
                file_type
            );
        }
    }

    #[test]
    fn test_header_offset_json_round_trip_is_backward_compatible() {
        // A JSON entry with no header_offset key must deserialize to None.
        let legacy_json = r#"[
            {
                "file_type": "png",
                "header": [137, 80, 78, 71],
                "footer": null,
                "max_size_bytes": 52428800,
                "validator_id": "png"
            }
        ]"#;
        let db = SignatureDb::from_json(legacy_json).expect("legacy JSON must still parse");
        assert_eq!(db.signatures.len(), 1);
        assert_eq!(db.signatures[0].header_offset, None);
        assert!(db.signatures[0].matches_header(&[137, 80, 78, 71, 13, 10]));

        // A JSON entry that declares the field must deserialize to Some(_).
        let offset_json = r#"[
            {
                "file_type": "mp4",
                "header": [102, 116, 121, 112],
                "footer": null,
                "max_size_bytes": 104857600,
                "validator_id": "mp4",
                "header_offset": 4
            }
        ]"#;
        let db = SignatureDb::from_json(offset_json).expect("offset JSON must parse");
        assert_eq!(db.signatures[0].header_offset, Some(4));
        assert!(db.signatures[0].matches_header(b"\x00\x00\x00\x20ftypisom"));
        assert!(!db.signatures[0].matches_header(b"ftypisomAAAA"));

        // Serializing a signature that has no offset must not emit the key, so the
        // on-disk database keeps its original shape if it is ever round-tripped.
        let serialized =
            serde_json::to_string(&legacy_signature("png", vec![137, 80])).expect("must serialize");
        assert!(
            !serialized.contains("header_offset"),
            "An offset-less signature must not serialize a header_offset key, got: {}",
            serialized
        );
    }

    // --- 4c. MP4 / MOV ISO-BMFF Validator Tests (§26.2, §28) ---

    /// Builds one ISO-BMFF box with a standard 32-bit size header.
    fn mp4_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 8 + payload.len();
        let mut b = Vec::with_capacity(total);
        b.extend_from_slice(&(total as u32).to_be_bytes());
        b.extend_from_slice(box_type);
        b.extend_from_slice(payload);
        b
    }

    /// Builds one ISO-BMFF box using the 64-bit extended size form (size32 == 1).
    fn mp4_box_ext(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 16 + payload.len();
        let mut b = Vec::with_capacity(total);
        b.extend_from_slice(&1u32.to_be_bytes()); // size32 == 1 -> extended
        b.extend_from_slice(box_type);
        b.extend_from_slice(&(total as u64).to_be_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// Builds an `ftyp` payload: major_brand + minor_version + compatible brands.
    fn ftyp_payload(major: &[u8; 4], compatible: &[&[u8; 4]]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(major);
        p.extend_from_slice(&512u32.to_be_bytes()); // minor_version
        for c in compatible {
            p.extend_from_slice(*c);
        }
        p
    }

    /// A minimal but structurally complete MP4: ftyp + moov + mdat.
    fn build_valid_mp4(major: &[u8; 4], compatible: &[&[u8; 4]]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(major, compatible)));
        f.extend_from_slice(&mp4_box(b"moov", &[0xAA; 40]));
        f.extend_from_slice(&mp4_box(b"mdat", &[0x5A; 64]));
        f
    }

    #[test]
    fn test_mp4_validator_accepts_minimal_valid_file() {
        let v = Mp4Validator;
        let mp4 = build_valid_mp4(b"isom", &[b"isom", b"mp42"]);

        let res = v.validate(&mp4);
        assert!(
            res.is_ok(),
            "ftyp + moov + mdat must yield V_OK, got: {}",
            res
        );
        match res {
            ValidationResult::Ok { object_length } => assert_eq!(
                object_length,
                Some(mp4.len() as u64),
                "object_length must be the exact sum of the top-level box sizes"
            ),
            other => panic!("expected V_OK, got {}", other),
        }

        // appended_data_ignored: sector padding after the object must not change the
        // reported length, and must not prevent recognition.
        let mut padded = mp4.clone();
        padded.extend_from_slice(&[0u8; 512]);
        match v.validate(&padded) {
            ValidationResult::Ok { object_length } => assert_eq!(
                object_length,
                Some(mp4.len() as u64),
                "Zero padding after the last box must not extend the object length"
            ),
            other => panic!("padded MP4 must still yield V_OK, got {}", other),
        }
    }

    #[test]
    fn test_mp4_validator_flags_and_type() {
        let flags = Mp4Validator.flags();
        assert!(
            flags.err_is_prefix,
            "The box tree is walked front-to-back, so an error is a prefix property"
        );
        assert!(
            flags.appended_data_ignored,
            "The box chain gives an exact extent, so trailing bytes are ignored"
        );
        assert!(
            !flags.no_zblocks,
            "free/skip padding boxes make all-zero blocks legitimate in ISO-BMFF"
        );
        assert_eq!(Mp4Validator.file_type(), "mp4");
    }

    #[test]
    fn test_mp4_validator_accepts_quicktime_compatible_brand() {
        // A modern QuickTime/MOV file carrying an ISO-BMFF ftyp with brand 'qt  '.
        let v = Mp4Validator;
        let mov = build_valid_mp4(b"qt  ", &[b"qt  "]);
        assert!(
            v.validate(&mov).is_ok(),
            "A QuickTime-brand ISO-BMFF object must validate like any other brand"
        );
        assert!(vajra_carve_mp4_is_quicktime(b"qt  "));
        assert!(!vajra_carve_mp4_is_quicktime(b"isom"));

        // Structural validity must NOT depend on the known-brand list: an unheard-of
        // brand that is otherwise well formed is still a valid object.
        let exotic = build_valid_mp4(b"Zz9 ", &[b"Zz9 "]);
        assert!(
            v.validate(&exotic).is_ok(),
            "An unknown but well-formed brand must not be rejected"
        );
        assert!(!crate::tier2::mp4::is_known_brand(b"Zz9 "));
    }

    // Local aliases so the test body reads clearly.
    fn vajra_carve_mp4_is_quicktime(b: &[u8]) -> bool {
        crate::tier2::mp4::is_quicktime_brand(b)
    }

    #[test]
    fn test_mp4_signature_detects_ftyp_at_offset_four_through_real_matcher() {
        // Exercises the REAL signature matcher against the REAL shipped database.
        let db = SignatureDb::standard_forensic_signatures();
        let sig = db
            .signatures
            .iter()
            .find(|s| s.file_type == "mp4")
            .expect("signatures.json must contain an 'mp4' entry");

        assert_eq!(sig.header, b"ftyp".to_vec(), "magic must be ASCII 'ftyp'");
        assert_eq!(sig.header_offset, Some(4), "ftyp begins at byte 4");
        assert_eq!(sig.validator_id, "mp4");

        let mp4 = build_valid_mp4(b"isom", &[b"isom"]);
        assert!(
            sig.matches_header(&mp4),
            "The shipped mp4 signature must detect ftyp at offset 4"
        );

        // And the registered validator must accept what the signature matched.
        let registry = ValidatorRegistry::default();
        let v = registry
            .get("mp4")
            .expect("ValidatorRegistry must expose the 'mp4' validator id");
        assert_eq!(v.file_type(), "mp4");
        assert!(v.validate(&mp4).is_ok());
    }

    #[test]
    fn test_mp4_signature_does_not_match_ftyp_in_the_wrong_place() {
        let db = SignatureDb::standard_forensic_signatures();
        let sig = db.signatures.iter().find(|s| s.file_type == "mp4").unwrap();

        // 'ftyp' at byte 0 — the classic false positive an offset-unaware matcher takes.
        assert!(!sig.matches_header(b"ftypisomAAAAAAAA"));
        // 'ftyp' deeper in the buffer, e.g. inside unrelated data.
        assert!(!sig.matches_header(b"AAAAAAAAftypisom"));
        assert!(!sig.matches_header(b"AAAftypisomAAAA"));
        // Plain text that merely contains the word.
        assert!(!sig.matches_header(b"see the ftyp box for details"));
    }

    #[test]
    fn test_mp4_existing_offset_zero_signatures_are_unaffected() {
        // Regression: adding the offset-4 mp4 entry must not perturb any existing format.
        let db = SignatureDb::standard_forensic_signatures();

        for file_type in ["jpeg", "png", "pdf", "zip", "sqlite", "ole2"] {
            let sig = db
                .signatures
                .iter()
                .find(|s| s.file_type == file_type)
                .unwrap_or_else(|| panic!("'{}' must still be present", file_type));
            assert_eq!(
                sig.header_offset, None,
                "'{}' must still have no header_offset",
                file_type
            );
            assert_eq!(sig.resolved_header_offset(), 0);

            let mut candidate = sig.header.clone();
            candidate.extend_from_slice(&[0u8; 32]);
            assert!(
                sig.matches_header(&candidate),
                "'{}' must still match at byte 0",
                file_type
            );
        }

        // The mp4 signature must not shadow or be shadowed by any other entry: no other
        // signature may match a well-formed MP4's first sector.
        let mp4 = build_valid_mp4(b"isom", &[b"isom"]);
        let matching: Vec<&str> = db
            .signatures
            .iter()
            .filter(|s| s.matches_header(&mp4))
            .map(|s| s.file_type.as_str())
            .collect();
        assert_eq!(
            matching,
            vec!["mp4"],
            "Exactly one signature must claim an MP4 candidate (no duplicate carving hits)"
        );
    }

    #[test]
    fn test_mp4_truncated_and_oversized_boxes_yield_eof() {
        let v = Mp4Validator;
        let mp4 = build_valid_mp4(b"isom", &[b"isom"]);

        // 1. A declared box larger than the available data -> V_EOF.
        //    (ftyp + moov complete, mdat declares 64 KiB but only 16 bytes follow.)
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        oversized.extend_from_slice(&mp4_box(b"moov", &[0xAA; 32]));
        oversized.extend_from_slice(&65536u32.to_be_bytes());
        oversized.extend_from_slice(b"mdat");
        oversized.extend_from_slice(&[0x5A; 16]);
        let res = v.validate(&oversized);
        assert!(
            res.is_eof(),
            "A declared box extending past the data must yield V_EOF, got: {}",
            res
        );

        // Critically: it must NOT be reported complete just because moov was seen.
        assert!(
            !res.is_ok(),
            "A truncated recording must never be reported as a complete object"
        );

        // 2. Truncated ordinary box header (fewer than 8 bytes remain after a box).
        let mut short_header = mp4.clone();
        short_header.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert!(
            v.validate(&short_header).is_ok(),
            "A complete object followed by 3 stray bytes ends at the object boundary"
        );

        // 3. Mid-file truncation of the whole candidate.
        for cut in [8usize, 16, 24, mp4.len() - 1] {
            let res = v.validate(&mp4[..cut]);
            assert!(
                res.is_eof(),
                "MP4 truncated to {} bytes must yield V_EOF, got: {}",
                cut,
                res
            );
        }

        // 4. ftyp alone, with no moov/mdat/moof, is structurally sound but incomplete.
        let ftyp_only = mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"]));
        let res = v.validate(&ftyp_only);
        assert!(
            res.is_eof(),
            "ftyp with no media box must yield V_EOF (more data could complete it), got: {}",
            res
        );
    }

    #[test]
    fn test_mp4_box_size_below_header_length_yields_err() {
        let v = Mp4Validator;

        // First box declares size 4 — impossible, the header alone is 8 bytes.
        let mut bad = Vec::new();
        bad.extend_from_slice(&4u32.to_be_bytes());
        bad.extend_from_slice(b"ftyp");
        bad.extend_from_slice(&[0u8; 32]);
        let res = v.validate(&bad);
        assert!(
            res.is_err(),
            "A box size below its 8-byte header must yield V_ERR, got: {}",
            res
        );

        // Every impossible size 2..=7 in the first box must be rejected.
        for size in 2u32..=7 {
            let mut b = Vec::new();
            b.extend_from_slice(&size.to_be_bytes());
            b.extend_from_slice(b"ftyp");
            b.extend_from_slice(&[0u8; 32]);
            assert!(
                v.validate(&b).is_err(),
                "First box declaring size {} must yield V_ERR",
                size
            );
        }
    }

    #[test]
    fn test_mp4_extended_64bit_size_box() {
        let v = Mp4Validator;

        // 1. Valid extended-size mdat.
        let mut ext = Vec::new();
        ext.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        ext.extend_from_slice(&mp4_box(b"moov", &[0xAA; 24]));
        ext.extend_from_slice(&mp4_box_ext(b"mdat", &[0x5A; 48]));
        let res = v.validate(&ext);
        assert!(
            res.is_ok(),
            "A valid 64-bit extended-size box must yield V_OK, got: {}",
            res
        );
        match res {
            ValidationResult::Ok { object_length } => {
                assert_eq!(object_length, Some(ext.len() as u64))
            }
            other => panic!("expected V_OK, got {}", other),
        }

        // 2. Truncated 64-bit size field: size32 == 1 but fewer than 16 header bytes.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        truncated.extend_from_slice(&1u32.to_be_bytes());
        truncated.extend_from_slice(b"mdat");
        truncated.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // only 4 of 8 size bytes
        let res = v.validate(&truncated);
        assert!(
            res.is_eof(),
            "A truncated 64-bit size field must yield V_EOF, got: {}",
            res
        );

        // 3. Extended size smaller than its own 16-byte header is impossible.
        let mut impossible = Vec::new();
        impossible.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        impossible.extend_from_slice(&1u32.to_be_bytes());
        impossible.extend_from_slice(b"mdat");
        impossible.extend_from_slice(&8u64.to_be_bytes()); // < 16
        impossible.extend_from_slice(&[0u8; 32]);
        assert!(
            v.validate(&impossible).is_err(),
            "A 64-bit size below the 16-byte extended header must yield V_ERR"
        );
    }

    #[test]
    fn test_mp4_malformed_ftyp_payload_yields_err() {
        let v = Mp4Validator;

        // 1. ftyp payload too small for major_brand + minor_version.
        let tiny = mp4_box(b"ftyp", &[0x69, 0x73, 0x6F, 0x6D]); // 4 bytes only
        assert!(
            v.validate(&tiny).is_err(),
            "ftyp payload below 8 bytes must yield V_ERR"
        );

        // 2. Compatible-brands region not a multiple of 4.
        let mut ragged_payload = ftyp_payload(b"isom", &[b"isom"]);
        ragged_payload.extend_from_slice(&[0x41, 0x42]); // 2 stray bytes
        let mut ragged = mp4_box(b"ftyp", &ragged_payload);
        ragged.extend_from_slice(&mp4_box(b"mdat", &[0u8; 16]));
        assert!(
            v.validate(&ragged).is_err(),
            "A compatible-brands region that is not a multiple of 4 must yield V_ERR"
        );

        // 3. Non-printable major brand.
        let mut binary_payload = Vec::new();
        binary_payload.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        binary_payload.extend_from_slice(&0u32.to_be_bytes());
        let bad_brand = mp4_box(b"ftyp", &binary_payload);
        assert!(
            v.validate(&bad_brand).is_err(),
            "A non-printable major_brand must yield V_ERR"
        );

        // 4. First box is well formed but is not ftyp.
        let mut not_ftyp = Vec::new();
        not_ftyp.extend_from_slice(&mp4_box(b"moov", &[0u8; 32]));
        not_ftyp.extend_from_slice(&mp4_box(b"mdat", &[0u8; 16]));
        assert!(
            v.validate(&not_ftyp).is_err(),
            "A first box that is not ftyp must yield V_ERR"
        );
    }

    #[test]
    fn test_mp4_unknown_top_level_box_is_skipped_safely() {
        let v = Mp4Validator;

        // 'uuid' and a wholly invented 'zZz9' box sit between the known ones. Both must
        // be skipped by their declared size rather than rejected.
        let mut f = Vec::new();
        f.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        f.extend_from_slice(&mp4_box(b"free", &[0u8; 24]));
        f.extend_from_slice(&mp4_box(b"uuid", &[0x11; 32]));
        f.extend_from_slice(&mp4_box(b"zZz9", &[0x22; 16]));
        f.extend_from_slice(&mp4_box(b"wide", &[0u8; 8]));
        f.extend_from_slice(&mp4_box(b"moov", &[0xAA; 40]));
        f.extend_from_slice(&mp4_box(b"skip", &[0u8; 16]));
        f.extend_from_slice(&mp4_box(b"mdat", &[0x5A; 64]));

        let res = v.validate(&f);
        assert!(
            res.is_ok(),
            "Unknown but well-formed top-level boxes must be skipped, got: {}",
            res
        );
        match res {
            ValidationResult::Ok { object_length } => {
                assert_eq!(
                    object_length,
                    Some(f.len() as u64),
                    "Skipped boxes still count toward the object length"
                )
            }
            other => panic!("expected V_OK, got {}", other),
        }

        // Recognition helper reports the documented set, but it does not gate validity.
        for t in [
            b"ftyp", b"moov", b"mdat", b"moof", b"free", b"skip", b"wide",
        ] {
            assert!(crate::tier2::mp4::is_recognised_top_level_box(t));
        }
        assert!(!crate::tier2::mp4::is_recognised_top_level_box(b"zZz9"));
    }

    #[test]
    fn test_mp4_validator_is_panic_free_on_tiny_and_hostile_input() {
        let v = Mp4Validator;

        // Tiny inputs must not panic.
        for len in [0usize, 1, 2, 3, 4, 5, 6, 7] {
            let data = vec![0x00u8; len];
            let res = v.validate(&data);
            assert!(
                res.is_eof(),
                "{}-byte input must yield V_EOF without panicking, got: {}",
                len,
                res
            );
        }

        // All-zero buffer: the type tag is 00 00 00 00, which is not a plausible box.
        assert!(v.validate(&[0u8; 512]).is_err());

        // 0xFF-filled buffer: enormous declared size, non-ftyp type.
        assert!(!v.validate(&[0xFFu8; 512]).is_ok());

        // A size field of u32::MAX in the first box must not overflow or panic.
        let mut huge = Vec::new();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        huge.extend_from_slice(b"ftyp");
        huge.extend_from_slice(&[0u8; 32]);
        assert!(v.validate(&huge).is_eof());

        // A 64-bit size of u64::MAX must be caught by the overflow check, not panic.
        let mut overflow = Vec::new();
        overflow.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        overflow.extend_from_slice(&1u32.to_be_bytes());
        overflow.extend_from_slice(b"mdat");
        overflow.extend_from_slice(&u64::MAX.to_be_bytes());
        overflow.extend_from_slice(&[0u8; 16]);
        let res = v.validate(&overflow);
        assert!(!res.is_ok(), "A u64::MAX box size must never validate");
    }

    #[test]
    fn test_mp4_one_megabyte_tier2_window_limitation_is_real() {
        // Documents the known limitation reported alongside this work: Tier 2 hands a
        // validator at most 2048 sectors (1 MiB). A real MP4 whose mdat is larger than
        // the window has that mdat declared but not present, so the validator correctly
        // returns V_EOF — and Tier 2 only produces an artifact from V_OK. Large MP4s are
        // therefore detected but not recovered until the window limit is addressed.
        let v = Mp4Validator;
        const WINDOW: usize = 2048 * 512; // 1 MiB, matching carve_tier2's cap

        let mut header = Vec::new();
        header.extend_from_slice(&mp4_box(b"ftyp", &ftyp_payload(b"isom", &[b"isom"])));
        header.extend_from_slice(&mp4_box(b"moov", &[0xAA; 256]));
        // mdat declaring 8 MiB of media — bigger than the window.
        let mdat_total: u32 = 8 * 1024 * 1024;
        header.extend_from_slice(&mdat_total.to_be_bytes());
        header.extend_from_slice(b"mdat");

        let mut window = header.clone();
        window.resize(WINDOW, 0x5A); // the slice Tier 2 would actually supply

        let res = v.validate(&window);
        assert!(
            res.is_eof(),
            "An MP4 whose mdat exceeds the 1 MiB Tier-2 window must yield V_EOF, got: {}",
            res
        );
        assert!(
            !res.is_ok(),
            "It must NOT be reported complete — that would carve a truncated recording"
        );

        // The same file wholly inside the window validates fine, proving the limit is
        // the window and not the validator.
        let small = build_valid_mp4(b"isom", &[b"isom"]);
        assert!(small.len() < WINDOW);
        assert!(v.validate(&small).is_ok());
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
