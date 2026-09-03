//! MP4 / MOV — ISO Base Media File Format Structural Validator (§26.2, §28).
//!
//! Implements the atom/box tree walk §26.2 specifies for MP4/MOV: *"Parse the atom/box
//! tree (`ftyp`, `moov`, `mdat`)"*. Reference: ISO/IEC 14496-12 (ISO Base Media File
//! Format), the container shared by MP4, and by modern QuickTime/MOV files that carry
//! an ISO-BMFF-style `ftyp`.
//!
//! # Detection
//!
//! An ISO-BMFF file does **not** begin with its magic. It begins with the 4-byte
//! big-endian size of the first box, and the `ftyp` type tag only starts at byte 4:
//!
//! ```text
//!   0..4   box size   (varies per file — NOT a usable signature)
//!   4..8   'ftyp'     (the actual magic)
//!   8..12  major_brand
//!  12..16  minor_version
//!  16..    compatible_brands[] (zero or more 4-byte brands)
//! ```
//!
//! Detection therefore uses the signature database's `header_offset` mechanism with
//! `header = "ftyp"` and `header_offset = 4`. Anchoring on the size bytes instead would
//! be brittle, since `00 00 00 18` is only one of many valid first-box sizes.
//!
//! The candidate still begins at byte 0 — `header_offset` moves where the magic is
//! looked for, not where the object starts — so this validator receives the box size
//! field it needs in order to parse.
//!
//! # Validation strategy
//!
//! Top-level boxes are walked with strict bounds checking. The walk distinguishes three
//! very different reasons for stopping, which is what makes carving from a padded disk
//! window work correctly:
//!
//! - **Truncated** — a *well-formed* box header declares an extent that runs past the
//!   supplied data. Something in the data actively declares more object than is present,
//!   and a well-formed header is strong evidence of a real box, so the object genuinely
//!   continues beyond the slice: `V_EOF`, never `V_OK` — even when `ftyp` and a media box
//!   have already been seen. Reporting otherwise would carve a partial recording and
//!   label it whole.
//! - **Malformed** — the bytes are not a box header at all (non-printable type tag, size
//!   below the header length, arithmetic overflow). On a real disk this is what sector
//!   padding or the next file looks like, so it marks the natural end of the object:
//!   `V_OK` if the object is already complete, otherwise `V_ERR`.
//! - **Exhausted** — fewer than 8 bytes remain, so nothing can start a box and nothing
//!   declares any further extent. A complete object followed by a short stub of padding
//!   lands here and is still recognised as complete: `V_OK` if complete, else `V_EOF`.
//!
//! Ordering matters: the type tag is checked *before* the size, so a run of zero padding
//! (type `00 00 00 00`) is classified Malformed — end of object — rather than being read
//! as a `size == 0` "extends to end of file" box.
//!
//! # Completeness
//!
//! A complete object requires a valid `ftyp` **and** at least one meaningful media
//! structure (`moov`, `mdat` or `moof`). A candidate holding only `ftyp` plus padding
//! boxes is structurally sound but not yet a media file, so it yields `V_EOF` rather
//! than `V_ERR` — more data could complete it, which is exactly Garfinkel's V_EOF.
//!
//! # `moov` reconstruction is NOT implemented
//!
//! §28 describes reconstructing a minimal `moov` from `mdat` when a recording was
//! interrupted. **That is deliberately not implemented here, because the current
//! interface cannot express it.** `StructuralValidator::validate` returns a
//! `ValidationResult` — a status plus an optional length. It has no channel for
//! returning *repaired or synthesised bytes*, and Tier 2 carves `payload` directly from
//! the source at the reported length, so a validator physically cannot emit a modified
//! object. moov reconstruction is therefore incompatible with the current validator
//! output interface and is deferred; it would need a new trait method or a repair stage
//! in the pipeline, which is a design change well beyond adding a validator.
//!
//! Flags: `err_is_prefix: true`, `appended_data_ignored: true`, `no_zblocks: false`.

use crate::tier2::validator::{StructuralValidator, ValidationResult, ValidatorFlags};

/// The ISO-BMFF magic, which begins at byte 4 rather than byte 0.
pub const FTYP_MAGIC: [u8; 4] = *b"ftyp";

/// Byte offset at which [`FTYP_MAGIC`] appears, for the signature database's
/// `header_offset` field.
pub const FTYP_HEADER_OFFSET: u32 = 4;

/// Standard box header: 4-byte size + 4-byte type.
const BOX_HEADER_LEN: u64 = 8;

/// Extended box header: 4-byte size==1 + 4-byte type + 8-byte 64-bit size.
const EXT_BOX_HEADER_LEN: u64 = 16;

/// `ftyp` requires at least major_brand (4) + minor_version (4).
const FTYP_MIN_PAYLOAD: u64 = 8;

/// Bound on top-level boxes examined, guarding against a pathological candidate.
/// Every accepted box advances the cursor by at least [`BOX_HEADER_LEN`], so the walk
/// already cannot loop; this is a second, explicit stop.
const MAX_TOP_LEVEL_BOXES: usize = 4096;

const BOX_FTYP: &[u8; 4] = b"ftyp";
const BOX_MOOV: &[u8; 4] = b"moov";
const BOX_MDAT: &[u8; 4] = b"mdat";
const BOX_MOOF: &[u8; 4] = b"moof";
const BOX_FREE: &[u8; 4] = b"free";
const BOX_SKIP: &[u8; 4] = b"skip";
const BOX_WIDE: &[u8; 4] = b"wide";

/// Brands recognised **for diagnostics and tests only**.
///
/// Structural validity never depends on this list — ISO-BMFF brands are open-ended and a
/// whitelist would reject legitimate files. A brand outside this list is accepted exactly
/// like one inside it.
pub const KNOWN_BRANDS: [&[u8; 4]; 12] = [
    b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1", b"dash", b"qt  ",
    b"M4V ", b"M4A ",
];

/// True for the QuickTime brand. Informational only — see the MOV note on
/// [`Mp4Validator`]; it does not affect validation or the carved file extension.
pub fn is_quicktime_brand(brand: &[u8]) -> bool {
    brand == b"qt  "
}

/// True if `brand` appears in [`KNOWN_BRANDS`]. Diagnostics only.
pub fn is_known_brand(brand: &[u8]) -> bool {
    KNOWN_BRANDS.iter().any(|b| brand == &b[..])
}

/// A box type tag byte must be printable ASCII, or 0xA9 — the copyright prefix
/// QuickTime uses for metadata atoms such as `©nam`.
#[inline]
fn is_plausible_type_byte(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == 0xA9
}

#[inline]
fn u32_be(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

#[inline]
fn u64_be(d: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    u64::from_be_bytes(b)
}

/// Outcome of examining the bytes at one cursor position.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BoxScan {
    /// A well-formed box wholly contained in the supplied data.
    Found {
        box_type: [u8; 4],
        total_size: u64,
        header_len: u64,
    },
    /// A well-formed header whose declared extent runs past the supplied data, or a
    /// declared extended-size box whose 64-bit size field is cut short. Something in
    /// the data actively declares more object than is present, so the object continues
    /// beyond the slice.
    Truncated,
    /// Fewer than [`BOX_HEADER_LEN`] bytes remain, so no box can start here and nothing
    /// declares any further extent. Distinct from [`BoxScan::Truncated`]: a complete
    /// object followed by a stub of sector padding lands here and must still be
    /// recognised as complete.
    Exhausted,
    /// Not a box header at all. On real media this is padding or the next file.
    Malformed(String),
}

/// Examines the bytes at `offset` without consuming them. Never panics: every read is
/// bounds-checked first, and every size computation is checked for overflow.
fn scan_box(data: &[u8], offset: usize) -> BoxScan {
    let available = match data.len().checked_sub(offset) {
        Some(a) => a as u64,
        None => return BoxScan::Exhausted,
    };

    if available < BOX_HEADER_LEN {
        return BoxScan::Exhausted;
    }

    let size32 = u32_be(data, offset) as u64;
    let mut box_type = [0u8; 4];
    box_type.copy_from_slice(&data[offset + 4..offset + 8]);

    // Type tag is checked FIRST, so zero padding (type 00 00 00 00) is classified as
    // Malformed — the end of the object — rather than as a `size == 0` box.
    if !box_type.iter().all(|&b| is_plausible_type_byte(b)) {
        return BoxScan::Malformed(format!(
            "box type at offset {} is not a plausible 4-character tag ({:02X?})",
            offset, box_type
        ));
    }

    let (total_size, header_len) = match size32 {
        // size == 0 means "this box extends to end of file". A carved slice has no
        // knowable end of file, so the object's extent cannot be established here.
        // Reported as Truncated rather than guessed at — see the module note on why a
        // guessed length must never be reported as V_OK.
        0 => return BoxScan::Truncated,

        // size == 1 means the real size is a 64-bit value following the type tag.
        1 => {
            if available < EXT_BOX_HEADER_LEN {
                return BoxScan::Truncated;
            }
            let size64 = u64_be(data, offset + 8);
            if size64 < EXT_BOX_HEADER_LEN {
                return BoxScan::Malformed(format!(
                    "extended box '{}' at offset {} declares 64-bit size {} below its 16-byte header",
                    String::from_utf8_lossy(&box_type),
                    offset,
                    size64
                ));
            }
            (size64, EXT_BOX_HEADER_LEN)
        }

        // 2..=7 cannot hold even the 8-byte header.
        2..=7 => {
            return BoxScan::Malformed(format!(
                "box '{}' at offset {} declares size {} below its 8-byte header",
                String::from_utf8_lossy(&box_type),
                offset,
                size32
            ))
        }

        n => (n, BOX_HEADER_LEN),
    };

    let end = match (offset as u64).checked_add(total_size) {
        Some(e) => e,
        None => {
            return BoxScan::Malformed(format!(
                "box '{}' at offset {} overflows a 64-bit extent",
                String::from_utf8_lossy(&box_type),
                offset
            ))
        }
    };

    if end > data.len() as u64 {
        return BoxScan::Truncated;
    }

    BoxScan::Found {
        box_type,
        total_size,
        header_len,
    }
}

/// Validates the `ftyp` payload. Returns `None` when acceptable, or the reason it is not.
///
/// Checks structure, not brand membership: the payload must be able to hold
/// major_brand + minor_version, the major brand must be four printable characters, and
/// any compatible brands must occupy a whole number of 4-byte slots. Compatible-brand
/// *content* is not checked, because real files pad that list in ways a stricter rule
/// would wrongly reject.
fn validate_ftyp(data: &[u8], offset: usize, total_size: u64, header_len: u64) -> Option<String> {
    let payload_len = total_size - header_len;
    if payload_len < FTYP_MIN_PAYLOAD {
        return Some(format!(
            "ftyp payload is {} bytes, too small for major_brand + minor_version",
            payload_len
        ));
    }

    let brands_len = payload_len - FTYP_MIN_PAYLOAD;
    if brands_len % 4 != 0 {
        return Some(format!(
            "ftyp compatible-brands region is {} bytes, not a multiple of 4",
            brands_len
        ));
    }

    let brand_start = offset + header_len as usize;
    let major_brand = &data[brand_start..brand_start + 4];
    if !major_brand.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return Some(format!(
            "ftyp major_brand is not four printable characters ({:02X?})",
            major_brand
        ));
    }

    None
}

/// ISO Base Media File Format (MP4 / MOV) structural validator.
///
/// # MP4 vs MOV — a deliberate, reported limitation
///
/// This validator accepts any structurally sound ISO-BMFF object, including a modern
/// QuickTime/MOV file that carries an ISO-BMFF `ftyp` (brand `qt  `). It does **not**
/// support legacy QuickTime containers that lack `ftyp` entirely — those are not
/// detectable by this signature at all.
///
/// Carved artifacts are labelled `.mp4` regardless of brand. The extension comes from
/// the *signature database* entry's `file_type` field, not from this validator — Tier 2
/// builds the filename as `carved_file_{id}.{sig.file_type}` — so a validator cannot
/// influence it. Emitting `.mov` for QuickTime brands would require either a second
/// signature entry with the same `ftyp`/offset (which would double-match every candidate
/// and inflate the artifact count) or a pipeline change letting a validator override the
/// carved file type. Neither is in scope, so QuickTime-brand files are recovered
/// correctly but named `.mp4`.
#[derive(Debug, Default, Clone)]
pub struct Mp4Validator;

impl StructuralValidator for Mp4Validator {
    fn file_type(&self) -> &'static str {
        "mp4"
    }

    fn flags(&self) -> ValidatorFlags {
        // Reasoned engineering rationale, in the same style as the other validators:
        // - err_is_prefix: true — the box tree is walked strictly front-to-back. Once a
        //   header at some offset is structurally impossible, no amount of appended data
        //   can change those bytes, so the error is a property of the prefix.
        // - appended_data_ignored: true — the box chain gives the object's exact extent,
        //   so an ISO-BMFF reader stops at the last top-level box and ignores whatever
        //   follows. This is what lets a carved candidate keep its sector-padded tail.
        // - no_zblocks: false — a compound of `free`/`skip` padding boxes and zero-filled
        //   mdat regions means an all-zero 512-byte block is entirely legitimate here.
        //   (The engine only applies this test to a candidate's first sector, which for
        //   ISO-BMFF always contains ftyp and so is never all-zero — but the flag states
        //   a property of the format, and the honest value is false.)
        ValidatorFlags {
            err_is_prefix: true,
            appended_data_ignored: true,
            no_zblocks: false,
        }
    }

    fn validate(&self, data: &[u8]) -> ValidationResult {
        if (data.len() as u64) < BOX_HEADER_LEN {
            return ValidationResult::Eof {
                partial_length: data.len() as u64,
            };
        }

        let mut offset: usize = 0;
        let mut boxes_seen: usize = 0;
        let mut saw_ftyp = false;
        let mut saw_media = false;

        while offset < data.len() {
            if boxes_seen >= MAX_TOP_LEVEL_BOXES {
                // Implausible for a real top-level box chain; stop rather than grind.
                return if saw_ftyp && saw_media {
                    ValidationResult::Ok {
                        object_length: Some(offset as u64),
                    }
                } else {
                    ValidationResult::Err(format!(
                        "MP4 box chain exceeded {} top-level boxes without a complete object",
                        MAX_TOP_LEVEL_BOXES
                    ))
                };
            }

            match scan_box(data, offset) {
                BoxScan::Found {
                    box_type,
                    total_size,
                    header_len,
                } => {
                    if boxes_seen == 0 {
                        if &box_type != BOX_FTYP {
                            return ValidationResult::Err(format!(
                                "First MP4 box is '{}', expected 'ftyp'",
                                String::from_utf8_lossy(&box_type)
                            ));
                        }
                        if let Some(reason) = validate_ftyp(data, offset, total_size, header_len) {
                            return ValidationResult::Err(format!("Malformed MP4 {}", reason));
                        }
                        saw_ftyp = true;
                    }

                    if &box_type == BOX_MOOV || &box_type == BOX_MDAT || &box_type == BOX_MOOF {
                        saw_media = true;
                    }

                    // Unknown-but-well-formed boxes (and ftyp/free/skip/wide) are simply
                    // skipped by their declared size — the format is extensible and an
                    // unrecognised top-level box is not an error.
                    debug_assert!(total_size >= BOX_HEADER_LEN, "scan_box guarantees progress");
                    offset += total_size as usize;
                    boxes_seen += 1;
                }

                BoxScan::Exhausted => {
                    // Too few bytes left for any box header, and nothing declared more
                    // object. If ftyp and a media box have already been consumed on
                    // exact boundaries, this is the object's end followed by a stub of
                    // padding — not a truncated recording.
                    return if saw_ftyp && saw_media {
                        ValidationResult::Ok {
                            object_length: Some(offset as u64),
                        }
                    } else {
                        ValidationResult::Eof {
                            partial_length: offset as u64,
                        }
                    };
                }

                BoxScan::Truncated => {
                    // A well-formed header running past the data: the object genuinely
                    // continues beyond this slice. Never reported as complete, even if
                    // ftyp and a media box have already been seen — doing so would carve
                    // a partial recording and label it whole.
                    return ValidationResult::Eof {
                        partial_length: offset as u64,
                    };
                }

                BoxScan::Malformed(reason) => {
                    // Not a box. If the object is already complete, this is its natural
                    // end (sector padding, or the next file on the medium).
                    return if saw_ftyp && saw_media {
                        ValidationResult::Ok {
                            object_length: Some(offset as u64),
                        }
                    } else if boxes_seen == 0 {
                        ValidationResult::Err(format!("Invalid MP4 ftyp box: {}", reason))
                    } else {
                        ValidationResult::Err(format!("Invalid MP4 box structure: {}", reason))
                    };
                }
            }
        }

        // Consumed every byte on a clean box boundary.
        if saw_ftyp && saw_media {
            ValidationResult::Ok {
                object_length: Some(offset as u64),
            }
        } else {
            // Structurally sound so far, but no media structure yet: more data could
            // complete it, which is precisely V_EOF rather than V_ERR.
            ValidationResult::Eof {
                partial_length: offset as u64,
            }
        }
    }
}

/// True for the top-level box types this validator recognises by name (§26.2).
/// Recognition is informational — unknown boxes are skipped by size, not rejected.
pub fn is_recognised_top_level_box(box_type: &[u8]) -> bool {
    [
        BOX_FTYP, BOX_MOOV, BOX_MDAT, BOX_MOOF, BOX_FREE, BOX_SKIP, BOX_WIDE,
    ]
    .iter()
    .any(|b| box_type == &b[..])
}
