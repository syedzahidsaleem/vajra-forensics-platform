//! Extensible File Signature Database (§26.1).
//!
//! Signatures are defined as structured data (JSON/TOML), allowing new file types
//! and header/footer rules to be registered dynamically without recompilation.

use serde::{Deserialize, Serialize};

/// Signature specification for candidate generation (§26.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileSignature {
    /// Canonical file type identifier (e.g. "jpeg", "png", "pdf", "docx", "sqlite").
    pub file_type: String,

    /// Magic byte sequence identifying this format.
    ///
    /// By default this is expected at the very start of the candidate. Formats whose
    /// magic is not at byte 0 declare `header_offset` (see below).
    pub header: Vec<u8>,

    /// Optional terminator byte sequence at file end.
    pub footer: Option<Vec<u8>>,

    /// Upper bound on file size in bytes to prevent unbounded search runaway.
    pub max_size_bytes: u64,

    /// Identifier corresponding to the registered `StructuralValidator`.
    pub validator_id: String,

    /// Byte offset **within the candidate** at which `header` begins (§26.1).
    ///
    /// Absent (the default) means offset 0 — the historical behaviour in which the magic
    /// must front the candidate. Every signature written before this field existed
    /// therefore keeps its exact original matching semantics, and the field may be
    /// omitted from `config/signatures.json` entries entirely.
    ///
    /// The motivating case is ISO-BMFF (MP4/MOV), where a file begins with a 4-byte
    /// big-endian box size and the `ftyp` magic only starts at byte 4. Such a signature
    /// declares `"header_offset": 4`.
    ///
    /// **This shifts where the magic is looked for, not where the candidate starts.**
    /// A match still anchors the candidate at its own byte 0, so the structural validator
    /// continues to receive the whole object including the bytes preceding the magic —
    /// which for MP4/MOV is exactly right, since the box size field that precedes `ftyp`
    /// is part of the object and is required to parse it.
    ///
    /// Typed `u32` rather than `u64`: an offset is a position inside a single candidate
    /// buffer, 4 GiB is far beyond any plausible magic position, and `u32` converts to
    /// `usize` losslessly on every supported target — which removes a class of truncation
    /// bug that a `u64` would introduce at the slicing boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_offset: Option<u32>,
}

impl FileSignature {
    /// Resolved header offset, treating an absent value as 0.
    #[inline]
    pub fn resolved_header_offset(&self) -> usize {
        self.header_offset.unwrap_or(0) as usize
    }

    /// Returns true when `data` carries this signature's `header` at its configured offset.
    ///
    /// Replaces the previous `data.starts_with(&sig.header)` test. For a signature with no
    /// `header_offset` the two are exactly equivalent for every input, including the
    /// degenerate cases of an empty header (matches, as `starts_with(&[])` did) and a
    /// buffer shorter than the header (does not match).
    ///
    /// Never panics: the slice bounds are checked against `data.len()` before indexing, and
    /// offset-plus-length is computed with `checked_add`, so an absurd offset from a
    /// malformed signature database yields "no match" rather than an arithmetic overflow or
    /// an out-of-range slice.
    pub fn matches_header(&self, data: &[u8]) -> bool {
        let start = self.resolved_header_offset();
        let end = match start.checked_add(self.header.len()) {
            Some(e) => e,
            None => return false,
        };
        if end > data.len() {
            return false;
        }
        data[start..end] == self.header[..]
    }
}

/// In-memory signature database.
#[derive(Debug, Clone)]
pub struct SignatureDb {
    pub signatures: Vec<FileSignature>,
}

impl Default for SignatureDb {
    fn default() -> Self {
        Self::standard_forensic_signatures()
    }
}

impl SignatureDb {
    /// Loads standard baseline forensic signatures for Tier-2 carving (§26.1, §28).
    /// Dynamically loads from `config/signatures.json` or `VAJRA_SIGNATURES_PATH` if present.
    pub fn standard_forensic_signatures() -> Self {
        if let Ok(env_path) = std::env::var("VAJRA_SIGNATURES_PATH") {
            if let Ok(db) = Self::from_file(&env_path) {
                return db;
            }
        }

        let search_paths = [
            "config/signatures.json",
            "../config/signatures.json",
            "../../config/signatures.json",
            "signatures.json",
        ];

        for path in &search_paths {
            if std::path::Path::new(path).exists() {
                if let Ok(db) = Self::from_file(path) {
                    return db;
                }
            }
        }

        // Embedded fallback if external file not found on path
        let embedded_json = include_str!("../../../../config/signatures.json");
        Self::from_json(embedded_json).unwrap_or_else(|_| Self { signatures: Vec::new() })
    }

    /// Loads signatures from an external JSON file at runtime (§26.1).
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let signatures: Vec<FileSignature> = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self { signatures })
    }

    /// Loads signatures from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        let signatures: Vec<FileSignature> = serde_json::from_str(json_str)?;
        Ok(Self { signatures })
    }

    /// Appends a custom signature entry.
    pub fn register(&mut self, signature: FileSignature) {
        self.signatures.push(signature);
    }
}
