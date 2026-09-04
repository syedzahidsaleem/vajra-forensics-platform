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

    /// Magic byte sequence at file start.
    pub header: Vec<u8>,

    /// Optional terminator byte sequence at file end.
    pub footer: Option<Vec<u8>>,

    /// Upper bound on file size in bytes to prevent unbounded search runaway.
    pub max_size_bytes: u64,

    /// Identifier corresponding to the registered `StructuralValidator`.
    pub validator_id: String,
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
