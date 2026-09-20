# Reference Index

This document catalogues the academic literature, specifications, and open-source forensic and sanitization implementations referenced during the architecture and development of Vajra.

---

## 1. Academic Literature & Foundation Research

- **Garfinkel (2007)**: *Carving Contiguous and Fragmented Files with Fast Object Validation*
  - File: `reference/garfinkel-2007-carving.pdf`
  - Purpose: Foundation for Vajra's Tier-2 fast object validation (`V_OK`, `V_ERR`, `V_EOF`) and Tier-3 bi-fragment gap carving with `err_is_prefix` early rejection.

---

## 2. Reference Forensic & Sanitization Implementations

| Reference Module | Domain / Area | Relevance to Vajra |
| :--- | :--- | :--- |
| **`reference/sleuthkit`** | Filesystem Forensics | Reference parsing logic for NTFS `$MFT` record attributes, ext4 extent trees/inodes, and FAT chain recovery. |
| **`reference/scalpel`** | File Carving | Benchmark comparison for file carving header/footer matching and sector-aligned scanning algorithms. |
| **`reference/libewf`** | Forensic Imaging | Specification and structure reference for Expert Witness Format (E01 / Ex01) header metadata and chunk compression. |
| **`reference/nwipe`** | Secure Sanitization | Reference implementations for DoD 5220.22-M, Gutmann, PRNG overwrite passes, and drive wiping patterns. |
| **`reference/tamper-evident-logging`** | Audit & Custody Integrity | Cryptographic hash chaining, Merkle tree concepts, and forward-secure audit log architectures. |
| **`reference/attest`** | Cryptographic Attestation | Digital signature packaging, PKI timestamping (RFC 3161), and independent verifier designs. |

---

## 3. Standards Traceability

For comprehensive traceability against international forensic and data destruction standards (NIST SP 800-88 Rev. 1, IEEE 2883-2022, ISO/IEC 27037:2012, ISO/IEC 27001:2022, Indian IT Act 2000 Section 65B, DPDP Act 2023), see [`docs/standards-mapping.md`](standards-mapping.md).
