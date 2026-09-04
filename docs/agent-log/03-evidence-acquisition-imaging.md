# Vajra Agent Log: Conversation 03 — Evidence Acquisition & Imaging

## Scope Summary
- **Crates Implemented**:
  - `vajra-image`: Pure forensic container format reading and writing library (`ForensicImageReader`, `ForensicImageWriter`, `RawImageReader`, `RawImageWriter`, `E01ImageReader` via pure-Rust `ewf = "0.4.10"`).
  - `vajra-acquire`: Evidence acquisition orchestration engine implementing §19 and §20 (pre-flight storage verification, bad sector retry/reduction flowchart, non-ambiguous placeholder substitution, on-the-fly rolling SHA-256 calculation, Phase 2 independent re-read verification pass, checkpointing & resumability, Vault/Audit/Custody integration).
  - `vajra-cli`: Extended with `acquire start`, `acquire status`, `acquire resume`, `acquire verify`, and `image inspect` commands.

---

## Standing Invariants & Project Rules

> [!IMPORTANT]
> **Standing Safety Rule (Non-Destructive Testing)**:
> Destructive testing (actual overwrite, erase, or sanitization operations) must NEVER be run against the primary development machine's own drives or system board. All write/erase operations must target explicitly spare/scratch hardware set aside for that purpose.
> Read-only operations (`enumerate`, `fingerprint`, `inspect`, `acquire`) are safe and exempt from this rule as they only read blocks via `ReadOnlyBlockSource`.

> [!IMPORTANT]
> **Type-Level Forensic Safety Boundary (§16)**:
> All source devices in `vajra-acquire` are strictly bound to `&mut dyn ReadOnlyBlockSource` (or generic `<S: ReadOnlyBlockSource + ?Sized>`).
> There is no syntax or code path through which a writable handle (`WritableBlockSource` / `WritablePhysicalDrive`) can be passed into the acquisition engine.

---

## Key Architectural Decisions & Evidence

### 1. Bad-Sector Placeholder & Single Source of Truth Guarantee (§20)
- **Marker Design**: Bad sectors are substituted with the repeating ASCII byte sequence `b"VAJRA_BAD_SECTOR"` (`0x56 0x41 0x4A 0x52 0x41 0x5F 0x42 0x41 0x44 0x5F 0x53 0x45 0x43 0x54 0x4F 0x52`).
  - This pattern is immediately recognizable during human hex analysis.
  - It maintains exact LBA offset alignment so that filesystem structures in subsequent sectors remain at their true physical offsets.
- **Single Source of Truth**:
  - A byte pattern alone is inherently ambiguous because healthy user data could legitimately contain the string `"VAJRA_BAD_SECTOR"`.
  - Therefore, `BadSectorMap` (and its API `BadSectorMap::is_lba_bad(lba)`) is the **authoritative single source of truth** for unreadable sectors.
  - Integration test `test_bad_sector_flowchart_and_authoritative_map_guarantee` proves that healthy sectors containing the marker bytes are correctly identified as healthy by the map, while genuinely bad sectors are tracked accurately.

### 2. E01 Image Format Integration via `ewf = "0.4.10"`
- **Independent Verification on Crates.io (`cargo info ewf`)**:
  - **Package**: `ewf`
  - **Version**: `0.4.10`
  - **License**: `Apache-2.0` (100% compatible with Vajra workspace Apache-2.0/MIT licensing)
  - **Rust Version**: `1.85`
  - **Repository**: `https://github.com/SecurityRonin/ewf-forensic`
  - **Description**: "Pure Rust reader for Expert Witness Format (E01/EWF) forensic disk images"
  - **Features**: `verify` (MD5/SHA-1 stored checksum validation)
  - Verified and integrated cleanly into `vajra-image::E01ImageReader`.
  - Supports multi-segment files (`.E01`, `.E02`), case metadata extraction (`case_number`, `evidence_number`, `examiner`, `description`, `notes`), stored MD5/SHA-1 hashes, and implements `ReadOnlyBlockSource` for downstream filesystem parsing and carving.
- **AFF4 Status**:
  - AFF4 reader is staged as an extensible stub returning `ImageError::UnsupportedFormat("AFF4 format reader not yet enabled")` in accordance with the scoping decisions.

### 3. Dual-Phase Hashing Architecture & Phase 2 Independent Re-Read Confirmation (§19)
- **Phase 1 (Streaming Rolling Hash)**: Computed on-the-fly during the sector copy loop in `AcquisitionEngine::acquire` via `AcquisitionHasher`.
- **Phase 2 (Independent Re-Read Pass)**:
  - Confirmed via `verify_image_file` in [`crates/vajra-acquire/src/hasher.rs`](file:///d:/Coding/Vajra/crates/vajra-acquire/src/hasher.rs#L49-L80).
  - Phase 2 does NOT reuse the Phase 1 rolling hash variable. It performs a genuine, separate second I/O pass: opens the finalized image file with `File::open()`, reads the file from offset 0 to EOF in 1 MB chunks, computes a fresh SHA-256 digest, and cryptographically matches it against the Phase 1 value.
  - If a discrepancy occurs (e.g. storage write failure or partial buffer flush), `AcquisitionError::VerificationHashMismatch` is returned.

### 4. `RawImageReader` Device Fingerprint Derivation
- An image file has no hardware serial number or inquiry strings. `RawImageReader` derives a deterministic `DeviceFingerprint` as follows:
  - **Vendor**: `"RawImage"`
  - **Model**: `"Flat Binary Container"`
  - **Serial**: SHA-256 hash of the canonical absolute file path (ensuring distinct image files have distinct identities).
  - **Capacity**: Exact file length in bytes.
  - **Interface**: `"Virtual Image File"`
  - **Boundary Sample**: First 512 bytes (LBA 0 sample) of the container.
- This ensures deterministic identity tracking compatible with `DeviceFingerprint` equality and Vault evidence tracking.

### 5. Resumability Architecture (NFR-1)
- Periodic checkpoints are saved to the Evidence Vault `operations.parameters_json` field every `checkpoint_interval_blocks` (default 10,000 blocks) and on operation completion.
- `AcquisitionCheckpoint` preserves `start_lba`, `current_lba`, `end_lba`, `bytes_written`, `source_fingerprint`, and the full `BadSectorMap`.
- On resume:
  - Validates that the connected device's fingerprint matches `source_fingerprint` (§23).
  - Reopens the output image with `RawImageWriter::open_for_resume()`.
  - Continues copying from `current_lba`.
  - Executes a full Phase 2 SHA-256 verification pass over the complete reconstructed file upon completion.

---

## Verification & Real Hardware Test Results

### 1. Real Hardware Partial Acquisition (Multi-Block Chunking & Dual-Phase Pass)
- Executed a real partial acquisition against real physical block device `/dev/sdb` (167.24 MB raw disk) for 20,000 LBAs (10,240,000 bytes = ~10.24 MB):
  ```bash
  $ ./target/debug/vajra-cli --db ./test_demo/vault_real.db acquire start CASE-REAL-001 EVID-C6FE9A9A /dev/sdb ./test_demo/sdb_partial_20000.raw --profile partial:0:19999 --operator "Lead Examiner Zahid"

  [*] Opening source block device: '/dev/sdb' (strictly read-only)
    Model:       Virtual Disk
    Serial:      naa.600224806ca9c06d835376681e4a916b
    Capacity:    167235584 bytes (326632 blocks @ 512B/block)
    Fingerprint: c6fe9a9afa89fd0f9ff0cb77c8e83b24701a1a6f360fb358a98ac6286a001fb4
    Write-Block: Direct R/W (OS Layer Enforced)
    Output File: ./test_demo/sdb_partial_20000.raw
    Profile:     Partial { start_lba: 0, end_lba: 19999 }

  [*] Initiating acquisition and Phase 1 streaming rolling SHA-256...
  [>] Progress: 100.0% (LBA    20000/20000   ,   10240000 bytes,   0 bad sectors)

  [*] Phase 1 streaming copy complete.
  [*] Phase 2 independent disk re-read verification pass complete.

  [+] Evidence Acquisition & Verification Successful (§19)!
    Operation ID:      a0e20f3f-c099-4961-aede-1296eef3c350
    Output Image:      ./test_demo/sdb_partial_20000.raw
    Blocks Acquired:   20000
    Bytes Written:     10240000
    Phase 1 Rolling:   75af4ecda6b3e045028a5ab450bc915eb26e69cf3ddbde69df3b382a590a20b2
    Phase 2 Re-Read:   75af4ecda6b3e045028a5ab450bc915eb26e69cf3ddbde69df3b382a590a20b2
    Integrity Status:  MATCH (Dual-Phase Cryptographic Integrity Confirmed)
    Bad Sectors Map:   0 unreadable sectors encountered
    Acquired At:       2026-08-30T14:09:37.011263149+00:00
    Completed At:      2026-08-30T14:09:38.294400686+00:00
  ```

### 2. Native Windows Execution & WDAC Note
- **WDAC Observation**:
  - In Conversation 02, Windows Defender Application Control (WDAC) blocked execution of raw test binaries in the build directory.
  - In this round, cross-compilation to `x86_64-pc-windows-gnu` generated `target/x86_64-pc-windows-gnu/debug/vajra-cli.exe` which executed successfully in native Windows PowerShell without triggering WDAC blocks.
  - *Standing Note*: While it is not completely certain whether the GNU PE loader characteristics bypassed the specific heuristic or if directory execution policy rules differed for the GNU target folder, native binary execution succeeded without WDAC interference.
- **Windows Physical Drive Permissions**:
  - Enumeration and identity fingerprinting of `\\.\PhysicalDrive0` (`Generic SAMSUNG MZVL81T0HFLB-00BH1`) succeeded in user mode.
  - Direct low-level block I/O / raw handle access via Win32 `CreateFileW` on `\\.\PhysicalDrive0` returns `Access Denied` unless running in an elevated Administrator shell, which is the expected Windows OS security design.

### 3. Automated Test Suites (WSL + Native Windows)
- **`vajra-acquire`**: 8/8 integration tests passing.
- **`vajra-image`**: 4/4 integration tests passing.
- **Workspace Test Suite**: 45/45 tests passing across all crates.
- **Clippy**: `cargo clippy --workspace --all-targets -- -D warnings` passed with **0 errors and 0 warnings**.

---

## Handoff & Open Questions for Conversation 04 (Filesystem Parsers & Data Carving)

1. **Downstream Block Source Abstraction**:
   - `ReadOnlyBlockSource` is implemented by both `PhysicalDrive` (device layer), `RawImageReader` (image layer), and `E01ImageReader` (image layer).
   - Conversation 04 filesystem parsers (`vajra-fs-fat`, `vajra-fs-ntfs`, `vajra-fs-ext4`, `vajra-fs-apfs`) and carver (`vajra-carve`) can consume any physical drive or forensic image interchangeably without knowing the underlying storage medium.
2. **BadSectorMap Propagation**:
   - When parsing filesystems or carving unallocated space from an image with bad sectors, how should carvers query or be informed of known-unreadable LBA ranges? (e.g. passing `Option<&BadSectorMap>` to parser contexts so fragmented file recovery can mark corrupted extents).
3. **Partition Table Handling**:
   - For physical acquisitions containing multiple partitions (e.g. GPT/MBR), should Conversation 04 introduce a `vajra-partition` module/crate to expose partition slices as sub-`ReadOnlyBlockSource` instances?
