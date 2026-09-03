# Vajra — Backend

**An offline-first digital forensics and secure data sanitization engine, written in Rust.**

Vajra performs two things that most tooling keeps apart: it **recovers** data from storage media with a defensible, itemised confidence score attached to every artifact, and it **destroys** data on storage media with a multi-layer-verified certificate attached to every operation. Both run entirely on the examiner's machine, with no network service in the trust path.

This README documents the **backend** — the Rust workspace, its crates, and the command-line interface over them. A desktop UI (`vajra-tauri-app`) is being developed separately and is outside the scope of this document.

---

## Contents

1. [What Vajra is](#what-vajra-is)
2. [The problem the backend solves](#the-problem-the-backend-solves)
3. [Architecture](#architecture)
4. [Implemented modules](#implemented-modules)
5. [Forensic workflow](#forensic-workflow)
6. [Sanitization workflow](#sanitization-workflow)
7. [Recovery pipeline](#recovery-pipeline)
8. [Supported filesystems](#supported-filesystems)
9. [Supported carving formats](#supported-carving-formats)
10. [Evidence integrity](#evidence-integrity)
11. [Reporting and independent verification](#reporting-and-independent-verification)
12. [Building](#building)
13. [Safe quick start](#safe-quick-start)
14. [Testing](#testing)
15. [Current limitations](#current-limitations)
16. [Roadmap](#roadmap)
17. [Branch status](#branch-status)

---

## What Vajra is

A 20-crate Rust workspace providing an end-to-end forensic and sanitization pipeline:

- **Device layer** — enumerate physical storage, fingerprint it deterministically, read drive health, detect write blockers and boot disks.
- **Acquisition** — copy a device to a forensic image with bad-sector handling, dual-phase hashing and resumable checkpoints.
- **Filesystem recovery** — parse NTFS, ext4 and FAT12/16/32 for deleted entries with a bitmap-verified confidence level.
- **Carving** — a three-tier recovery pipeline with real structural validators for eight file formats.
- **Classification** — a CPU-only, pure-Rust file-type classifier feeding an explainable signal into recovery confidence.
- **Sanitization** — a two-phase confirmation gate, a media-aware decision engine, and five independent verification layers, the last of which re-runs the recovery engine against the wiped device.
- **Evidence integrity** — a hash-chained signed audit log, a validated chain of custody, and a case database with irreversible tombstoning.
- **Reporting** — six signed report types and a standalone verifier that shares no code with the tool that produced them.

Section markers (`§26`, `§35`, …) throughout the source refer to `docs/Vajra_Master_Technical_Document.md`.

---

## The problem the backend solves

Forensic recovery tools and data-destruction tools are usually built by different vendors, tested against different assumptions, and produce output that has to be trusted rather than checked. Three consequences follow, and each maps to a design decision here:

**Recovery output is asserted, not qualified.** A carved file is usually presented as recovered or not. Vajra attaches a six-signal confidence breakdown and a free-text limitations field to every artifact, on the view that the breakdown is more useful to an examiner than the single number derived from it.

**Erasure is claimed, not proven.** A wipe tool typically reports the outcome of the command it issued. Vajra verifies across five independent layers, and the last one is the platform's own recovery engine run against the sanitized device — if the carver finds anything at all, the operation is reported as failed regardless of what the preceding four layers said.

**Evidence handling depends on the tool being honest about itself.** Vajra's audit log is hash-chained and Ed25519-signed, its chain head can be exported as a signed anchor to external media, and `vajra-verify` re-implements every verification check independently so a report can be checked without trusting the code that generated it.

The whole system is offline by design. The one network call anywhere in the backend is an optional RFC 3161 timestamp request that degrades to a local timestamp when unreachable.

---

## Architecture

### The read-only / writable split

`vajra-core` divides block access into two traits: `ReadOnlyBlockSource` and `WritableBlockSource`. This is the load-bearing decision in the codebase. An analysis path that only ever holds a `ReadOnlyBlockSource` cannot write to evidence, and that is enforced by the type system rather than by convention. The corollary is that any new storage backend — an image file, a reconstructed RAID array, an unlocked encrypted volume — becomes usable by the entire analysis stack the moment it implements the trait, with no downstream changes.

`vajra-core` holds no I/O and no platform syscalls. It defines the traits, `MediaType`, `IoError`, `DeviceFingerprint`, `WriteBlockerMetadata`, `SanitizeMethod`, and the shared filesystem types (`RecoverableFileEntry`, `DataLocation`, `MetadataConfidence`, `detect_filesystem`).

### Layering

```
                       vajra-cli
                           │
   ┌───────────────┬───────┴────────┬──────────────────┐
   │               │                │                  │
vajra-acquire  vajra-carve      vajra-erase        vajra-audit
   │           vajra-file-erase  vajra-file-erase   vajra-custody
   │               │                │              vajra-case-db
   │        vajra-fs-{ntfs,ext4,fat}│                  │
   │        vajra-ml                │              vajra-verify
   │               │                │              (independent)
   └──────── vajra-image ───────────┘
                   │
             vajra-device
                   │
              vajra-core   ← traits + domain types, zero I/O
```

`vajra-verify` sits deliberately outside the dependency graph: it does not depend on `vajra-audit` and re-implements every check from scratch.

---

## Implemented modules

| Crate | Responsibility | Status |
|---|---|---|
| `vajra-core` | Block-source traits, domain types, fingerprinting, error model | Implemented |
| `vajra-device` | Device enumeration, health, write-blocker and boot-disk detection | Implemented (Linux + Windows; see [limitations](#current-limitations)) |
| `vajra-acquire` | Device → image acquisition, bad-sector map, checkpoint/resume | Implemented |
| `vajra-image` | RAW/DD read + write, E01 read | Implemented; AFF4 stubbed |
| `vajra-fs-ntfs` | `$MFT` parsing, `$Bitmap` cross-reference, USN records | Implemented |
| `vajra-fs-ext4` | Superblock, group descriptors, inodes, extent trees, dir slack | Implemented |
| `vajra-fs-fat` | FAT12/16/32 chains, LFN, deleted entries | Implemented |
| `vajra-fs-apfs` | APFS | **Stub** |
| `vajra-carve` | Three-tier recovery, signature DB, structural validators, confidence | Implemented |
| `vajra-ml` | Pure-Rust gradient-boosted file-type classifier | Implemented |
| `vajra-erase` | Confirmation gate, decision engine, methods, five-layer verification, certificates | Implemented (see [limitations](#current-limitations)) |
| `vajra-file-erase` | Block-level file erasure, live-file primitive, residual scanner | Implemented (partial) |
| `vajra-audit` | Hash-chained signed audit log, anchoring, six report types | Implemented |
| `vajra-custody` | Chain-of-custody event state machine | Implemented |
| `vajra-case-db` | Case / evidence / operation / artifact store with tombstoning | Implemented |
| `vajra-verify` | Independent standalone report verifier | Implemented |
| `vajra-cli` | Command-line front end over every crate above | Implemented |
| `vajra-raid` | RAID 0/5/6 reconstruction | Stub on `main`; implemented on a branch |
| `vajra-crypto-vol` | Encrypted volume unlock | Stub on `main`; partially implemented on a branch |
| `vajra-tauri-app` | Desktop UI shell | Developed separately; out of scope here |

---

## Forensic workflow

```
vajra-cli list                      # enumerate devices
vajra-cli fingerprint <device>      # deterministic SHA-256 identity
vajra-cli health <device>           # SMART / NVMe health
vajra-cli case create ...           # open a case in the evidence database
vajra-cli evidence add ...          # register the item, opening its custody chain
vajra-cli acquire start ...         # image the device, checkpointed and hashed
vajra-cli image inspect <image>     # confirm format and stored hashes
vajra-cli fs detect|list|dump ...   # filesystem-level recovery
vajra-cli carve run|inspect|stats   # three-tier carving
vajra-cli ml classify <file>        # classifier output with feature attribution
vajra-cli report generate ...       # signed report
vajra-verify <report.vjr>           # independent verification
```

**Acquisition detail.** Three profiles — physical (full LBA range), partial (explicit LBA bounds) and logical (bounded range with a description). Bad sectors follow a retry → reduce-block-size → mark-unreadable path: the chunk is retried with linear backoff, then recursively subdivided down to single-sector reads, and a sector that still fails is recorded in an authoritative `BadSectorMap` and filled with a non-ambiguous `VAJRA_BAD_SECTOR` placeholder so unreadable regions can never be mistaken for zeroed data. Hashing is dual-phase on a fresh acquisition: a rolling SHA-256 during the copy, then an independent re-read of the finished image compared against it. Checkpoints are written every 10,000 blocks by default, and a resume validates the stored device fingerprint before continuing.

---

## Sanitization workflow

Every destructive operation requires a `SanitizationAuthorizationToken`, and the only way to obtain one is to complete a two-phase gate.

```
begin(device, operator, typed_serial, confirm)
    ├── rejects system disks outright
    ├── rejects write-blocked devices outright
    ├── requires an exact serial-number match
    └── → PendingSanitization
finalize(pre_exec_confirm)            # consumes the pending gate by value — single use
    └── → SanitizationAuthorizationToken
```

**Decision engine.** Given a device descriptor and the methods its controller supports, the engine recommends: cryptographic erase for self-encrypting drives, NVMe Sanitize or Format for NVMe, ATA (Enhanced) Secure Erase for SATA SSDs, overwrite for HDDs, and — for flash media whose controller offers no sanitize command — host-level overwrite accompanied by an explicit residual-risk warning.

**Execution.** Host overwrite is implemented and functional: ChaCha20-seeded patterns from OS entropy, zero / ones / random passes, chunked writes through `WritableBlockSource`. Controller-level commands (ATA Secure Erase, NVMe Sanitize/Format, SCSI Sanitize, crypto erase) are modelled end-to-end and simulated against the mock device, but the underlying ioctl transport is not yet implemented — see [limitations](#current-limitations).

**Five-layer verification.**

| Layer | Check |
|---|---|
| 1 | Command status — did the issued operation report success |
| 2 | Device status — post-operation readiness of the block source |
| 3 | Deterministic sampling — read specified LBAs and check byte uniformity |
| 4 | Statistical sampling — hypergeometric sample-size calculation, ChaCha20-seeded random LBA selection, per-sector uniformity |
| 5 | **Independent recovery scan** — re-runs the real `vajra-carve` pipeline (Tier 2 + Tier 3) against the sanitized device |

Layer 5 is an **override**: if the carver recovers any artifact whatsoever, overall assurance is forced to `Failed` regardless of layers 1–4.

**Certificates.** Each carries the certificate ID, device details and fingerprint, method, standard reference, timestamps, per-layer results, overall assurance, operator ID, a SHA-256 of the certificate body, and an Ed25519 signature. Assurance is **structurally capped at Medium** — never High — whenever the media is NVMe, SATA SSD, USB or SD card and the method used was a host-level overwrite, because flash translation layers and over-provisioning mean the host cannot address every physical cell. That cap is code, not policy documentation.

**File-level erasure** (`vajra-file-erase`) covers two paths: a block-level pipeline that overwrites a file's data extents and zeroes its metadata record on an unmounted image or device, and a live-OS-file primitive that performs a multi-pass overwrite with `sync_all()` between passes, truncates, and unlinks. A five-state residual artifact scanner classifies the result as `Sanitized`, `ResidualTracesDetected`, `PartiallySanitized`, `UnableToVerify` or `NotApplicable`.

---

## Recovery pipeline

Three tiers run in precedence order; each records the sectors it resolves in a shared `AllocatedBlockMap` so later tiers never re-examine claimed regions.

**Tier 1 — filesystem metadata.** Delegates to the `vajra-fs-*` parsers. Yields the original path and filename, which no signature-based approach can recover. Only `Confirmed` and `Partial` confidence entries claim sectors.

**Tier 2 — signature and structural validation.** Sector-aligned scan for signature headers from `config/signatures.json`, then dispatch to a structural validator implementing Garfinkel's fast-object-validation framework (DFRWS 2007): each validator returns `V_OK`, `V_ERR` or `V_EOF`, and declares three per-format flags — `err_is_prefix`, `appended_data_ignored`, `no_zblocks` — that govern how aggressively the carver may prune. These are genuine structural validators. The OLE2 validator walks the FAT/DIFAT/MiniFAT sector chains of the compound-file structure and derives an exact object length from the allocation table; the ISO-BMFF validator walks the box tree and distinguishes a truncated object from a malformed one from an exhausted buffer, because conflating them is how a partial recording gets carved and labelled complete.

**Tier 3 — bifragment gap carving.** For two-fragment files, a bounded split-point × gap-size search using the empirically-derived gap order (8, 16, 32, 4, 64, 24, 40, 128, 256, 512, 1024, 2048 sectors) before falling back to linear scan, with `err_is_prefix` early rejection. Full fragment provenance is retained: source LBAs for both fragments and the gap between them.

**Confidence model.** Every `RecoveredArtifact` carries a six-signal breakdown with named constant weights summing to 1.0:

| Signal | Weight |
|---|---|
| Structural validity | 0.25 |
| Header/footer integrity | 0.20 |
| Metadata cross-reference | 0.20 |
| Entropy consistency | 0.15 |
| Fragmentation confidence | 0.15 |
| Overwrite probability | 0.05 |

These are declared in the source as baseline weights pending empirical calibration against labelled corpora, and should be read that way.

**Classification signal.** `vajra-ml` implements the `EntropyAnalyzer` trait as a swap-in for the heuristic analyzer. It is a gradient-boosted tree ensemble (60 estimators, depth 4) trained offline in Python and re-implemented natively in Rust over an exported JSON tree dump — no ONNX runtime, no C++ dependency, CPU-only. Features are a 280-dimensional vector: a 256-bin byte histogram, a 16-chunk Shannon entropy profile, six bigram statistics, a printable-ASCII run ratio and a chi-square uniformity statistic. A train/serve parity test checks the Python and Rust feature extractors agree numerically.

---

## Supported filesystems

| Filesystem | What is parsed |
|---|---|
| **NTFS** | `$MFT` with update-sequence-array fixups; `$STANDARD_INFORMATION`, `$FILE_NAME` and `$DATA` attributes, resident and non-resident, with signed-delta run-list decoding; `$Bitmap` from MFT record 6 used to grade deleted-file confidence; USN record parsing; a bounded scan of unallocated clusters for orphaned `FILE` records, which is what makes quick-format recovery work |
| **ext4** | Superblock (magic `0xEF53`); 32-bit and 64-bit group descriptors; inodes; recursive extent-tree walk (`0xF30A`, depth-bounded); recursive directory tree walk from inode 2 with true path reconstruction; **directory-entry slack recovery** — scanning the expanded `rec_len` left behind by `unlink` to recover entries no longer reachable; a full inode-table sweep for orphaned inodes; block-bitmap cross-reference for confidence |
| **FAT12 / 16 / 32** | BPB and FAT-type derivation; FAT12/16/32 chain walking with correct EOF and bad-cluster sentinels; long-filename reconstruction including the reverse-order chunk correction for deleted entries; `0xE5` deleted-entry recovery with 8.3 reconstruction; where the FAT chain has been zeroed, a contiguous-run reconstruction from the start cluster, graded down in confidence when any assumed cluster is not free; bounded unallocated-cluster scan for orphaned directory fragments |

`MetadataConfidence` in all three is derived the same way: `Confirmed` when every resolved cluster or block is still marked free in the allocation bitmap, `Partial` when only some are, `Low` otherwise. Recovery is never reported as certain because a metadata record survived.

---

## Supported carving formats

Signatures live in `config/signatures.json` and are read at runtime, so a new format can be registered without recompiling. Each entry declares a header byte pattern, an optional footer, a maximum size, the validator to dispatch to, and an optional `header_offset` for formats whose magic does not begin at byte 0.

| Format | Validator does |
|---|---|
| **JPEG** | SOI/EOI framing and segment-marker walk |
| **PNG** | Chunk walk with per-chunk CRC verification through `IEND` |
| **PDF** | Header/`%%EOF` framing and object-structure checks |
| **ZIP** | Local file headers and end-of-central-directory; also covers DOCX, XLSX and PPTX |
| **SQLite** | Header field validation and page-structure consistency |
| **OLE2 / CFB** | Compound File Binary header field validation, FAT/DIFAT/MiniFAT sector-chain consistency, exact object length derived from the allocation table. Covers legacy DOC/XLS/PPT |
| **MP4 / ISO-BMFF** | Box-tree walk with strict bounds checking: 32-bit sizes, 64-bit extended sizes (`size == 1`), to-EOF boxes (`size == 0`), and `ftyp` / `moov` / `mdat` / `moof` / `free` / `skip` / `wide` handling. A complete object requires a valid `ftyp` plus at least one media box. A second top-level `ftyp` ends the object, so adjacent files are not swallowed as one |

**MP4 detection detail.** An ISO-BMFF file does not begin with its magic — bytes 0–4 are the first box's size, and the literal `ftyp` tag starts at byte 4. Detection therefore uses `header = "ftyp"` with `header_offset = 4`. The offset mechanism is optional and backward-compatible: every pre-existing signature omits the field and continues to match at byte 0 exactly as before. Modern QuickTime/MOV files that carry an ISO-BMFF-style `ftyp` are accepted by the same validator; this is not universal MOV support, and older QuickTime layouts without `ftyp` are not detected.

---

## Evidence integrity

**Audit log.** Each entry's hash is `SHA-256(canonical_json(payload) ‖ "||" ‖ prev_hash)` over `{seq, timestamp, operator_id, case_id, operation, target_descriptor, result}`. Verification independently checks sequence monotonicity, backward hash linkage, genesis linkage and per-entry payload integrity. Entries are Ed25519-signed.

**External anchoring.** The chain head can be exported as a signed anchor record — `VAJRA_ANCHOR_V1:{case}:{seq}:{hash}:{ts}:{operator}` — to be placed on external or write-once media. Re-verification checks both the anchor signature and that the anchored `(seq, hash)` still matches the live chain, which detects a truncated or regenerated log even when the regenerated log is internally self-consistent. The anchor file is written locally; placing it on trustworthy media is the operator's procedure, not the tool's.

**Chain of custody.** Ten event types (`Seized`, `Received`, `StorageChange`, `Transferred`, `WriteBlockerAttached`, `AnalysisStarted`, `AnalysisCompleted`, `WorkingCopyCreated`, `Returned`, `Disposed`) validated by a state machine: the first event must be `Seized` or `Received`; nothing may follow a terminal state; a `Transferred` event requires both parties; timestamps must be monotonically non-decreasing. The crate is explicit in its own output that it records operator-reported events and checks internal consistency — it does not verify physical transfers occurring outside the application boundary.

**Case database.** Nine tables covering cases, evidence items, forensic images, operations, recovered artifacts, sanitization events, custody events, the audit log and reports. Case status is two-state only, Active → Closed, and irreversibility is enforced twice: at the application layer and by a `BEFORE UPDATE` database trigger. A second trigger unconditionally aborts any `DELETE` against a case row. Passphrase-derived key material uses Argon2id (64 MB, 3 iterations) with zeroize-on-drop.

**Device fingerprinting.** SHA-256 over length-prefixed normalised serial, length-prefixed normalised model, capacity as little-endian `u64`, and a 512-byte boundary sample. The interface string is deliberately excluded so a drive fingerprints identically whether attached directly or through a USB bridge — there is a test asserting exactly that.

---

## Reporting and independent verification

Six report types: `ForensicExamination`, `SanitizationCertificate`, `AcquisitionReport`, `RecoveryReport`, `DeviceHealthReport`, `ChainOfCustodyReport`. Each pulls real data from the crates above and goes through a shared pipeline: canonical JSON, SHA-256 digest, optional RFC 3161 timestamp, Ed25519 signature, self-signed certificate, an audit-chain entry recording the generation, and a persisted `.vjr` envelope. When the timestamp authority is unreachable the report is still produced, marked as locally timestamped.

`vajra-verify` is a separate binary with **no dependency on `vajra-audit`** — its data structures and every check are re-implemented, so a report can be verified without trusting the code that wrote it. It checks the content hash, extracts the Ed25519 public key from the embedded certificate, verifies the signature, independently recomputes the whole audit hash chain including sequence-gap and linkage checks, checks the timestamp label, and optionally re-hashes external evidence files against the manifest. It is exercised against several distinct tamper scenarios in `tests/tamper_tests.rs`.

---

## Building

Requires a Rust toolchain; verified against `rustc` / `cargo` 1.95.0, edition 2021.

```bash
git clone <repository-url>
cd vajra
cargo build --release
cargo run -p vajra-cli -- help
```

`rusqlite` is built with the `bundled` feature, so SQLite is compiled from source and no system SQLite is required. There is no C++ toolchain requirement and no ML runtime to install — the classifier is pure Rust.

---

## Safe quick start

This sequence touches no physical device. It creates a case, generates a synthetic disk image, carves it, and verifies a signed report.

```bash
# 0. Clean scratch directory
mkdir -p /tmp/vajra-demo && cd /tmp/vajra-demo

# 1. Generate a synthetic carving corpus (from the repository root)
python3 scripts/generate_carve_corpus.py

# 2. Open a case
vajra-cli case create --name "DEMO-001" --examiner "analyst" --db /tmp/vajra-demo/case.db

# 3. Inspect the synthetic image
vajra-cli image inspect test_data/carve_test.img
vajra-cli fs detect test_data/carve_test.img

# 4. Run the recovery pipeline
vajra-cli carve run --image test_data/carve_test.img --out /tmp/vajra-demo/recovered
vajra-cli carve stats --image test_data/carve_test.img

# 5. Generate and independently verify a signed report
vajra-cli report generate --db /tmp/vajra-demo/case.db --case-id <id> --type recovery
vajra-verify /tmp/vajra-demo/<report-id>.vjr
```

Two standing rules the project holds itself to, and which the quick start reflects:

- **No destructive operation is ever run against real hardware.** Sanitization is exercised exclusively against mock and simulated devices.
- **Reported numbers are measured, not estimated.** Benchmark figures come from actual runs against the seeded corpora produced by `scripts/`, and are regenerable by anyone with the repository.

`vajra-cli help` output currently lags the dispatch table in some places; `crates/vajra-cli/src/main.rs` is authoritative. `docs/user-manual.md` documents each command with real captured output.

---

## Testing

Roughly 95 `#[test]` functions across the workspace, plus integration suites in each crate's `tests/` directory.

| Area | Coverage |
|---|---|
| Carving | 35 unit tests + 2 integration tests in `vajra-carve`, covering each validator against intact, truncated, corrupted and wrong-signature inputs, plus a full pipeline run against the synthetic corpus |
| Sanitization | Gate semantics including system-disk and serial-mismatch rejection; dedicated Layer-5 tests proving the recovery-scan override actually fires |
| Acquisition | Clean round-trip with hash verification, partial ranges, the bad-sector flowchart, transient-failure recovery with backoff, block-size reduction, interrupted-acquisition resume, and resume rejection on device-fingerprint mismatch |
| Filesystems | NTFS fixup application and data-run decoding; ext4 superblock parsing and directory-slack recovery; FAT LFN reconstruction and deleted-entry recovery |
| Verification | Independent verifier run against multiple distinct tamper scenarios |
| ML | Classifier behaviour, pipeline integration, and a Python↔Rust feature-extraction parity test |

Ground-truth fixtures are generated by `scripts/generate_ground_truth_images.py` (NTFS/ext4/FAT images with known deleted files) and `scripts/generate_carve_corpus.py` (intact, truncated, corrupted and genuinely two-fragmented files). Every scenario is reproducible from a documented script, so reported metrics can be regenerated independently.

The classifier's measured figures — macro precision 0.9964, recall 0.9963, F1 0.9963 — are from a 540-sample test set drawn from a **synthetically generated** corpus across six classes (`jpeg`, `png`, `pdf`, `zip`, `sqlite`, `unknown`). They characterise the model on that corpus and should not be read as performance on real-world forensic media.

---

## Current limitations

Stated plainly, because a forensic tool that overstates itself is worse than one that does less.

**Device layer**

- SMART and NVMe health parsing is implemented on Windows only. The Linux path returns a nominal placeholder and does not query the drive.
- HPA/DCO detection is modelled as a data structure but no detection logic exists on either platform.
- Write-blocker detection currently fires on vendor/model string matching and the OS read-only flag. The VID/PID table is present but neither OS backend extracts a USB VID/PID to feed it, so that path is inactive. SCSI Mode-Sense and manual-override detection methods are declared but not implemented.
- macOS is not supported on `main`; unsupported targets return `UnsupportedOperation` rather than silently degrading.

**Acquisition and imaging**

- The independent re-read verification pass runs on a fresh acquisition but not on a resumed one, where a single hash is recorded for both values.
- E01 is read-only; there is no E01 writer. AFF4 is a stub that returns `UnsupportedFormat`.
- The logical acquisition profile is currently a bounded LBA range with a description, not filesystem-aware extraction.

**Case database**

- **The case database is not encrypted at rest in the current build.** `rusqlite` is built with `bundled`, not `bundled-sqlcipher`, so the `PRAGMA key` issued at open is a no-op against vanilla SQLite. The Argon2id key derivation and zeroizing key material are real and in place; activating encryption requires switching the feature and re-testing. Do not treat the current database file as protected.

**Filesystems**

- NTFS `$LogFile` is not parsed. VSS handling is a filename/GUID heuristic, not shadow-copy store parsing. Directory hierarchy is not reconstructed from `$INDEX_ROOT`/`$INDEX_ALLOCATION`, so recovered paths are flat rather than nested.
- ext4 legacy (non-extent) inodes resolve only the 12 direct block pointers; single, double and triple indirect blocks are not walked, so large non-extent files resolve incompletely. jbd2 journal parsing exists but is not wired into the enumeration path.
- exFAT is not supported. APFS is a stub.

**Carving**

- The Tier-2 candidate window is capped at 2048 sectors (1 MiB). Objects larger than that are validated only within the window, which materially limits recovery of large real-world MP4 files.
- `moov` reconstruction from an intact `mdat` is **not** implemented. An interrupted recording missing its index is currently not recoverable, and the validator reports that honestly rather than emitting a partial object as complete.
- Tier 2 accepts only `V_OK`; validators correctly return `V_EOF` with a partial length for truncated candidates, but the pipeline does not currently surface those as partial recoveries.
- `header_footer_integrity` and `structural_validity` are set to 1.0 at construction rather than computed per candidate, so 45% of the composite confidence weight is presently constant. The weights themselves are declared baseline values pending calibration.

**Sanitization**

- Host-level overwrite is fully implemented and functional. **Controller-level commands — ATA Secure Erase, ATA Enhanced Secure Erase, NVMe Sanitize, NVMe Format, SCSI Sanitize and cryptographic erase — are not yet issued to real hardware**; the ioctl transport is unimplemented and these methods return `UnsupportedOperation` on a real device. They are fully simulated against the mock device and are what the test suite exercises. This means the decision engine can currently recommend a method the execution layer cannot perform on real media, and that gap must be closed before any real-hardware use.
- The authorization token is a compile-time capability marker. It derives `Deserialize`, so it is constructible by deserialization outside the gate, and consuming functions do not currently re-check it against the device being written. Treat the gate as a strong workflow control, not a cryptographic authorization.
- Verification Layer 2 currently checks that the block source is responsive rather than querying an NVMe Sanitize Status log page or ATA IDENTIFY word 128.
- In `vajra-file-erase`, the journal-scrubbing and free-after-overwrite verification steps report success without performing the check. The residual scanner is a classifier over inputs supplied by the caller, not an independent re-scan.

**Reporting**

- Reports are produced as signed JSON envelopes with Markdown bodies. **No PDF is generated**, despite a schema column existing for one.
- RFC 3161 responses are accepted on HTTP 200 without parsing the PKIStatus field.
- Certificates are self-signed; there is no CA chain issuance or external PKI integration. `vajra-verify` locates the Ed25519 key inside the certificate by structural search and does not perform chain, expiry or trust validation.

Vajra makes no compliance certification claim. `docs/standards-mapping.md` records how implemented features relate to NIST SP 800-88 Rev.2, IEEE 2883, ISO/IEC 27037, ISO/IEC 27001, the Information Technology Act 2000, the CERT-In Directions of 28 April 2022 and the DPDP Act 2023 — as an engineering record of what the code does, alongside a register of blueprint claims the code does not yet support.

---

## Roadmap

Unfinished backend capabilities, in rough order of value to the platform:

- **Controller-level sanitize transport** — implement the ATA/NVMe/SCSI ioctl paths so the methods the decision engine recommends for SSD, NVMe and SED media can actually be executed and verified on real hardware. This is the highest-priority gap.
- **RAID reconstruction** — RAID 0/5/6 including degraded-mode reconstruction, exposed as a `ReadOnlyBlockSource`. Implemented on a branch, not yet on `main`.
- **Encrypted volume support** — LUKS, BitLocker and FileVault unlock given credentials the operator already lawfully holds. Partially implemented on a branch; see [branch status](#branch-status).
- **MP4 `moov` reconstruction** — rebuild a minimal index from `mdat` structure to recover interrupted recordings, together with a validator output interface that can represent a reconstructed object honestly rather than reporting it as an ordinary complete file.
- **Large-object carving** — raise or stream past the 1 MiB Tier-2 candidate window so large MP4 and other media files can be validated in full.
- **Partial-recovery surfacing** — carry `V_EOF` results through Tier 2 as partial artifacts with their `partial_length`, instead of discarding them.
- **Confidence calibration** — bucket predicted confidence into deciles against ground truth, measure calibration error, and replace the baseline weights with empirically-derived ones. Compute the header/footer and structural signals per candidate rather than as constants.
- **Expanded benchmarking** — scale the ground-truth matrix across scenarios (quick format, partial overwrite, fragmentation, bad sectors, colliding signatures, large and small files, nested directories) crossed against all three filesystems and all eight carving formats, and re-measure precision, recall, F1, byte-level accuracy and false-positive rate at that scale.
- **APFS** — object map and snapshot parsing.
- **Deeper exFAT** — currently unsupported.
- **AFF4** — image format read support.
- **N-fragment carving** — Tier 3 currently handles the two-fragment case.
- **Database encryption at rest** — switch to a SQLCipher-backed build and add tests that verify the on-disk file is genuinely unreadable without the key.
- **Linux health parsing** — real SMART/NVMe log-page queries, plus HPA/DCO detection on both platforms.
- **Broader hardware validation** — testing across more controllers, interfaces and media types than the current set.
- **Filesystem depth** — NTFS `$LogFile` parsing, index-based directory hierarchy reconstruction, real VSS store parsing, and ext4 indirect-block traversal.

---

## Branch status

The project is **pre-merge**. `main` is the shared baseline and contains everything described above except where noted. The following backend work exists on individual branches and is not yet on `main`.

**`vaibhavi` — additional carving formats** *(commits `1c40ab4`, `a20d186`, `b7cb1d7`, `5c65e29`, `f82af35`)*

- OLE2/CFB structural validator for legacy DOC/XLS/PPT containers, with a low-entropy profile registered in the entropy analyzer.
- Optional, backward-compatible `header_offset` in the signature database. Existing formats continue to match at byte 0; MP4 uses byte 4.
- MP4/ISO-BMFF structural validator with 32-bit and 64-bit box sizes and `ftyp`/`moov`/`mdat` handling.
- `docs/standards-mapping.md` and `docs/user-manual.md`.
- Verified on this branch: **35 unit tests and 2 integration tests in `vajra-carve`, 0 failures**.

**`syed-zahid` — advanced storage**

- **`vajra-raid`** — RAID 0, 5 and 6 with a genuine GF(2⁸) Reed–Solomon implementation, exposed as a `ReadOnlyBlockSource`. Array detection reads **mdadm superblocks only**; other RAID metadata formats are not parsed. 4 integration tests.
- **`vajra-crypto-vol`** — **LUKS1 and LUKS2 unlock are real** (PBKDF2 / Argon2id, AES-XTS, AF-split/merge). **BitLocker support parses a project-defined layout rather than the Microsoft FVE on-disk format** and will not open a real BitLocker volume. **FileVault is detection-only** — the unlock path returns `NotSupported` in all cases. 5 tests, one of which no-ops because its fixture directory is absent from the branch.
- **macOS device support** — implemented by invoking `diskutil` and `smartctl` as subprocesses. Two agent-log entries on this branch describe an IOKit-based implementation and an `AlignedBuffer` type; **neither is present in the source**, and the logs should be corrected before anyone relies on them.
- New CLI commands `raid detect`, `raid mount`, `crypto-vol unlock`; 2 CLI storage tests.
- One additive change to `vajra-core`: a blanket `impl<T: ?Sized + ReadOnlyBlockSource> ReadOnlyBlockSource for Box<T>`. Non-breaking.

**Conflicts to resolve before merge**

1. **`crates/vajra-cli/tests/ground_truth_test.rs` is weakened on one branch.** Four hard `assert!(img_path.exists(), …)` fixture checks are replaced with early `return`s that print a skip message, so the FAT32, ext4, NTFS and NTFS-quick-format recovery tests report as passing whether or not the ground-truth images exist and without exercising any recovery logic. `main`'s version should be kept unless the team explicitly decides otherwise.
2. **Two branches independently rewrite `crates/vajra-tauri-app`** on incompatible foundations. That is a UI-layer decision and is outside this document's scope; it does not affect any backend crate.

No other branch modifies a backend crate that another branch also modifies.

---

## License

Apache-2.0, as declared in the workspace manifest. A `LICENSE` file has not yet been added to the repository.

---

## Legal scope

Vajra is intended for use by authorized examiners on media they are lawfully entitled to examine or destroy. Encrypted volume support unlocks a volume using credentials the operator already lawfully holds; the project implements no bypass, no key recovery and no cryptanalytic attack, and that is a design boundary rather than a limitation to be lifted later. Network-attached RAID is out of scope; local, directly-attached member drives only.
