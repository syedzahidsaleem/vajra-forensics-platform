# Integrated Secure Data Erasure & Advanced File Recovery Platform
## Complete Technical Blueprint

**Codename suggestion:** *Vajra* (Sanskrit: indestructible/thunderbolt — evokes both "unrecoverable erasure" and "cuts through corruption to recover data"). Rename freely.

**Scope commitments locked in:**
- Platforms: Windows, Linux, macOS — all three fully production-grade
- Core engines: Rust (workspace, multi-crate)
- UI: Tauri + React
- Deployment: Installed desktop app, single-investigator standalone
- Encrypted volumes: Full decrypt-and-process support (BitLocker, FileVault, LUKS)
- RAID (0/5/6) + network share (SMB/NFS) support: In scope
- Reports: Court-admissible — hash-chained audit log + X.509/PKI digital signing
- Compliance emphasis: NIST 800-88 + DoD 5220.22-M, with India-specific (IT Act 2000, CERT-In, DPDP Act 2023) as primary framing
- ML: CPU-only, lightweight, explainable models (no GPU dependency)
- Training data: Public forensic corpora + synthetic generation

---

## 1. System Architecture

### 1.1 High-level component diagram

```
┌──────────────────────────────────────────────────────────────────┐
│  Tauri + React UI (Case Dashboard, Wizards, Live Progress, Report │
│  Viewer, Recovered-File Browser)                                  │
├──────────────────────────────────────────────────────────────────┤
│  Tauri IPC Bridge (Rust <-> JS, typed commands, async event bus)  │
├──────────────────────────────────────────────────────────────────┤
│  Orchestration Layer (job scheduler, cancellation tokens,         │
│  progress streaming, crash-safe checkpointing)                    │
├───────────────┬───────────────┬──────────────┬───────────────────┤
│ Erasure Engine │ File/Folder   │ Carving &    │ ML Inference       │
│ (drive-level)  │ Eraser Engine │ Recovery     │ Layer              │
│                │               │ Engine       │ (classification,   │
│                │               │              │ fragment scoring,  │
│                │               │              │ confidence model)  │
├───────────────┴───────────────┴──────────────┴───────────────────┤
│  Device & Storage Abstraction Layer                               │
│  - ATA/SCSI/NVMe raw command interface                            │
│  - RAID reconstruction (software RAID 0/5/6 parity math)          │
│  - Network share mounting (SMB/CIFS, NFS)                         │
│  - Encrypted volume unlock (BitLocker/FileVault/LUKS)             │
│  - Filesystem parsers (NTFS, ext4, APFS, FAT32/exFAT, Btrfs*)     │
├──────────────────────────────────────────────────────────────────┤
│  Cryptographic Audit & Chain-of-Custody Engine                    │
│  - Append-only hash-chained event log (SHA-256)                   │
│  - X.509 certificate management + report signing                 │
│  - Report generation (PDF/JSON/XML)                               │
├──────────────────────────────────────────────────────────────────┤
│  Case Management Store (SQLite, encrypted at rest via SQLCipher)  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Why this layering

The Device & Storage Abstraction Layer is the load-bearing wall of the whole system. Every module above it (erasure, file deletion, carving, ML) operates on a **common `BlockSource` trait** rather than talking to hardware directly:

```rust
trait BlockSource {
    fn read_blocks(&mut self, lba: u64, count: u32) -> Result<Vec<u8>, IoError>;
    fn write_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), IoError>;
    fn total_blocks(&self) -> u64;
    fn block_size(&self) -> u32;
    fn supports_secure_erase(&self) -> bool;
    fn issue_secure_erase(&mut self) -> Result<(), IoError>;
    fn media_type(&self) -> MediaType; // HDD, SATA_SSD, NVMe, SED, USB, SDCard
}
```

Concrete implementations: `PhysicalDrive`, `RaidArray` (composes N `PhysicalDrive`s + parity logic and exposes itself as a single virtual `BlockSource`), `NetworkShare`, `EncryptedVolume` (wraps an inner `BlockSource`, transparently decrypts). This means your carving engine and eraser engine **don't care** whether they're operating on a raw USB stick, a reconstructed RAID-5 array, or a decrypted BitLocker volume — same code path. This is the single most important architectural decision in the whole system; get this trait right early and everything else composes cleanly.

### 1.3 Rust workspace layout

```
vajra/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── vajra-core/                  # BlockSource trait, shared types, error handling
│   ├── vajra-device/                # ATA/NVMe/SCSI raw I/O, per-OS device enumeration
│   ├── vajra-raid/                  # RAID 0/5/6 reconstruction logic
│   ├── vajra-network/               # SMB/NFS share mounting & block access
│   ├── vajra-crypto-vol/            # BitLocker/FileVault/LUKS unlock
│   ├── vajra-fs-ntfs/                # NTFS parser (MFT, $LogFile, $UsnJrnl, VSS)
│   ├── vajra-fs-ext4/                # ext4 parser (inodes, extents, journal)
│   ├── vajra-fs-apfs/                # APFS parser (object maps, snapshots)
│   ├── vajra-fs-fat/                 # FAT32/exFAT parser
│   ├── vajra-erase/                  # Drive eraser: NIST 800-88, DoD 5220.22-M, crypto-erase
│   ├── vajra-file-erase/             # Secure file/folder deletion per FS
│   ├── vajra-carve/                  # Signature + structure-based carving, BGC fragment reassembly
│   ├── vajra-ml/                     # ML inference (classification, fragmentation, confidence)
│   ├── vajra-ml-train/               # Offline training pipeline (not shipped in app)
│   ├── vajra-audit/                  # Hash-chained logging, X.509 signing, report generation
│   ├── vajra-case-db/                # SQLite/SQLCipher case management
│   └── vajra-tauri-app/              # Tauri app shell, IPC commands
├── ui/                               # React frontend
├── ml-models/                        # Trained model artifacts (ONNX/LightGBM format)
├── test-corpus/                      # Synthetic + public test files
└── docs/
    ├── standards-mapping.md
    ├── validation-report.md
    └── user-manual.md
```

This structure lets an agentic coding tool (Antigravity) work on one crate at a time with a clear contract (the trait interfaces), which is exactly how you want to parallelize a build of this scope — each crate can be developed and unit-tested in near-isolation against mock `BlockSource` implementations before wiring into the real device layer.

---

## 2. Module 1 — Secure Drive Eraser (`vajra-erase`)

### 2.1 Media detection & routing logic

```
detect_media(device) -> MediaType:
    1. Query via IDENTIFY DEVICE (ATA) or Identify Controller/Namespace (NVMe)
    2. Check rotation rate field (0x0001 = SSD, non-zero = HDD RPM) [ATA word 217]
    3. Check TRIM support (ATA word 169) and DEVICE SLEEP / NVMe Dataset Management support
    4. Check Security feature set support (ATA word 128) -> SECURITY ERASE capable?
    5. Check TCG Opal support via Level 0 Discovery (SED detection)
    6. Check for HPA (compare word 61:60 native max vs word 103:100 accessible max) and DCO
    7. Route to appropriate EraseStrategy
```

### 2.2 Erase strategy matrix (implement all, auto-select + allow override)

| Strategy | Applies to | Method |
|---|---|---|
| `OverwriteNist800_88_Clear` | HDD, USB, SD | Single-pass pseudorandom overwrite (CSPRNG-seeded, ChaCha20-based for speed) across full addressable LBA range including HPA/DCO after unlocking |
| `OverwriteDod522022M` | HDD (legacy compliance mode) | 3-pass: 0x00, 0xFF, random, each followed by read-verify |
| `AtaSecureEraseUnit` | SATA SSD supporting Security feature set | Issue `SECURITY ERASE PREPARE` then `SECURITY ERASE UNIT` (enhanced mode if supported — enhanced erase writes vendor-defined pattern to all cells including reallocated ones) |
| `NvmeSanitize` | NVMe SSD | `Sanitize` command with `SANACT` = Block Erase or Overwrite; poll `Sanitize Status` log page until complete; fallback to `Format NVM` with `SES=1` if Sanitize unsupported |
| `CryptographicErase` | Self-Encrypting Drives (TCG Opal 2.0) | `PSID Revert` or `Admin SP Revert` — destroys/regenerates Media Encryption Key. Sub-second operation, cryptographically irreversible regardless of NAND wear-leveling state |
| `RaidArrayErase` | Software/hardware RAID sets | Decompose to member drives via `vajra-raid`, apply appropriate per-drive strategy to **every member drive independently** (parity data must also be destroyed — a common oversight; wiping only data drives and leaving parity drives intact can allow partial reconstruction) |
| `LegacyGutmann35Pass` | Opt-in only, flagged as legacy/unnecessary on modern media in UI tooltip | 35-pass per original Gutmann spec, offered purely for compliance-checkbox scenarios |

### 2.3 HPA/DCO handling (frequently missed by other tools — build this properly)

```
1. IDENTIFY DEVICE -> read native max address (word 61:60) vs current max (word 103:100)
2. If native > current -> HPA present
   -> issue SET MAX ADDRESS (unlock, volatile or non-volatile per user choice)
3. Check DCO via DEVICE CONFIGURATION IDENTIFY
   -> if real max capacity > HPA-adjusted max -> DCO present
   -> issue DEVICE CONFIGURATION SET to restore, or DEVICE CONFIGURATION RESTORE
4. Wipe the FULL native LBA range
5. Log explicitly in report: "HPA detected: Y/N, size X sectors, unlocked and wiped: Y/N"
   -> this single log line is what proves due diligence in an audit
```

### 2.4 Verification (statistical sampling engine)

```rust
fn compute_sample_plan(total_sectors: u64, confidence: f64, defect_rate: f64) -> SamplePlan {
    // Hypergeometric-corrected sample size for finite population
    let n = required_sample_size(total_sectors, confidence, defect_rate);
    SamplePlan {
        random_sample: uniform_random_sectors(n),
        mandatory_sample: smart_flagged_reallocated_sectors()
            .chain(hpa_dco_full_range())
            .chain(partition_boundary_sectors()),
    }
}
```

Default: 99.9% confidence, 0.01% assumed max defect rate → this typically yields a sample in the low single-digit percent range for multi-TB drives, keeping verification time reasonable while remaining statistically defensible. **State the exact formula and parameters in every generated report** — this is what makes "verified" a real claim rather than marketing copy.

### 2.5 Crash-safety / resumability

Every erase job writes a checkpoint record (`last_verified_lba`, `pattern_used`, `pass_number`) to the case DB every N sectors (tunable, e.g. every 1% of drive). On restart after crash/power loss, the job resumes from last checkpoint and **re-verifies a buffer zone** (e.g., 10MB before the checkpoint) rather than trusting the last write blindly, since the crash may have occurred mid-write.

---

## 3. Module 2 — Secure File & Folder Eraser (`vajra-file-erase`)

### 3.1 Common pipeline (per file, filesystem-agnostic shape)

```
1. Resolve file -> list of (extent/cluster-run) physical locations via FS-specific parser
2. Overwrite each data extent (pattern per selected standard)
3. Overwrite/zero the metadata record (MFT entry / inode / directory entry) itself
4. Purge references from FS journal / change-log
5. Purge from snapshot/shadow-copy providers if present (see 3.5)
6. Purge OS-level residual traces (see 3.6)
7. Mark space free in allocation bitmap ONLY after step 2-3 confirmed complete
   (critical ordering — see below)
8. Verify: attempt a best-effort carve of the just-deleted file; expect zero recoverable content
9. Log per-file result (success/partial/failed + reason) to case DB
```

**Critical ordering rule:** never mark clusters/blocks free before overwriting them. If you free-then-overwrite, a concurrent process (or the OS itself, e.g. via prefetch/indexing) can allocate and write to that space between your free and your overwrite, and if your tool crashes in that window, the file is neither properly erased nor recoverable-and-intact — it's corrupted garbage that still might leak partial content. Free-after-overwrite is slightly slower but is the only version that is crash-safe and non-racy.

### 3.2 NTFS specifics (`vajra-fs-ntfs`)

- Parse `$MFT` directly (raw sector reads, don't rely on Windows API which won't show low-level structure) to locate `$DATA` attribute runs (handle both resident — data stored inline in MFT record for small files — and non-resident attributes)
- Zero the full 1024-byte MFT record after data overwrite, not just the filename attribute
- Parse and purge relevant entries from **`$LogFile`** (NTFS write-ahead log — can contain full or partial old data even after MFT cleanup) and **`$UsnJrnl:$J`** (change journal — records every rename/delete/write event with old names)
- Enumerate and delete relevant **Volume Shadow Copies**: use Windows VSS API (`IVssBackupComponents`) to enumerate shadow copies containing the target file's volume, and either delete the whole shadow copy (if policy allows) or flag it in the report as "not sanitized — present in shadow copy created [date]" so the user/investigator makes an informed call rather than the tool silently claiming success
- Purge `$Bitmap` only after confirming overwrite+MFT-zero succeeded

### 3.3 ext4 specifics (`vajra-fs-ext4`)

- Parse inode → extent tree (or indirect block pointers for older ext2/3-style inodes still valid in ext4) to find physical block locations
- Zero inode table entry fully (many default configs leave stale inode data — a classic recoverability finding your tool should specifically fix, and can cite in your report as a differentiator vs. plain `rm`)
- Handle `jbd2` journal: if `data=journal` mode, actual file content may be journaled — must locate and overwrite journal blocks referencing this inode too; if `data=ordered` (default), only metadata is journaled, still needs purging
- Detect and handle **LVM snapshots** and **Btrfs/ZFS subvolume snapshots** on the same physical volume — same philosophy as VSS: either purge with permission, or explicitly flag as residual risk in the report

### 3.4 APFS specifics (`vajra-fs-apfs`)

- Parse the APFS object map (copy-on-write B-tree) to find current physical block mapping for the file
- **APFS snapshots are the big one here** — Time Machine and macOS system updates create these constantly and silently. A "securely deleted" file can be trivially recoverable from an untouched snapshot even with perfect live-volume erasure. Enumerate snapshots via `fs_snapshot_list`-equivalent syscalls, and this must be surfaced prominently in the UI before the user considers a delete "done"
- Extended attributes (xattrs) and resource forks handled as separate data streams needing their own overwrite pass
- **SIP constraint**: for system-volume operations, the tool needs a properly signed/notarized helper with the right entitlements (`com.apple.rootless.storage-class` or a DriverKit extension for raw access). Scope initial macOS support to non-system/user-data and external volumes to avoid fighting SIP; document the system-volume limitation honestly rather than silently failing.

### 3.5 exFAT/FAT32 specifics (`vajra-fs-fat`)

Simplest of the four — FAT table chain zeroing + directory entry (including long-filename entries, which span multiple 32-byte directory records) + no journal to worry about. Good confidence-building first target during development.

### 3.6 OS-level residual trace cleanup (per platform)

| OS | Traces to clean |
|---|---|
| Windows | Thumbcache (`thumbcache_*.db`), Recent Items (`Recent\`), Jump Lists (`AutomaticDestinations`/`CustomDestinations`), Windows Search index (`Windows.edb`), Prefetch (`.pf` files referencing the executable/path), Registry `MRU` (Most Recently Used) lists, `RecentDocs` registry key |
| Linux | `~/.local/share/Trash`, `~/.thumbnails` / `~/.cache/thumbnails`, desktop search indexes (Tracker, Baloo), shell history if filename was referenced, `.recently-used.xbel` |
| macOS | Spotlight index entries (`mdimport`/`mds` metadata), `com.apple.LSSharedFileList` (recent items plist), QuickLook thumbnail cache |

### 3.7 Batch operation semantics

Job queue with per-file atomic status (`Pending → InProgress → Verified → Failed(reason)`), resumable (same crash-safety principle as drive erase), and a final batch report showing exact counts and itemized failures — never a bare "Done" for a 10,000-file batch.

---

## 4. Module 3 — Advanced File Carving & Recovery (`vajra-carve`)

### 4.1 Three-tier recovery pipeline (run in this order, cheapest/highest-confidence first)

```
Tier 1: Filesystem-metadata recovery (cheapest, highest confidence when available)
   -> Parse $MFT / inode table / FAT directory entries directly from raw device,
      even on a "formatted" volume, since quick-format typically leaves original
      metadata structures largely intact
   -> Recovers correct filenames, timestamps, directory hierarchy, and exact
      cluster/block runs -- best possible outcome, do this first always

Tier 2: Signature-based carving (for anything Tier 1 couldn't resolve)
   -> Header/footer scanning across unallocated + full raw image
   -> Structural validator confirms/rejects each candidate

Tier 3: Fragmented reconstruction (for candidates that fail validation as contiguous)
   -> Bifragment Gap Carving for 2-fragment case
   -> Graph-based reassembly for N-fragment case (bounded, heuristic)
   -> ML-assisted fragment-boundary prediction narrows search space (see Module 5)
```

### 4.2 Signature database design

Extensible TOML/JSON-defined signature entries, not hardcoded:

```toml
[[signature]]
type = "jpeg"
header = "FFD8FF"
footer = "FFD9"
max_size_bytes = 52428800
validator = "jpeg_structural"

[[signature]]
type = "pdf"
header = "255044462D"   # "%PDF-"
footer = "2525454F46"    # "%%EOF"
max_size_bytes = 104857600
validator = "pdf_xref_validator"
```

Ship with signatures for: JPEG, PNG, GIF, BMP, TIFF, PDF, DOCX/XLSX/PPTX (ZIP-based), legacy DOC/XLS/PPT (OLE2/CFB format), ZIP, RAR, 7z, MP3, MP4/MOV, AVI, MKV, SQLite DB, email formats (PST/MBOX), and common source-code/text formats via content heuristics rather than magic bytes.

### 4.3 Structural validators (the quality differentiator — build these properly, not just magic-byte checks)

- **JPEG**: walk JFIF marker segments (SOI, APPn, DQT, SOF, DHT, SOS...EOI); attempt Huffman decode of scan data, reject if bitstream errors occur mid-decode
- **PNG**: verify per-chunk CRC32 sequentially; PNG's built-in checksums make this near-deterministic
- **PDF**: parse xref table/cross-reference streams; walk object references; validate trailer/`startxref` consistency; handle both classic xref-table and modern cross-reference-stream (compressed) PDFs
- **ZIP-based (docx/xlsx/pptx/zip)**: validate local file headers + central directory + end-of-central-directory record; then validate that internal XML (`[Content_Types].xml`, `document.xml`, etc.) is well-formed
- **OLE2/CFB (legacy doc/xls/ppt)**: validate FAT/MiniFAT sector chains within the compound file structure
- **MP4/MOV**: parse atom/box tree (`ftyp`, `moov`, `mdat`); specifically implement **moov-atom repair** for the very common case where `moov` (index) is truncated/missing but `mdat` (raw media) is intact — this is a known hard, high-value sub-problem in video recovery and worth calling out specifically in your report as original engineering
- **SQLite**: validate page header magic (`SQLite format 3\0`), walk b-tree page structure for consistency — high value for recovering browser history, messaging app databases, forensic artifacts

### 4.4 Fragmented reconstruction — algorithm detail

**Bifragment Gap Carving (2-fragment case):**
```
Input: start block S (validated header), target size N blocks (from header metadata
       or max_size_bytes bound), structural_validator fn
For gap_size in 0..max_search_radius:
    For gap_start in S..(S + N):
        fragment_1 = blocks[S : gap_start]
        fragment_2_start = gap_start + gap_size
        fragment_2 = blocks[fragment_2_start : fragment_2_start + (N - len(fragment_1))]
        candidate = concat(fragment_1, fragment_2)
        if structural_validator(candidate).is_valid():
            return candidate  # first valid = accepted; log gap_size and confidence
return None  # falls through to N-fragment graph search or marked unrecoverable
```
Bound `max_search_radius` using filesystem allocation heuristics (query Tier-1 metadata if any survives — even partial MFT/inode data narrows the search space enormously versus blind search over the whole disk).

**N-fragment graph-based reassembly (heuristic, bounded):**
Build a graph where nodes are candidate block-runs (from unallocated-space clustering) and edge weights are a "structural compatibility score" — does content flow validly across the boundary (JPEG Huffman continues decoding without error; ZIP local-header checksum validates at the seam; text encoding remains valid UTF-8/ASCII across the join). Solve via bounded best-first search (A*-style, heuristic = remaining structural-validity gap) rather than exhaustive search. Document precisely in your report: this is heuristic and probabilistic beyond ~3-4 fragments, and you cap search time/depth explicitly rather than letting it run unbounded — an honest, bounded claim here is far stronger than an unbounded "it'll get there eventually" black box.

---

## 5. AI/ML Subsystem (`vajra-ml`) — Exact Design, CPU-Only

Since you're CPU-constrained, the entire ML layer uses **classical/lightweight models** — this is not a limitation to apologize for, it's the *correct* engineering choice for an explainable, court-relevant forensic tool anyway.

### 5.1 Model 1 — File-type classification (structure-agnostic)

**Purpose:** classify file type/validity from raw bytes even when headers are corrupted, stripped, or the file is renamed — catches what signature matching alone misses.

**Model:** Gradient-boosted trees (LightGBM — fast, CPU-efficient, handles tabular engineered features well, and crucially: **feature importance is directly inspectable**, which matters for your "explainable confidence" story).

**Features (engineered, not raw bytes fed to a black box):**
- Byte-frequency histogram (256-dim, normalized) computed over sliding windows
- Shannon entropy, computed per 512-byte chunk across the candidate file (a *profile*, not one scalar — encrypted/compressed data is uniformly high-entropy throughout; plaintext/structured data has entropy variation, e.g. headers are low-entropy, compressed payloads are high-entropy, and the *transition pattern* is itself a strong signal)
- N-gram byte sequence frequencies (2-gram, 3-gram) — different file formats have distinct statistical "fingerprints" here
- Longest run of printable ASCII (helps separate text-like from binary-like content)
- Chi-square test statistic against uniform distribution (further entropy corroboration)

**Training data:** Public corpora — **Govdocs1** (nearly 1 million files, ground-truth labeled by type, the standard academic corpus for exactly this task) and **NIST CFReDS** (Computer Forensic Reference Data Sets — designed specifically for forensic tool validation) — supplemented with your own synthetically corrupted/truncated/header-stripped variants generated by a training-data augmentation script (`vajra-ml-train` crate: takes clean files, randomly truncates/corrupts/strips headers/introduces byte flips, labels the ground truth, builds the training set).

### 5.2 Model 2 — Fragmentation-point prediction

**Purpose:** instead of blind O(disk²) BGC search, predict likely fragment-boundary locations to prune the search space.

**Model:** Binary classifier (LightGBM again, or even simpler — logistic regression may suffice, worth benchmarking both since interpretability and speed both favor simplicity here) predicting "is this byte offset a likely fragment boundary" using local entropy discontinuity, structural-validity discontinuity (does the structural validator's confidence drop sharply here), and filesystem-allocation-pattern priors (from any surviving Tier-1 metadata) as features.

### 5.3 Model 3 (deliberately NOT a black-box) — Confidence Scoring

As discussed: this is a **transparent weighted composite**, not a learned end-to-end score. Individual *signals* feeding into it can be ML-derived (e.g., Model 1's classification confidence is one input signal), but the combination function itself must stay interpretable:

```rust
struct ConfidenceBreakdown {
    header_footer_integrity: f32,   // weight 0.20
    structural_validity: f32,        // weight 0.25  (from validator, possibly ML-assisted)
    metadata_cross_reference: f32,   // weight 0.20
    entropy_consistency: f32,        // weight 0.15  (Model 1 output feeds here)
    fragmentation_confidence: f32,   // weight 0.15  (Model 2 output feeds here)
    overwrite_probability: f32,      // weight 0.05
}

fn composite_score(b: &ConfidenceBreakdown) -> f32 {
    0.20 * b.header_footer_integrity
  + 0.25 * b.structural_validity
  + 0.20 * b.metadata_cross_reference
  + 0.15 * b.entropy_consistency
  + 0.15 * b.fragmentation_confidence
  + 0.05 * b.overwrite_probability
}
```

Every recovered file's report shows the full breakdown, not just the final number. Weights should themselves be **empirically calibrated** against your labeled test corpus (measure: does a file scored 85%+ actually turn out correct/intact 85%+ of the time when checked against ground truth? Adjust weights until the score is well-calibrated — this calibration step, and the resulting calibration curve/plot, is genuinely excellent material for your validation report and will impress judges who understand ML evaluation).

### 5.4 Model 4 — Audit log anomaly detection (secondary feature)

Isolation Forest (lightweight, unsupervised, good for this) over operation-sequence and timing features from the audit log — flags unusual patterns (repeated verification aborts, operations outside expected sequence). Positioned honestly as a compliance-assist feature, not a security-critical control.

### 5.5 Deployment format

Train in Python (scikit-learn/LightGBM) inside `vajra-ml-train`, export to **ONNX**, run inference in Rust via the `ort` (ONNX Runtime) crate — keeps the shipped app pure-Rust/native with no Python runtime dependency, while giving you the mature Python ML tooling during development.

---

## 6. RAID & Network Storage (`vajra-raid`, `vajra-network`)

### 6.1 RAID reconstruction

- **RAID 0**: pure striping — reconstruct by reading member drives in stripe order, no parity math needed, but *order matters* — must correctly detect stripe size and drive order from metadata (mdadm superblock on Linux, or manual stripe-size specification if metadata is damaged/missing)
- **RAID 5**: single parity (XOR across N-1 drives = Nth). Implement both: (a) full-array reconstruction when all drives present, (b) **degraded-mode reconstruction** when one drive is missing/failed — compute missing drive's data on-the-fly via XOR of remaining drives + parity. This degraded-mode case is actually the *most realistic forensic scenario* (why else would someone need recovery on a RAID array) and is where your tool proves real value
- **RAID 6**: dual parity (Reed-Solomon based, not just XOR) — can reconstruct with up to 2 missing drives; implement the Galois-field arithmetic for the second parity syndrome
- Detect RAID metadata: `mdadm` superblocks (Linux software RAID), Windows Storage Spaces metadata, common hardware RAID controller signatures (best-effort, vendor-specific formats aren't always public)
- Expose the reconstructed array as a single `BlockSource` — this is why the trait-based architecture from Section 1.2 pays off here; carving/erasure code needs zero RAID-specific logic

### 6.2 Network share access

- SMB/CIFS (Windows shares, Samba) via a Rust SMB client library, NFS via native OS mount or a Rust NFS client
- Treat mounted network shares primarily as a **file/folder eraser target** (Module 2) rather than block-level erasure target, since you don't own the underlying physical media over a network protocol — be explicit in the report that "secure erase" over a network share means file-level overwrite+metadata purge on the *remote filesystem*, not a drive-level NIST 800-88 Purge, since you have no access to the remote physical media or its controller commands. This distinction matters and should be stated plainly rather than glossed over.

---

## 7. Encrypted Volume Support (`vajra-crypto-vol`)

| Encryption | Approach |
|---|---|
| **BitLocker** (Windows) | Parse BitLocker metadata (FVE metadata block) to detect encryption; unlock via recovery key, password, or (if run on the live encrypted system with appropriate privileges) TPM-backed key retrieval through Windows APIs. Once unlocked, expose the decrypted volume as a standard `BlockSource` — everything downstream (carving, secure delete) works unmodified |
| **FileVault 2** (macOS) | Detect via CoreStorage/APFS encryption metadata; unlock via password or institutional/recovery key; similarly exposes decrypted volume transparently |
| **LUKS** (Linux) | Parse LUKS header (LUKS1/LUKS2), unlock via passphrase or keyfile using standard key-derivation (PBKDF2/Argon2 depending on LUKS version), decrypt via `dm-crypt`-equivalent AES-XTS implementation |

**Critical scoping note to be explicit about in your docs:** "full decrypt-and-process support" means the tool can unlock volumes **given valid credentials** (password/recovery key/keyfile) — this is not, and should never be marketed as, a brute-force or credential-bypass capability. That would cross from a forensic/security tool into something else entirely, and your report/documentation should state this boundary clearly and unambiguously: valid authorization/credentials are a precondition for volume access, consistent with lawful forensic practice (a warrant/consent authorizes access; your tool executes the technical unlock given the resulting credentials, exactly like Autopsy/EnCase/FTK operate in real casework).

---

## 8. Reporting & Chain-of-Custody Engine (`vajra-audit`)

### 8.1 Hash-chained event log

```rust
struct AuditEntry {
    seq: u64,
    timestamp_utc: DateTime<Utc>,      // NTP-synced at app start, drift-checked periodically
    operator_id: String,
    case_id: String,
    operation: OperationType,           // Erase, Recover, Verify, etc.
    target_descriptor: String,          // device serial / file path+hash
    result: OperationResult,
    prev_hash: [u8; 32],
    entry_hash: [u8; 32],               // SHA256(serialize(entry without entry_hash) + prev_hash)
}
```
Any post-hoc edit to any entry breaks every subsequent hash — this is your tamper-resistance guarantee, verifiable by anyone re-computing the chain, not just trusted because your app says so.

### 8.2 X.509 / PKI digital signing

- On first run, generate a self-signed CA + operator certificate (demo/single-org mode); document clearly how this would be replaced by an org-issued cert from a real CA in production deployment
- Each finalized case report is signed: `signature = RSA/ECDSA_Sign(privkey, SHA256(report_content))`
- Report bundle includes: the report (PDF human-readable + JSON machine-readable), the signature, and the signing certificate chain — anyone can verify independently with standard tools (`openssl verify`), not just inside your app
- Timestamping: consider embedding a **RFC 3161 trusted timestamp** if you want to go further (proves the report existed at signing time, independent of your app's own clock) — worth implementing given your "no time constraints" scope, it's a strong differentiator for the court-admissibility story

### 8.3 Report contents (chain-of-custody fields, per operation)

Case number, investigator/operator ID, device make/model/serial, device hash before operation (if applicable — e.g. hash of a forensic image before file recovery), operation type and parameters (exact standard used, pass count, etc.), start/end timestamps, verification method and sample plan, result, operator signature, and for recovery specifically: per-file confidence breakdown (Section 5.3) and recovery method used (Tier 1/2/3).

---

## 9. Case Management (`vajra-case-db`)

SQLite via SQLCipher (encrypted at rest — the case DB itself contains sensitive forensic data and must not sit as a plaintext file on disk). Schema sketch:

```sql
CREATE TABLE cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT, investigator_id TEXT,
    created_at TEXT, status TEXT
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases,
    serial TEXT, model TEXT, media_type TEXT, capacity_bytes INTEGER
);
CREATE TABLE operations (
    op_id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases,
    device_id TEXT REFERENCES devices, op_type TEXT,
    parameters_json TEXT, started_at TEXT, completed_at TEXT, status TEXT
);
CREATE TABLE recovered_files (
    file_id TEXT PRIMARY KEY, op_id TEXT REFERENCES operations,
    original_path TEXT, recovered_path TEXT, file_type TEXT,
    confidence_score REAL, confidence_breakdown_json TEXT,
    recovery_tier INTEGER  -- 1=metadata, 2=signature, 3=fragmented
);
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY, entry_json TEXT, entry_hash TEXT, prev_hash TEXT
);
```

---

## 10. UI Dashboard (Tauri + React)

Core screens: **Case Home** (create/open case) → **Device Selection** (enumerated drives with media-type badges, RAID/network share detection) → **Operation Wizard** (Erase / Secure Delete / Recover, each with a standard-selection step showing plain-language explanations of NIST Clear vs Purge vs crypto-erase) → **Live Progress** (throughput, ETA, sectors verified, cancel/pause) → **Recovered File Browser** (grid view, filterable by type/confidence tier, per-file breakdown panel) → **Report Center** (generate, view, export, verify signature).

Design principle: mirror the case-based workflow of Autopsy/FTK/EnCase since that's what will read as credible to anyone with forensic domain knowledge on your evaluation panel, while using Tauri/React to make it feel modern rather than dated.

---

## 11. Standards & Compliance Mapping

| Standard | Where it's satisfied in the system |
|---|---|
| NIST SP 800-88 Rev.1 | Section 2.2 (Clear/Purge strategy matrix), Section 2.4 (verification methodology) |
| DoD 5220.22-M | Section 2.2 (legacy 3-pass mode) |
| ISO/IEC 27001 (information security management) | Section 8 (audit logging), Section 9 (encrypted case DB) |
| IT Act 2000, Section 43A (India — reasonable security practices) | Whole-system: audit trail + access control on case DB directly supports "reasonable security practices" documentation requirements |
| CERT-In guidelines | Section 8 (incident-grade audit logging), report retention format |
| DPDP Act 2023 (India — data sanitization obligations) | Section 2 (Drive Eraser) directly implements the "erasure of personal data" technical requirement the Act contemplates for data fiduciaries |

Build a dedicated `docs/standards-mapping.md` in the repo, generated/maintained as a living document — SIH panels specifically reward teams that can point to an explicit compliance mapping rather than vague "we follow standards" claims.

---

## 12. Testing & Validation Methodology

1. **Erasure verification loop**: wipe a drive with `vajra-erase` → run `vajra-carve` (your own recovery engine) against it → separately run a third-party tool (PhotoRec) against the same wiped drive as an independent check → expect near-zero recoverable content from both; any discrepancy between your carver and PhotoRec's findings is itself useful debugging signal
2. **Recovery accuracy**: build a labeled ground-truth corpus (Govdocs1 subset + synthetic corruption/fragmentation) → run full recovery pipeline → report **precision, recall, and confidence-score calibration curve** (predicted confidence vs. observed correctness) — this calibration curve is your single best piece of evidence that the confidence scoring system in Section 5.3 is real and not decorative
3. **Cross-filesystem test matrix**: NTFS/ext4/APFS/FAT32 × (intact file, deleted-not-overwritten, quick-formatted, fully corrupted, fragmented) — a full matrix of test scenarios, documented with pass/fail per cell
4. **RAID degraded-mode test**: build a test RAID-5 array, simulate single-drive failure, verify reconstruction accuracy against known-good data
5. **Chain-of-custody integrity test**: generate a report, tamper with one field in the underlying log, verify the hash chain detects it and the signature verification fails

---

## 13. Known Limitations (state these explicitly — this is what makes the rest credible)

- SSD data that has undergone TRIM + garbage collection prior to your tool running cannot be recovered by any software method — physics, not an engineering gap
- N-fragment (>3-4) reassembly is heuristic/probabilistic, bounded by search time, not guaranteed
- Volume decryption requires valid credentials — this is a design boundary, not a shortfall
- Hardware-RAID controllers with proprietary/undocumented metadata formats may not be auto-detected; manual configuration fallback needed
- Physical destruction (NIST "Destroy" tier) is out of software's reach by definition — the tool correctly recommends it rather than claiming to replace it

---

## 14. Development Phases (no fixed deadline, but sequence matters)

1. **Foundation**: `vajra-core` trait design + `vajra-device` basic enumeration (Windows/Linux/macOS) + `vajra-case-db`
2. **Erasure MVP**: `vajra-erase` for HDD (overwrite) + basic USB support, working end-to-end with reporting
3. **File/Folder Eraser MVP**: NTFS + ext4 + FAT32, no snapshot handling yet
4. **Carving Tier 1+2**: filesystem-metadata recovery + signature carving for the top 6 file types
5. **SSD-proper erasure**: ATA Secure Erase, NVMe Sanitize, TCG Opal crypto-erase
6. **Snapshot/journal handling**: VSS, ext4 journal, APFS snapshots
7. **Carving Tier 3**: BGC + graph-based fragment reassembly
8. **ML layer**: train Model 1 (classification) and Model 2 (fragmentation) on public+synthetic data, integrate via ONNX
9. **RAID + network shares**
10. **Encrypted volumes**
11. **PKI signing + full chain-of-custody reporting**
12. **UI polish + full case workflow**
13. **Validation suite + documentation + user manuals**

This ordering front-loads the pieces that are both highest-value and lowest-risk (basic erasure and Tier 1/2 recovery are well-understood, deterministic engineering), and pushes the genuinely research-grade pieces (N-fragment reassembly, ML layer) to the middle once the foundation is solid — so you always have a demoable system at every stage rather than a big-bang integration risk at the end.

---

*This document is meant to be a living reference — update `docs/standards-mapping.md` and `docs/validation-report.md` as the build progresses so your final SIH submission has real evidence (calibration curves, test matrices, precision/recall numbers) rather than only design claims.*
