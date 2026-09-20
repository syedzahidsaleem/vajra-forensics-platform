# Vajra

**An offline-first digital forensics and secure data sanitization platform, written in Rust and TypeScript.**

Vajra performs two critical functions that traditional tooling keeps strictly separate:
1. **Forensic Recovery**: Recovers digital evidence from storage media and filesystems with an itemized, mathematically defensible confidence breakdown attached to every recovered artifact.
2. **Secure Sanitization**: Destroys data on storage media across five independent verification layers, culminating in an automated forensic re-carve scan and a cryptographically signed sanitization certificate.

Both workflows execute entirely on the examiner's workstation with **zero network dependencies** in the trust path.

---

## Contents

1. [What Vajra is](#what-vajra-is)
2. [The problem Vajra solves](#the-problem-vajra-solves)
3. [Architecture & Layering](#architecture--layering)
4. [Implemented Workspace Modules](#implemented-workspace-modules)
5. [User Interface & Desktop Application](#user-interface--desktop-application)
6. [Forensic Workflow](#forensic-workflow)
7. [Sanitization Workflow & Safety Gate](#sanitization-workflow--safety-gate)
8. [Multi-Tier Recovery Pipeline](#multi-tier-recovery-pipeline)
9. [Supported Filesystems](#supported-filesystems)
10. [Supported Carving Formats](#supported-carving-formats)
11. [Evidence Integrity & Audit Chains](#evidence-integrity--audit-chains)
12. [Reporting & Standalone Verification](#reporting--standalone-verification)
13. [Releases & Installation](#releases--installation)
14. [Building & Running](#building--running)
15. [Testing & Verification](#testing--verification)
16. [Current Limitations](#current-limitations)
17. [Branch Status & Team Contributions](#branch-status--team-contributions)
18. [Standards & Compliance](#standards--compliance)
19. [License & Legal Scope](#license--legal-scope)

---

## What Vajra is

A 20-crate Rust workspace paired with a high-performance React/Vite/Tailwind desktop interface (powered by Tauri v2):

- **Device Layer (`vajra-device`)** — Enumerates physical storage, performs deterministic hardware fingerprinting, assesses SMART / NVMe health via native ioctl queries, and detects write blockers and boot disks.
- **Acquisition & Imaging (`vajra-acquire`, `vajra-image`)** — Bit-stream disk imaging (RAW/DD, E01) with recursive bad-sector reduction, dual-phase rolling/re-read SHA-256 hashing, and checkpoint resumption.
- **Filesystem Reconstruction (`vajra-fs-ntfs`, `vajra-fs-ext4`, `vajra-fs-fat`, `vajra-fs-apfs`)** — In-depth parsing of NTFS (`$MFT`, `$Bitmap`, USN records), ext4 (extent trees, directory slack), and FAT12/16/32 with allocation-bitmap validation.
- **Multi-Tier File Carving (`vajra-carve`)** — Fast object validation (JPEG, PNG, PDF, ZIP/Office, SQLite, OLE2/CFB, MP4/ISO-BMFF) paired with bi-fragment gap carving and dynamic candidate window expansion.
- **Machine Learning Classification (`vajra-ml`)** — Pure-Rust, CPU-only gradient-boosted decision tree ensemble (280-dimensional feature vector) providing an explainable classification signal for carved fragments.
- **Storage Subsystems (`vajra-raid`, `vajra-crypto-vol`)** — Automatic mdadm superblock assembly with $\text{GF}(2^8)$ Reed–Solomon RAID 0/5/6 reconstruction; real LUKS1/LUKS2 volume unlock (AES-XTS), BitLocker layouts, and FileVault detection.
- **Secure Data Sanitization (`vajra-erase`, `vajra-file-erase`)** — Two-phase Device Identity Confirmation Gate, NIST SP 800-88 / IEEE 2883 decision engine, 5-layer verification suite (with Layer-5 recovery override), and block/file-level erasure.
- **Evidence Vault & Audit Custody (`vajra-case-db`, `vajra-audit`, `vajra-custody`)** — SQLCipher encrypted case database at rest (Argon2id key derivation), hash-chained Ed25519-signed audit trail, and 10-state chain-of-custody machine.
- **Reporting & Independent Verifier (`vajra-audit`, `vajra-verify`)** — Six signed `.vjr` report envelopes with RFC 3161 PKI timestamping and an isolated, zero-dependency standalone verification tool.
- **Desktop Application & UI (`vajra-tauri-app`, `ui`)** — Modern Tauri v2 desktop GUI with dark/light themes, interactive storage block map visualizer, hex explorer, case management dashboard, and sanitization console.

---

## The problem Vajra solves

Forensic recovery tools and data-destruction tools are usually built by different vendors, tested against different assumptions, and produce output that must be trusted on faith. Vajra addresses three core flaws:

1. **Recovery output is qualified, not merely asserted**: A carved file is never simply marked as "recovered". Every artifact receives a composite confidence score with a 6-signal breakdown and an explicit limitations statement detailing structural flags, sector slack, or truncation.
2. **Erasure is verified, not merely claimed**: Wipe utilities typically report the success code of the command issued. Vajra validates destruction across five independent layers, culminating in its own recovery engine re-scanning the media. If a single artifact is recovered, the sanitization operation is marked as `Failed`.
3. **Evidence handling is independently auditable**: Audit trails are hash-chained and Ed25519-signed with optional external anchoring. The standalone verifier (`vajra-verify`) shares zero code with the generation pipeline, allowing courts or third parties to verify reports independently.

---

## Architecture & Layering

```
                     ┌───────────────────────────────┐
                     │   Tauri Desktop UI / React    │
                     │          (ui/ + tauri)        │
                     └───────────────┬───────────────┘
                                     │ IPC Bridge
                     ┌───────────────▼───────────────┐
                     │           vajra-cli           │
                     └───────┬───────┬───────┬───────┘
                             │       │       │
      ┌──────────────────────┼───────┼───────┼──────────────────────┐
      │                      │       │       │                      │
┌─────▼────────┐      ┌──────▼───────▼┐ ┌────▼────────┐      ┌──────▼───────┐
│ vajra-acquire│      │  vajra-carve  │ │ vajra-erase │      │ vajra-audit  │
└─────┬────────┘      │vajra-file-eras│ │vajra-file-er│      │vajra-custody │
      │               └──────┬────────┘ └────┬────────┘      │vajra-case-db │
┌─────▼────────┐      ┌──────▼────────┐      │               └──────┬───────┘
│ vajra-image  │      │vajra-fs-{ntfs,│      │                      │
│ (RAW/DD, E01)│      │  ext4, fat}   │      │               ┌──────▼───────┐
└─────┬────────┘      │   vajra-ml    │      │               │ vajra-verify │
      │               └──────┬────────┘      │               │(independent) │
┌─────▼──────────────────────┼───────────────▼┐              └──────────────┘
│ vajra-raid / vajra-crypto-vol / vajra-device │
└────────────────────────────┬────────────────┘
                             │
                      ┌──────▼───────┐
                      │  vajra-core  │  ← Pure traits & domain types (zero I/O)
                      └──────────────┘
```

### The Read-Only / Writable Type Safety Boundary
In `vajra-core`, storage access is split into two traits:
- `ReadOnlyBlockSource`: Carried across acquisition, imaging, filesystem parsing, and carving pipelines. Write operations are physically prevented at compile-time by the Rust type system.
- `WritableBlockSource`: Only instantiable by providing a cryptographically issued `SanitizationAuthorizationToken` following completion of the two-phase identity gate.

---

## Implemented Workspace Modules

| Crate | Responsibility | Status |
| :--- | :--- | :--- |
| **`vajra-core`** | Block-source traits, domain models, deterministic fingerprinting, error model | Implemented |
| **`vajra-device`** | Physical storage enumeration, SMART/NVMe health (Windows ioctl + Linux ioctl), write-blocker detection | Implemented |
| **`vajra-raid`** | RAID 0, 5, and 6 reconstruction with $\text{GF}(2^8)$ Reed–Solomon decoding, auto-assembling mdadm superblocks | Implemented |
| **`vajra-crypto-vol`** | Volume unlock: real LUKS1/LUKS2 (PBKDF2/Argon2id + AES-XTS), BitLocker layouts, FileVault detection | Implemented |
| **`vajra-acquire`** | Bit-stream device imaging, bad-sector map, dual-phase hashing, checkpoint resumption | Implemented |
| **`vajra-image`** | Forensic image reading/writing: RAW/DD read+write, E01 read (ewf), AFF4 container stub | Implemented |
| **`vajra-fs-ntfs`** | NTFS parser: `$MFT` record decoding, signed-delta runlists, `$Bitmap` cross-referencing, USN journals | Implemented |
| **`vajra-fs-ext4`** | ext4 parser: 64-bit group descriptors, extent trees, directory-entry slack recovery, orphan inode sweep | Implemented |
| **`vajra-fs-fat`** | FAT12/16/32 parser: FAT chain walk, LFN reconstruction, deleted `0xE5` entry recovery | Implemented |
| **`vajra-fs-apfs`** | APFS container and object map module | Stub / Phase A |
| **`vajra-carve`** | 3-tier carving engine: signature DB, fast object validators (JPEG, PNG, PDF, ZIP, SQLite, OLE2, MP4), bi-fragment gap carving | Implemented |
| **`vajra-ml`** | Pure-Rust gradient-boosted tree classifier (60 estimators, 280-dim features) for header-stripped candidate validation | Implemented |
| **`vajra-erase`** | Sanitization decision engine, 2-phase confirmation gate, 5-layer verification, Ed25519 certificates | Implemented |
| **`vajra-file-erase`** | Block-level file erasure, live-file multi-pass primitive, 5-state residual scanner | Implemented |
| **`vajra-audit`** | Hash-chained Ed25519-signed audit ledger, external anchoring, 6 signed report formats | Implemented |
| **`vajra-custody`** | 10-state chain-of-custody tracking engine with strict state-transition enforcement | Implemented |
| **`vajra-case-db`** | Encrypted evidence vault (SQLCipher + Argon2id key derivation, 9 tables, irreversible tombstoning) | Implemented |
| **`vajra-verify`** | Isolated, zero-dependency CLI binary for independent `.vjr` report envelope verification | Implemented |
| **`vajra-cli`** | Unified CLI covering forensic acquisition, filesystem analysis, carving, sanitization, and reporting | Implemented |
| **`vajra-tauri-app`** | Tauri v2 desktop application shell with modular IPC command handlers | Implemented |

---

## User Interface & Desktop Application

Vajra includes a complete desktop user interface located in `ui/` that binds directly to the Rust backend via Tauri v2 IPC handlers:

- **Case Management Dashboard**: Manage open cases, evidence registries, and examiner session metadata stored in the encrypted SQLCipher database.
- **Device Selection & Health Monitor**: Live device discovery with real-time SMART/NVMe telemetry, partition mapping, and hardware write-blocker indicators.
- **Acquisition Wizard**: Visual setup for physical, partial, or logical disk acquisitions with real-time throughput metrics, bad-sector tracking, and dual-phase hash verification.
- **Forensic Recovery Browser**: Multi-tier artifact browser with search filters, metadata inspection, confidence breakdowns, and direct payload exports.
- **Storage Block Map (`StorageMap`)**: High-performance visual canvas mapping physical drive blocks into allocated, unallocated, bad-sector, and recovered fragment regions.
- **Hex Explorer**: Integrated hex viewer with ASCII decoding, entropy graph overlays, and offset bookmarking.
- **Sanitization Console & Two-Phase Gate**: Secure destruction interface enforcing operator identity entry, physical serial confirmation, algorithm selection, and 5-layer verification display.
- **Report Center**: One-click generation and cryptographic signing of `.vjr` envelopes and audit certificates.

---

## Forensic Workflow

```bash
vajra-cli list                      # Enumerate physical devices & write-blocker status
vajra-cli fingerprint <device>      # Deterministic SHA-256 hardware identity
vajra-cli health <device>           # Native SMART / NVMe health diagnostics
vajra-cli case create ...           # Open an encrypted case in the vault
vajra-cli evidence add ...          # Register physical media and open custody chain
vajra-cli acquire start ...         # Image device with dual-phase hashing & checkpoints
vajra-cli image inspect <image>     # Validate image container headers and stored hashes
vajra-cli fs detect|list|dump ...   # Perform filesystem-level metadata recovery
vajra-cli carve run|inspect|stats   # Execute Tier 2 & Tier 3 carving pipeline
vajra-cli ml classify <file>        # Run GBDT classifier on header-stripped artifacts
vajra-cli report generate ...       # Generate and sign .vjr Report Envelope
vajra-verify <report.vjr>           # Independently verify cryptographic integrity
```

---

## Sanitization Workflow & Safety Gate

To eliminate accidental data loss, all destructive operations strictly require a valid `SanitizationAuthorizationToken`.

```
Phase 1: DeviceConfirmationGate::begin(device, operator, typed_serial, confirm)
    ├── Unconditionally rejects system/boot disks
    ├── Unconditionally rejects write-blocked devices
    ├── Requires exact case-insensitive match of physical hardware serial number
    └── Returns a single-use PendingSanitization ticket

Phase 2: PendingSanitization::finalize(pre_exec_confirm)
    ├── Consumes ticket by value (single use, cannot be re-executed)
    └── Returns SanitizationAuthorizationToken bound to target physical path
```

### Five-Layer Verification Suite

| Layer | Verification Stage | Method |
| :---: | :--- | :--- |
| **1** | Command Execution | Verifies controller/OS return status |
| **2** | Device State Readiness | Confirms post-operation block source readiness |
| **3** | Deterministic Sampling | Reads fixed boundary and partition table LBAs |
| **4** | Statistical Sampling | Hypergeometric sampling over ChaCha20 random sectors |
| **5** | **Independent Carving Scan** | **Re-runs `vajra-carve` against the sanitized drive; any artifact forces overall failure** |

---

## Multi-Tier Recovery Pipeline

1. **Tier 1 (Filesystem Metadata)**: Traverses NTFS MFT, ext4 directory trees/slack, and FAT tables. Confirmed free blocks are marked in an `AllocatedBlockMap`.
2. **Tier 2 (Structural Fast Object Validation)**: Scans unallocated sectors against `config/signatures.json`. Dispatches candidates to Garfinkel-style fast object validators (`V_OK`, `V_ERR`, `V_EOF`):
   - **JPEG**: SOI/EOI marker sequence and segment validation.
   - **PNG**: Chunk header walk with per-chunk CRC verification through `IEND`.
   - **PDF**: Header/trailer cross-reference table and `%%EOF` checks.
   - **ZIP / Office**: Local file headers and end-of-central-directory validation (DOCX, XLSX, PPTX).
   - **SQLite**: Page-size consistency, reserved space checks, and b-tree page header validation.
   - **OLE2 / CFB**: Compound File Binary header validation and FAT/DIFAT/MiniFAT sector chain traversal.
   - **MP4 / ISO-BMFF**: Box-tree walk (`ftyp`, `moov`, `mdat`, `moof`) with 32-bit and 64-bit extended box sizes.
3. **Tier 3 (Bi-Fragment Gap Carving)**: Solves two-fragment fragmented files using split-point $\times$ gap-size searches across empirical gap distributions with early prefix rejection.

### Composite Confidence Model

$$\text{Confidence} = 0.25\,S_v + 0.20\,H_i + 0.20\,M_c + 0.15\,E_c + 0.15\,F_c + 0.05\,O_p$$

- $S_v$: Structural validity (validator result & container geometry)
- $H_i$: Header/footer integrity (exact magic match vs. partial EOF)
- $M_c$: Metadata cross-reference (bitmap allocation status)
- $E_c$: Entropy consistency (Shannon profile or ML classifier score)
- $F_c$: Fragmentation confidence (contiguous vs. bi-fragment provenance)
- $O_p$: Overwrite probability (slack-byte uniformity check)

---

## Releases & Installation

Official pre-built binaries and installer packages are available on the [**GitHub Releases**](https://github.com/syedzahidsaleem/vajra-forensics-platform/releases) page.

### Pre-Built Packages (v0.1.0)

| Platform | Package File | Format | Target Arch | Included Components | SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows** | `Vajra-0.1.0-Setup.exe` | NSIS Setup | `x86_64` | Desktop UI (`vajra-tauri-app`), `WebView2Loader`, `vajra-cli`, `vajra-verify`, Signatures & ML Models | `52D207225A1C8CA4B540621CBDE0F8227AA6594E752CAB99EF9EC235D16B63A8` |
| **Linux** | `vajra_0.1.0_amd64.deb` | Debian Package | `amd64` | `vajra-cli`, `vajra-verify`, Signatures & ML Models, Doc Suite | `3DC7886B16CA187DD5BF81433E868CC9F10017E26BE46BCF557DF32B55EBC201` |
| **macOS** | Native Installer | `.pkg` / `.dmg` | `Apple Silicon` / `x86_64` | Phase B Roadmap (targeting `/Applications`) | *Phase B* |

> [!IMPORTANT]
> **Operating System / Boot Drive Installation Restriction**:
> By architectural design, Vajra must be installed strictly on the host operating system drive (`$WINDIR` / `C:\` on Windows, root `/` filesystem on Linux). Both the Windows NSIS installer and the Debian package actively validate the destination mount at install time and block installation onto secondary or removable drives. This guarantees that running binaries, dynamic libraries, and logs never create in-use OS file locks on secondary drives scheduled for sanitization or forensic acquisition.

---

### Windows Installation

1. Download [`Vajra-0.1.0-Setup.exe`](https://github.com/syedzahidsaleem/vajra-forensics-platform/releases/download/v0.1.0/Vajra-0.1.0-Setup.exe) from GitHub Releases.
2. Run the setup executable.
3. Review and accept the Vajra Apache-2.0 End-User Forensic License Agreement.
4. Keep the default installation directory on the OS drive (e.g., `C:\Program Files\Vajra`).
5. Complete installation. The installer automatically registers Desktop and Start Menu shortcuts and appends Vajra binaries to the system `PATH`.

To verify CLI availability from PowerShell or Command Prompt:
```powershell
vajra-cli --version
vajra-verify --version
```

---

### Linux Installation (Debian / Ubuntu)

1. Download [`vajra_0.1.0_amd64.deb`](https://github.com/syedzahidsaleem/vajra-forensics-platform/releases/download/v0.1.0/vajra_0.1.0_amd64.deb) from GitHub Releases.
2. Install the package using `dpkg` or `apt`:
```bash
sudo dpkg -i vajra_0.1.0_amd64.deb
# or
sudo apt-get install -f ./vajra_0.1.0_amd64.deb
```
3. *(Optional)* Grant raw block device inspection capabilities without requiring full root login:
```bash
sudo setcap cap_sys_rawio,cap_sys_admin+ep /usr/bin/vajra-cli
```
4. Verify installation:
```bash
vajra-cli --version
vajra-verify --version
```

---

## Building & Running

### Prerequisites

- **Rust**: 1.80+ (edition 2021)
- **Node.js**: 18+ (for desktop UI)
- **Perl**: Required on Windows if compiling SQLCipher with vendored OpenSSL

### 1. Build Backend CLI & Verifier

```bash
git clone https://github.com/syedzahidsaleem/vajra-forensics-platform.git
cd vajra-forensics-platform

# Build all workspace crates in release mode
cargo build --release

# Run CLI
cargo run -p vajra-cli -- --help

# Run Independent Verifier
cargo run -p vajra-verify -- --help
```

### 2. Build & Run Desktop UI (Tauri)

```bash
# Install UI dependencies
cd ui
npm install

# Build production web bundle
npm run build

# Run Tauri desktop app in development mode
npm run tauri dev
```

---

## Testing & Verification

The Vajra repository contains over 95 automated tests across all 18 backend crates, plus end-to-end integration and tamper verification suites.

```bash
# Run all workspace unit and integration tests
cargo test --workspace

# Run independent tamper verification tests
cargo test -p vajra-verify --test tamper_tests

# Run encrypted vault & SQLCipher tests
cargo test -p vajra-case-db --test db_tests

# Run multi-tier carving pipeline tests
cargo test -p vajra-carve --test carve_tests
```

---

## Current Limitations

- **Controller-Level Physical Issuance**: While ATA Secure Erase, NVMe Sanitize, and Cryptographic Erase are modeled and verified against mock devices, raw physical drive ioctl issuance is restricted to host-level overwrite to prevent accidental damage on development workstations.
- **MP4 `moov` Index Reconstruction**: Interrupted video recordings missing the `moov` atom are surfaced as truncated candidates (`V_EOF`) with qualified limitations rather than synthesized as complete.
- **APFS Depth**: APFS parser is currently in Phase A (container and superblock structures); snapshot tree traversal is planned for future scope.
- **E01 Writer**: E01 support is currently read-only; disk image writing produces raw bit-stream (.raw/.dd) images.

---

## Branch Status & Team Contributions

All development branches have been merged into `main` (`96d0610`):

1. **`vaibhavi`**:
   - Master technical documentation, standards mapping (`docs/standards-mapping.md`), and comprehensive user manual (`docs/user-manual.md`).
   - OLE2/CFB structural validator and ISO-BMFF box parsing foundations.
2. **`syed-zahid`**:
   - SQLCipher encrypted vault at rest with Argon2id key derivation.
   - Dynamic carving confidence (HFI + SV), candidate window expansion, and V_EOF partial recovery surfacing.
   - Linux `NVME_IOCTL_ADMIN_CMD` / ATA `HDIO_DRIVE_CMD` native diagnostics.
   - `vajra-raid` (RAID 0/5/6) and `vajra-crypto-vol` (LUKS1/2, BitLocker, FileVault).
3. **`akanksha`**:
   - Comprehensive test session logs (`docs/testing/session-logs/session-2026-09-04-01.md`) and multi-crate QA validation.
4. **`nitya`**:
   - Complete desktop application frontend in `ui/` (React, Vite, Tailwind CSS, AppShell, wizards, and dashboards).
   - Tauri v2 application configuration, capability schemas, and modular IPC commands in `crates/vajra-tauri-app/src/commands/`.
5. **`hari-priya`**:
   - Two-phase Device Identity Confirmation Gate formal proof (`docs/safety-gate-proof.md`).
   - Storage block map visualization components and forensic recovery filtering.

---

## Standards & Compliance

Vajra's implementation aligns with the following international and national digital forensics and sanitization standards (see [`docs/standards-mapping.md`](docs/standards-mapping.md) for full traceability):

- **NIST SP 800-88 Rev. 1 / IEEE 2883-2022**: Media sanitization methods, decision logic, and multi-layer verification.
- **ISO/IEC 27037:2012**: Digital evidence handling, chain of custody, and write-blocking principles.
- **ISO/IEC 27001:2022 / NIST SP 800-53**: Audit logging, cryptographic hash chaining, and access control.
- **RFC 3161**: ASN.1 DER trusted time-stamp token validation.
- **Indian IT Act 2000 (Section 65B) & DPDP Act 2023**: Electronic evidence admissibility, tamper-evident audit logs, and compliant data erasure.

---

## License & Legal Scope

- **License**: Apache-2.0
- **Legal Notice**: Vajra is intended strictly for authorized digital forensic examiners, incident responders, and compliance officers on storage media they are legally authorized to inspect or sanitize. The software does not implement unauthorized access or cryptanalytic bypass mechanisms.
