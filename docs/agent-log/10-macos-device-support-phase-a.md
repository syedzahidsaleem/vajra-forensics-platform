# Agent Log: Conversation 10 — macOS Device Support (Phase A: Implementation & Static Verification)

---

## 0. Phase A Scope & Verification Status

> [!IMPORTANT]
> **PHASE A ONLY — HARDWARE TESTING DEFERRED TO PHASE B**:
> No physical macOS hardware was available during this session. This conversation completes the full macOS device subsystem implementation, static type-checking against macOS target architectures (`x86_64-apple-darwin` and `aarch64-apple-darwin`), and local unit test validation of all XML plist parsers, APFS container unwrapping algorithms, media classifiers, and path normalization logic.
>
> In accordance with project discipline, **zero claims of empirical hardware execution on macOS are made in this log**. All hardware-bound assertions are explicitly marked as **"Implemented, Pending Phase B Real-Hardware Confirmation"**.

---

## 1. Summary of What Was Built

1. **`vajra-device` macOS OS Layer (`crates/vajra-device/src/os/macos/mod.rs`)**:
   - Added native macOS backend module alongside existing `windows` and `linux` implementations, satisfying the unified cross-platform contract (`enumerate_devices`, `query_device_health`, `OsDriveHandle::open_readonly`, `OsDriveHandle::open_writable`, `read_blocks`, `write_blocks`).
   - Gated in `crates/vajra-device/src/os/mod.rs` via `#[cfg(target_os = "macos")] pub use macos as imp;`.

2. **Raw Character Device Sector I/O (`/dev/rdiskN` & `F_NOCACHE`)**:
   - Implemented direct raw sector I/O targeting BSD raw character device nodes (`/dev/rdiskN`) rather than buffered block device nodes (`/dev/diskN`).
   - Normalizes path inputs (`disk0` / `/dev/disk0` -> `/dev/rdisk0`).
   - Issues `fcntl(fd, F_NOCACHE, 1)` to disable the macOS Unified Buffer Cache (UBC), enforcing direct DMA transfers between memory and the controller.
   - Enforces 4096-byte memory alignment (`AlignedBuffer`), exact-byte-count validation, and hard error returns (`IoError::ReadFailureAtLba`) on short reads.

3. **APFS Container Unwrapping & Boot-Disk Detection (§24)**:
   - Traverses active mount points (`/`, `/System/Volumes/Data`, `/System/Volumes/Preboot`) to isolate the active boot volume node (e.g. `/dev/disk3s1s1`).
   - Unwraps synthesized APFS Containers (`disk3`) to their underlying physical store partitions (`disk0s2`) and parent physical whole disks (`disk0`).
   - Sets `is_system_disk: true` on the physical parent drive to feed the platform-agnostic `DeviceConfirmationGate` (§34).

4. **Zero-Dependency Apple XML Plist Parser & Hardware Discovery (§23)**:
   - Built a robust, zero-dependency XML property list parser (`parse_plist`) supporting `<dict>`, `<array>`, `<string>`, `<integer>`, and `<true/>`/`<false/>` primitives.
   - Parses `diskutil list -plist` and `diskutil info -plist` to extract model, vendor, capacity, logical/physical block size, bus protocol, solid-state status, removable status, and partition scheme.
   - Implemented heuristic media classification (`MediaType::Nvme`, `MediaType::SataSsd`, `MediaType::Hdd`, `MediaType::Usb`, `MediaType::SdCard`).

5. **Dual-Tier Health Diagnostics (DiskArbitration + `smartctl`) (§23)**:
   - Primary tier: Queries native macOS `SMARTStatus` ("Verified", "Failing", "Not Supported") from DiskArbitration/IOKit.
   - Extended tier: Transparently invokes `smartctl -j -a` if installed on host (`/usr/local/bin/smartctl`, `/opt/homebrew/bin/smartctl`, or on PATH), extracting NVMe available spare percentage, percentage used, critical warnings, and ATA reallocated sectors with calibrated threshold evaluation.

---

## 2. Key Architectural Decisions & Reference Documentation

### 2.1 Raw Node (`/dev/rdiskN`) vs Buffered Node (`/dev/diskN`)
- **Apple Architecture**: On macOS/Darwin BSD, `/dev/diskN` accesses the buffered block device interface managed by the Unified Buffer Cache (UBC). Reads and writes pollute the OS file system cache and suffer copy overhead. `/dev/rdiskN` accesses the raw character device node, bypassing UBC for direct DMA transfers.
- **Reference**: Apple Developer Documentation: *BSD System Calls — raw device access and Disk Arbitration framework*.
- **Implementation**: `normalize_to_raw_device_path` automatically translates `/dev/diskN` and `diskN` to `/dev/rdiskN`. `OsDriveHandle` sets `F_NOCACHE` via `fcntl` for unbuffered sector throughput.

### 2.2 System Integrity Protection (SIP) & System Disk Safety
- **Apple Architecture**: Introduced in OS X 10.11 El Capitan and expanded in macOS 11 Big Sur (Signed System Volume), SIP prohibits raw write operations to internal storage hosting the active system boot container even when executed as `root` (`UID 0`).
- **Design Alignment**: Vajra explicitly scopes forensic sanitization to external and user-data drives on macOS, matching master blueprint guidance (§23, §34, §35). Boot disk detection tags the physical parent disk as `is_system_disk: true`, enabling the `DeviceConfirmationGate` to hard-block destructive operations.

### 2.3 APFS Container Structure & Physical Store Resolution
- **Apple Architecture**: Modern macOS systems format internal storage with GUID Partition Table (GPT), where partition 2 (`disk0s2`) is an `Apple_APFS` physical store. The macOS kernel synthesizes a virtual container block device (`disk3` or `disk1`) hosting multiple APFS volumes (`Macintosh HD`, `Macintosh HD - Data`, `Preboot`, `Recovery`, `VM`).
- **Resolution Algorithm**:
  1. Inspect `mount` table for `/` and `/System/Volumes/Data`.
  2. Query `diskutil info -plist` on the mounted node to extract `APFSPhysicalStores` or `APFSContainerReference`.
  3. Strip partition slice suffixes (e.g. `disk0s2` -> `disk0`).
  4. Tag physical disk `disk0` as protected system disk.

### 2.4 Write-Blocker VID/PID Detection Logic Confirmation (§24)
- **Question**: Does Conversation 01's OS-agnostic write-blocker detection logic (`check_write_blocker` in `detection.rs`) work unmodified on macOS, or does it require macOS-specific adaptation?
- **Finding & Confirmation**:
  - `check_write_blocker` is **100% OS-agnostic** and was integrated **completely unmodified**.
  - Its three-tier hierarchy operates as follows:
    1. *Tier 1 (Exact VID/PID)*: Matches numeric `(vid, pid)` against the known signature table (`Tableau`, `WiebeTech`, `Coolgear`).
    2. *Tier 2 (Vendor/Model Keyword Heuristic)*: Matches substring signatures (`TABLEAU`, `WIEBETECH`, `FASTBLOC`, `WRITEBLOCK`, `WRITE-BLOCK`, `CRU DITTO`) across `vendor` and `model` strings.
    3. *Tier 3 (OS Read-Only Status)*: Flags write-protection if the OS marks the device read-only (`Writable: false`).
  - *macOS Subsystem Adaptation in `vajra-device`*:
    - `diskutil info -plist` directly provides `DeviceVendor` and `DeviceModel`, immediately triggering Tier 2 keyword detection.
    - To achieve full Tier 1 parity, `macos/mod.rs` implements `query_usb_vid_pid(disk_id)` to recursively parse `system_profiler SPUSBDataType -json` / IOKit USB trees for exact hexadecimal vendor and product IDs.
    - Verified via unit test `test_macos_usb_vid_pid_and_write_blocker_integration`: correctly identifies a Tableau T8u bridge (`0x0ECF:0x0003`) with `WriteBlockerDetectionMethod::KnownVidPid`, and falls back to keyword heuristic when VID/PID is absent.
  - *Phase B Item*: Physical confirmation with an actual hardware write-blocker attached to the Mac.

---

## 3. Static Verification & Cross-Compilation Results

### 3.1 macOS Target Type-Checking (`cargo check`)
Executed via `rustup` cross-compilation targets on development host:
- **`x86_64-apple-darwin` (Intel Macs)**:
  - Command: `cargo check --target x86_64-apple-darwin -p vajra-device`
  - Result: **SUCCESS** (0 errors, 0 warnings).
- **`aarch64-apple-darwin` (Apple Silicon M1/M2/M3/M4 Macs)**:
  - Command: `cargo check --target aarch64-apple-darwin -p vajra-device`
  - Result: **SUCCESS** (0 errors, 0 warnings).

### 3.2 Workspace Cross-Compilation Boundary Note
- When running `cargo check --target x86_64-apple-darwin --workspace`, pure Rust crates (`vajra-device`, `vajra-core`, `vajra-raid`, `vajra-crypto-vol`, `vajra-image`, `vajra-fs-*`, `vajra-carve`, `vajra-ml`, `vajra-verify`) check cleanly.
- Workspace-level cross-checking of C-dependent crates (`libsqlite3-sys` in `vajra-case-db` and `ring` in `rustls`) fails on the Linux host during `build.rs` execution because the Linux host compiler `cc` does not accept Apple Darwin Clang flags (`-arch x86_64`, `-mmacosx-version-min=10.7`). Full native compilation will be performed directly on the real Mac in Phase B using native Apple Clang and Xcode command-line tools.

### 3.3 Host Workspace Test Suite
- Command: `cargo test --workspace` (on dev host)
- Result: **100% PASSING** (all unit and integration tests passing across all 19 workspace crates, including new macOS plist parser, APFS container unwrap tests, path normalizer tests, and USB VID/PID write-blocker integration tests).

---

## 4. PHASE B — TO DO WHEN THE MAC IS AVAILABLE (Prioritized Verification Checklist)

When physical macOS hardware becomes available, the following test matrix must be executed natively:

- [ ] **1. PHYSICAL USB & SD CARD REAL-HARDWARE TEST (HIGHEST HARDWARE PRIORITY — CARRIED FROM CONV 01 & 09)**:
  - Attach a real physical USB flash drive and an external SD card (via internal card slot or USB reader) to the Mac.
  - Run `vajra-cli list` and confirm authentic non-"Virtual Disk" vendor/model strings (e.g. `SanDisk`, `Kingston`, `Samsung`).
  - Verify `MediaType::Usb` and `MediaType::SdCard` heuristic assignments on real physical hardware.
  - Compute deterministic SHA-256 fingerprint on external media and verify sector 0 inspect.
- [ ] **2. Boot-Disk Detection & Safety Gate (HIGHEST ARCHITECTURAL PRIORITY)**:
  - Execute `vajra-cli list` on the native Mac and verify the internal drive (e.g. `disk0` / `/dev/rdisk0`) is correctly tagged with `is_system_disk: true` (`[Protected System Disk]`).
  - Verify that `DeviceConfirmationGate` correctly and unconditionally hard-blocks any sanitization attempt against the host Mac's system disk with zero code changes.
- [ ] **3. Native Compilation & Toolchain**:
  - Run `cargo build --workspace` natively on the Mac using Apple Clang / Xcode command-line tools.
  - Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] **4. Real Internal Hardware Enumeration & Fingerprint**:
  - Inspect output of `vajra-cli list` on internal Apple SSD (Apple Fabric NAND / PCIe NVMe) to confirm model string, capacity, serial number, and `MediaType::Nvme` classification.
  - Compute deterministic SHA-256 fingerprint via `vajra-cli fingerprint /dev/rdisk0`.
- [ ] **5. Raw Sector 0 Inspection (`/dev/rdiskN`)**:
  - Run `vajra-cli inspect /dev/rdisk0` (with `sudo`) and confirm unbuffered sector 0 read (GPT / protective MBR hex dump) succeeds with exact-byte alignment.
  - Confirm unprivileged execution cleanly returns `IoError::PermissionDenied`.
- [ ] **6. SMART & Health Diagnostics Telemetry**:
  - Run `vajra-cli health /dev/rdisk0` and observe what telemetry is returned:
    - Native `SMARTStatus` (Verified/Failing) on internal Apple SSD.
    - Extended `smartctl` metrics if Homebrew `smartmontools` is installed.
- [ ] **7. SIP Enforcement Empirical Confirmation**:
  - Confirm empirical behavior of macOS SIP when raw sector writes to `/dev/rdisk0` are attempted (expected: `EPERM` / Operation not permitted even as root).
- [ ] **8. Hardware Write-Blocker Verification**:
  - Connect a physical forensic hardware write-blocker (Tableau, WiebeTech, or Coolgear) to the Mac.
  - Verify `vajra-cli list` detects `is_write_blocked: true` via `query_usb_vid_pid` matching or vendor keyword heuristic.
- [ ] **9. Phase B Log Wrap-Up**:
  - Create `docs/agent-log/10-macos-device-support-phase-b.md` documenting the real terminal outputs, hardware serials, and test results from the native Mac run.

