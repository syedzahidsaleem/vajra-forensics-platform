---

## 0. Standing Project Safety Rule (Binding Invariant)

> [!CAUTION]
> **DESTRUCTIVE TESTING SAFETY INVARIANT (MANDATORY FOR ALL FUTURE CONVERSATIONS)**:
> Destructive testing (actual overwrite, block zeroing, pattern overwriting, ATA Secure Erase, NVMe Format/Sanitize, cryptosecure erase, or TRIM/Deallocate operations) must **NEVER** be executed against the primary development machine's own internal storage drives, system board, or operating system volumes — only against explicitly designated spare, scratch, or isolated virtual test devices set aside specifically for that purpose.
> 
> Read-only operations (`enumerate_devices`, `fingerprint`, `inspect`, `health`, `ReadOnlyBlockSource::read_blocks`) are non-destructive, safe, and exempt from this restriction as they never issue write commands.
> 
> This rule is permanently binding across all development sessions (most critically Conversation 6: Sanitization Engine).

---

## 1. Summary of What Was Built

1. **Authoritative Rust Cargo Workspace Scaffolding (§16)**:
   - Scaffolding of the entire 20-crate workspace tree per §16.
   - Implemented crates: `vajra-core`, `vajra-device`, `vajra-cli`.
   - Stub member crates with documentation and `#![allow(dead_code)]`: `vajra-raid`, `vajra-crypto-vol`, `vajra-image`, `vajra-fs-ntfs`, `vajra-fs-ext4`, `vajra-fs-apfs`, `vajra-fs-fat`, `vajra-acquire`, `vajra-erase`, `vajra-file-erase`, `vajra-carve`, `vajra-ml`, `vajra-audit`, `vajra-custody`, `vajra-case-db`, `vajra-verify`, `vajra-tauri-app`.
   - Full workspace clean build (`cargo build --workspace`), zero Clippy warnings (`cargo clippy --workspace --all-targets -- -D warnings`), and 19 passing unit/integration tests.

2. **`vajra-core` (Domain Traits, Types & Errors — §16, §23, §24, §35)**:
   - **`ReadOnlyBlockSource`**: Core read-only trait implemented by physical drives, forensic images, decrypted volumes, and RAID arrays.
   - **`WritableBlockSource`**: Dedicated trait extending `ReadOnlyBlockSource`, implemented *only* by physical drives opened in explicit sanitization contexts.
   - **`MediaType`**: Storage classification enum (`Hdd`, `SataSsd`, `Nvme`, `Sed`, `Usb`, `SdCard`, `ForensicImage`).
   - **`IoError`**: Structured `thiserror` enum covering device discovery, LBA-level read/write failures, alignment errors, permission errors, and disconnection events.
   - **`DeviceFingerprint`**: Deterministic SHA-256 identity calculation (§23).
   - **`WriteBlockerMetadata`**: Detailed write-blocker detection attributes and detection methods (§24).
   - **`SanitizeMethod`**: Sanitization primitive specifications (§35).

3. **`vajra-device` (Hardware Enumeration, Diagnostics & Sector I/O — §23, §24)**:
   - **`PhysicalDrive`**: Concrete struct implementing **ONLY** `ReadOnlyBlockSource`. Structurally incapable of issuing writes.
   - **`WritablePhysicalDrive`**: Concrete struct implementing `WritableBlockSource` (and `ReadOnlyBlockSource`), accessible only via `WritablePhysicalDrive::open_writable()`.
   - **Windows OS Layer**:
     - Device discovery via `\\.\PhysicalDriveN` and `IOCTL_STORAGE_QUERY_PROPERTY` (`STORAGE_DEVICE_DESCRIPTOR`).
     - Dual-mode handle opening: standard user execution accesses hardware identity and geometry, while raw sector I/O strictly enforces Administrator elevation.
     - Disk geometry & capacity via `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`.
     - NVMe SMART/Health Information Log via `StorageAdapterProtocolSpecificProperty` (Log Page 0x02).
     - ATA SMART attributes via `IOCTL_STORAGE_PREDICT_FAILURE`.
     - System/boot drive detection via `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` on `C:`.
     - Unbuffered sector I/O via `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` with 4096-byte aligned buffers.
   - **Linux OS Layer**:
     - Device discovery via `/sys/block/*` sysfs traversal.
     - Unique controller serial extraction via `device/serial`, `serial`, `device/wwid`, and `/dev/disk/by-id/`.
     - System/boot disk detection via recursive device-mapper slave traversal (`/sys/block/dm-*/slaves`) against `/proc/mounts`.
     - Direct sector I/O using `O_DIRECT` with fallback to buffered I/O and page cache eviction (`POSIX_FADV_DONTNEED`), cross-verified against `reference/nwipe` C architecture.
   - **Write-Blocker Detection (§24)**:
     - Known VID/PID database for Tableau/OpenText (T8, T8u, T35u, T7u, T9, T6u, T35689iu), CRU/WiebeTech (UltraDock, DriveLock, DittoBeam, ToughTech), Coolgear/ASMedia.
     - Vendor string heuristic matching and OS read-only status detection.
   - **Health Diagnostics (§23)**:
     - HDD attribute parsing (reallocated, pending, uncorrectable sectors, temperature, power-on hours).
     - NVMe metric parsing (critical warnings, composite temperature, available spare percentage, percentage used, media errors).
     - Calibrated threshold engine producing plain-language forensic recommendations.

4. **`vajra-cli` (Validation & Diagnostic Tool)**:
   - CLI tool supporting `list`, `fingerprint`, `health`, and `inspect <device>` (read-only LBA 0 hex-dump smoke test).
   - Validated on real physical and virtual drives on Windows and Linux (WSL).

---

## 2. Key Architectural Decisions & Rationales

### 2.1 Type-Level Safety Split (`PhysicalDrive` vs `WritablePhysicalDrive`)
- **Problem**: If a single `PhysicalDrive` struct implemented both `ReadOnlyBlockSource` and `WritableBlockSource`, any forensic recovery function receiving `&mut PhysicalDrive` would still have a syntactically callable `.write_blocks()` method on the concrete struct.
- **Decision**: Created two distinct types:
  - `PhysicalDrive`: implements **ONLY** `ReadOnlyBlockSource`. It has no `.write_blocks()` method and no `WritableBlockSource` implementation.
  - `WritablePhysicalDrive`: implements `WritableBlockSource` (and `ReadOnlyBlockSource`).
- **Consequence**: Recovery, carving, and analysis modules cannot write to evidence, as the compiler forbids calling `.write_blocks()` on `PhysicalDrive` or `&mut dyn ReadOnlyBlockSource`.

### 2.2 Device Fingerprinting Excludes `interface` from Hash Input (§23)
- **Problem**: An external drive connected directly via SATA vs. through a USB-to-SATA bridge reports different interface bus types across sessions. If `interface` were included in the SHA-256 hash input, the drive would produce a differing fingerprint hash across sessions, breaking identity re-confirmation in §43.
- **Decision**: `DeviceFingerprint.sha256_hash` is computed strictly from normalized `serial`, `model`, `capacity_bytes`, and boundary sector data (LBA 0). `interface` is preserved as a struct field on `DeviceFingerprint` for display/reporting, but excluded from the SHA-256 computation.

### 2.3 System Boot Drive Detection & LVM / Device-Mapper Resolution (§24)
- **Linux**: Rather than shallow string matching against `/proc/mounts`, `vajra-device` implements recursive slave traversal via `/sys/block/dm-*/slaves/` and canonical mapper resolution. If root (`/`), `/boot`, or `/home` is mounted on an LVM Logical Volume, LUKS encrypted container, or software RAID, `check_if_system_disk` recursively unwraps the device-mapper hierarchy to the underlying physical partition and disk (e.g. `dm-0` -> `sda2` -> `sda`).
- **Windows**: Queries `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` against `\\.\C:` to identify the physical drive index of the Windows OS boot disk.
- **Wording**: On a system disk without a hardware write-blocker, the CLI displays: `"No write-blocker detected — OS-level enforcement not yet implemented (deferred to Safety/Policy Engine)"` rather than claiming Direct R/W Access.

### 2.4 Unbuffered Sector I/O, Alignment & Short-Read Prevention
- **Decision**: All low-level read/write buffers use `AlignedBuffer` allocated with 4096-byte memory alignment (`Layout::from_size_align`).
- **Windows**: Opened with `FILE_FLAG_NO_BUFFERING`. `read_blocks` explicitly validates `bytes_read == requested_bytes` and returns a hard `IoError::ReadFailureAtLba` error on any short read (zero silent short reads or partial zero buffers).
- **Linux**: Uses `O_DIRECT` with fallback to buffered I/O + `posix_fadvise(POSIX_FADV_DONTNEED)`. Uses `read_exact` to guarantee complete sector buffer population.
- **Source Alignment**: Checked directly against `reference/nwipe/src/device.c`.

---

## 3. Real Empirical Testing & Verification Findings

### 3.1 Native Windows Verification (Physical Samsung NVMe SSD)
- **Device Tested**: `\\.\PhysicalDrive0` (Samsung MZVL81T0HFLB-00BH1, 1.02 TB NVMe SSD).
- **Serial Number**: `0025_38F4_51B3_DC6A.` (retrieved via `STORAGE_DEVICE_DESCRIPTOR`).
- **Deterministic SHA-256 Fingerprint**: `c51b430363f618e1965f2f891fc767d5576064169b23b6ff57398d2cc9e33b79`.
- **Dual-Mode Access Verified**:
  - Standard user execution: successfully queries hardware model, serial number, and capacity without elevation.
  - Sector inspection (`inspect`) and SMART query (`health`): strictly enforces administrator elevation (`IoError::PermissionDenied`).

### 3.2 Linux Environment Findings & Hardware Status
- **Host Setup**: The Linux testing environment runs on Ubuntu WSL 2 over Windows 11 Hyper-V storage controllers (`/dev/sda` through `/dev/sdd`). Bare-metal Linux hardware was not attached in this host environment.
- **Serial Retrieval**: Confirmed retrieval of unique SCSI WWID identifiers (`naa.60022480ad4cc93734533f3aaddd1f65` on `/dev/sdd`) via `/sys/block/<dev>/device/wwid`.
- **USB & SD Card Heuristics & Known Limitation**:
  - No physical USB flash drives or external SD card readers were plugged in during test execution.
  - **Heuristic**: When an SD card is attached via a USB reader, if the descriptor contains "Card", "SD", "MMC", or sysfs exposes `/mmc` or `mmcblk*`, `vajra-device` correctly maps `MediaType::SdCard`. If a generic USB card reader reports only generic USB mass storage without card-reader descriptors, it defaults to `MediaType::Usb`. This is an inherent hardware reporting boundary on generic USB bridges.

### 3.3 LVM / Device-Mapper Slave Traversal Terminal Transcript
Verified with live `dmsetup` dm-linear volume mounted in Linux:
```
=== 1. Creating backing disk and loop device ===
Backing disk attached as: /dev/loop0 (Base device: loop0)

=== 2. Creating Device-Mapper Linear Target (simulating LVM/LUKS) ===
Device-mapper node active: /dev/mapper/vajra_test_lvm_root

=== 3. Inspecting Sysfs Slave Hierarchy ===
Sysfs slaves path: /sys/block/dm-0/slaves
Underlying slave devices detected: ['loop0']

=== 4. Formatting and Mounting Target ===
Mounted /dev/mapper/vajra_test_lvm_root to /tmp/vajra_test_mount

=== 5. Verification Check ===
[PASS] Device-mapper target /dev/mapper/vajra_test_lvm_root successfully traces to physical base device loop0.

=== 6. Cleanup ===
All test resources cleanly unmounted and released.
```

### 3.4 Sector 0 Partition Table & MBR Inspection
Tested `inspect` on a partitioned block device with authentic MBR bootstrap code:
```
00000000  EB 3C 90 00 90 90 90 90  90 90 90 90 90 90 90 90  |.<..............|
...
000001B0  90 90 90 90 90 90 90 90  90 90 90 90 90 90 80 00  |................|
000001C0  01 00 83 00 01 00 00 08  00 00 00 40 00 00 00 00  |...........@....|
000001F0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 55 AA  |..............U.|

Valid Boot Record Signature detected at offset 0x01FE (0x55, 0xAA)
[PASS] Read-only block I/O verified successfully.
```

---

## 4. Open Issues / Notes for Next Conversation (Evidence Vault & Audit Log)

1. **Evidence Vault (`vajra-case-db`)**:
   - When creating case records, `cases.status` must follow the `Active -> Tombstoned` (or `Closed`) irreversible lifecycle (§22).
   - Forensic image paths and recovered artifact paths must be stored as metadata in SQLite/SQLCipher, never storing raw binary BLOBs inside the database (§17).
2. **Device Fingerprint Storage**:
   - `DeviceFingerprint.sha256_hash` (stored as 64-character hex string) should be indexed in the database schema to link physical evidence acquisitions to case ledgers.
3. **Chain of Custody vs Audit Log Split**:
   - `vajra-audit` (what the software did) and `vajra-custody` (who possessed the physical evidence) are two distinct crates per §21 and §39.
