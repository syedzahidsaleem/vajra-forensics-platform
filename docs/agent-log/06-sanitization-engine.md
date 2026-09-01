# Agent Log: Conversation 06 — Sanitization Engine (`vajra-erase`, `vajra-file-erase`)

## Scope Summary
Conversation 06 implements **Module 1 (`vajra-erase`)** and **Module 2 (`vajra-file-erase`)**, delivering NIST SP 800-88 Rev. 2 / IEEE 2883-2022 compliant media sanitization and filesystem-aware selective file erasure capabilities (§33a–§38, §43).

---

## 1. Safety Architecture: Device Identity Confirmation Gate (§43)

### Temporal Two-Phase Separation & Bypass Resistance
Per §43's strict requirement that dual confirmations cannot be satisfied with a single prompt or combined call:
1. `DeviceConfirmationGate::begin(device, operator_id, typed_serial, initial_confirm) -> Result<PendingSanitization, GateError>`
   - Unconditionally blocks OS/system disks (`is_system_disk == true`).
   - Unconditionally blocks devices with active write blockers (`write_blocker_info.is_some()`).
   - Verifies `typed_serial == device.serial` (exact match).
   - Verifies `initial_confirm == true`.
   - Returns a `PendingSanitization` ticket.
2. `PendingSanitization::finalize(self, pre_exec_confirm: bool) -> Result<SanitizationAuthorizationToken, GateError>`
   - Consumes `self` by value (single-use; cannot be finalized twice).
   - Verifies `pre_exec_confirm == true` immediately before write calls commence.
   - Mints the unforgeable `SanitizationAuthorizationToken`.

### Capability-Token Enforcement
All destructive entry points across `vajra-erase` require `&SanitizationAuthorizationToken` as a parameter. It is structurally impossible to invoke whole-device sanitization without passing through both phases of the gate.

### Automated Gate Tests
- `test_system_disk_unconditional_hard_refusal`: Proves OS system disks are rejected before confirmation.
- `test_write_blocker_unconditional_refusal`: Proves write-blocked devices are rejected before confirmation.
- `test_serial_mismatch_refusal`: Proves mistyped serial numbers fail Phase 1.
- `test_temporal_separation_enforcement`: Proves the requirement of `begin()` followed by `finalize(true)`.
- `test_gate_bypass_resistance_single_call_impossibility`: Proves that `DeviceConfirmationGate` exposes no single-step constructor for `SanitizationAuthorizationToken`, and rejecting `pre_exec_confirm: false` leaves no valid token.

---

## 2. Destructive Naming & Doc-Comment Convention

To allow mechanical auditing of every destructive code path in the codebase (e.g. via `grep -rn "_destructive" crates/` or `grep -rn "DESTRUCTIVE OPERATION" crates/`), the following conventions are strictly applied:
1. Every function that writes block data, overwrites files, or issues hardware sanitize commands ends with the suffix `_destructive`.
2. Every such function contains the doc-comment header:
   ```rust
   /// [DESTRUCTIVE OPERATION (§43)]
   /// Requires `&SanitizationAuthorizationToken` capability token (or explicit local file confirmation).
   ```

---

## 3. Sanitization Decision Engine & §33a Assurance Structural Capping

### Decision Engine Recommendations (§34)
- **SED / Opal**: Recommends `CryptographicErase` (TCG Opal PSID Revert) — sub-second controller-native key destruction sidestepping FTL wear-leveling.
- **NVMe SSD**: Recommends `NvmeSanitizeBlock` — purges all namespaces and physical NAND blocks (including reallocated/over-provisioned pools).
- **SATA SSD**: Recommends `AtaEnhancedSecureErase` — vendor-defined NAND cell purge across wear-leveling pools.
- **HDD**: Recommends `HostOverwriteSinglePass` (NIST SP 800-88 Clear).
- **USB / Flash Fallback**: Emits mandatory **Residual Risk Caveat (§33a)** stating that host overwrite cannot reach wear-leveled / over-provisioned NAND blocks.

### §33a Certificate Honesty & Structural Assurance Cap
Per §33a and NIST SP 800-88 §2.4, host-level logical overwrites cannot address unmapped, wear-leveled, or over-provisioned NAND flash blocks managed by the device controller (FTL).
- **Rule**: Whenever the sanitization method is a host overwrite (`HostOverwriteSinglePass` or `HostOverwriteMultiPass`) against flash-based media (`MediaType::Nvme`, `MediaType::SataSsd`, `MediaType::Usb`, `MediaType::SdCard`), `OverallAssurance` is structurally capped at **MEDIUM** (never HIGH), even if all 5 verification layers report clean.
- **Certificate Integration**: `SanitizationCertificate::generate` automatically embeds the §33a Residual Risk Disclosure whenever flash media is subjected to host-level overwrite.
- **Controller-Native Purge**: Achieving **HIGH** assurance on flash media requires controller-native commands (`NvmeSanitizeBlock`, `AtaEnhancedSecureErase`, or `CryptographicErase`).

---

## 4. Multi-Layer Verification Suite, Layer 5 Override & RNG Reproducibility (§37)

Implements all five verification layers:
1. **Layer 1 (Command Level)**: Exit status confirmation.
2. **Layer 2 (Device Status)**: Controller post-operation ready state.
3. **Layer 3 (Deterministic)**: Verified read on critical sample LBAs (LBA 0, partition boundaries).
4. **Layer 4 (Statistical Sampling)**: Hypergeometric-corrected finite-population sampling formula:
   $$n \approx \left[1 - (1 - C)^{\frac{1}{N \cdot p}}\right] \cdot N$$
   - **Reproducibility**: Supported via `verify_layer4_with_seed` and `verify_sanitization_with_seed`. In `test_layer5_isolated_override_scenario`, seed `0xCAFE_BABE_DEAD_BEEF` is used to make the test's sampled sectors 100% deterministic and reproducible on every run.
5. **Layer 5 (Independent Recovery Scan)**: Invokes `vajra-carve`'s `RecoveryPipeline`.
   - **Resolution Override Rule**: If Layer 5 recovers $\ge 1$ artifact, overall assurance is forced to **FAILED**, regardless of Layers 1–4.
   - **Pure Isolation Test (`test_layer5_isolated_override_scenario`)**: Proves the exact scenario where Layers 1–4 ALL report PASS, but Layer 5 detects a residual artifact outside the sample set (at LBA 1500), overriding overall assurance to **FAILED**.

---

## 5. File Erasure Primitives: `file_eraser.rs` vs `local_eraser.rs` Resolution

Module 2 contains two distinct, purpose-built file erasure primitives:

### 1. Live OS Host File Erasure (`local_eraser.rs` / `erase_local_file_destructive`)
- **Direct CLI Call Site**: `vajra-cli file-erase run <FILE_PATH> [--passes N]`
- **Source Proof (`main.rs`)**:
  ```rust
  "file-erase" => {
      match filtered_args[1].as_str() {
          "run" => {
              let file_path = &filtered_args[2];
              let passes = parse_passes(&filtered_args);
              cmd_file_erase_run(file_path, passes);
          }
      }
  }
  ```
  Inside `cmd_file_erase_run`:
  ```rust
  let erased_bytes = erase_local_file_destructive(file_path, passes)?;
  ```
- **Execution Workflow**:
  1. Validates file existence and resolves byte length via OS metadata.
  2. Executes multi-pass ChaCha20 CSPRNG overwrites (with final pass NIST 0x00) and calls OS `fsync()` after every pass.
  3. Truncates file length to 0 bytes (`file.set_len(0)` + `sync_all()`).
  4. Unlinks directory entry via `std::fs::remove_file()`.
  5. Verifies path non-existence.
- **Honest Scope Reporting**: Discloses that on an active mounted OS filesystem, block allocation and journal references are managed by the host OS kernel and VFS layer.

### 2. Block-Device & Image Filesystem-Aware Pipeline (`file_eraser.rs` / `execute_file_erasure_pipeline_destructive`)
- **Target**: Block devices and unmounted forensic disk images (`&mut dyn WritableBlockSource`).
- **Execution Workflow**: 6-step pipeline: (1) Extent resolution via `vajra-fs-*`, (2) Data extent overwrite, (3) Metadata zeroing, (4) Journal scrubbing ($LogFile, $UsnJrnl, jbd2), (5) **Free-After-Overwrite Ordering Rule** (crash-safe space deallocation only after writes are flushed), and (6) **Five-State Residual Scanner**.
- **Automated Tests**: Tested for crash safety and residual detection in `tests/file_erase_tests.rs::test_free_after_overwrite_ordering_and_crash_safety`.

---

## 6. Honest Hardware Testing Scope Statement

> [!NOTE]
> In accordance with the project's absolute standing safety rule, ATA Secure Erase, NVMe Sanitize, and TCG Opal Cryptographic Erase command construction and execution paths are implemented and tested against **in-memory simulated block devices (`MockWritableDevice`)**. They are genuinely **untested against real physical hardware** in this environment to prevent catastrophic destruction of the host workstation's storage.
