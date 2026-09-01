# Conversation 09 — Advanced Storage Providers (`vajra-raid`, `vajra-crypto-vol`)

**Date**: 2026-09-01  
**Branch**: `syed-zahid`  
**Crates Built / Extended**: `vajra-raid`, `vajra-crypto-vol`, `vajra-core`, `vajra-cli`  
**Phase Context**: First conversation of the post-split team phase, continuing sequentially from the completed 8-conversation backend build (Conversations 01–08).

---

## 1. What Was Built

### A. `vajra-raid` (Advanced Software RAID Reconstruction Engine — §15 Part III, §16)
- **$GF(2^8)$ Galois Field Engine (`galois.rs`)**:
  - Implemented finite field arithmetic using canonical primitive polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
  - Precomputed 256-entry exponential, logarithmic, and multiplicative inverse tables.
  - Implemented vectorized $P$ (XOR) and $Q$ (Galois generator polynomial $g = 2$) dual-parity computations.
  - Single-disk failed reconstruction from $P$ or $Q$, and dual-disk failed reconstruction ($D_x, D_y$) by solving the linear equation system in $GF(2^8)$:
    $$P_{xy} = D_x \oplus D_y, \quad Q_{xy} = g^x D_x \oplus g^y D_y \implies D_y = \frac{Q_{xy} \oplus g^x P_{xy}}{g^y \oplus g^x}$$
- **Stripe Layout & Rotation Geometry (`layout.rs`)**:
  - Implemented `RaidGeometry` supporting **RAID 0 (striping)**, **RAID 5 (distributed single parity)**, and **RAID 6 (distributed dual $P+Q$ parity)**.
  - Supported all 4 canonical parity rotation layouts: `LeftSymmetric` (standard Linux default), `RightSymmetric`, `LeftAsymmetric`, and `RightAsymmetric`.
  - Deterministic forward and reverse address mapping: `logical_lba_to_disk_blocks` translating virtual array LBAs to disk member index and physical sector offsets across stripe boundaries.
- **Mdadm Superblock Parser & Prober (`superblock.rs`)**:
  - Probes Linux software RAID superblocks across standard offsets:
    - **1.2**: LBA 8 (offset 4096 bytes)
    - **1.1**: LBA 0 (offset 0 bytes)
    - **1.0**: 8–12 KiB before end of disk
  - Validates magic `0xa9280c09`, parses UUID, array level, layout, chunk size, device role number, and data offset.
  - Implemented `write_mdadm_1_2_superblock` serializer for synthetic testing and validation.
- **Virtual Block Device Implementation (`array.rs`)**:
  - Implemented `RaidArray: ReadOnlyBlockSource`.
  - Transparent on-the-fly degraded reconstruction when reading missing or unreadable member disks.
  - Deterministic virtual device fingerprint computation hashing member serials and geometry.

---

### B. `vajra-crypto-vol` (Lawful Encrypted Volume Decryption Engine — §16, §57)
- **Sector Cipher Abstraction (`cipher.rs`)**:
  - `SectorCipher` trait with sector LBA tweak calculation.
  - `Aes128XtsCipher` and `Aes256XtsCipher` using `xts-mode` and standard 128-bit little-endian sector LBA tweaks.
  - `AesCbcCipher` (AES-CBC-128 / AES-CBC-256) with sector LBA IV derivation for legacy volumes.
  - Anti-Forensic splitter merge algorithm (`af_merge`) and forward splitter (`af_split`) implementing the standard LUKS multi-stripe hash expansion.
- **LUKS1 Unlock Pipeline (`luks/luks1.rs`)**:
  - Parses binary header `b"LUKS\xba\xbe"`, MK digest salt, iteration counts, and 8 keyslots.
  - Derives slot password key via PBKDF2 (`Sha1` or `Sha256`), decrypts split material with AES-ECB, merges AF stripes, and validates candidate master key against recorded `mk_digest`.
  - Constructs `AesXtsCipher` and yields decrypted sector stream at payload offset.
- **LUKS2 Unlock Pipeline (`luks/luks2.rs`)**:
  - Parses JSON metadata area at offset 4096.
  - Supports Argon2id (`time`, `memory`, `cpus`) and PBKDF2 keyslots.
  - Decrypts key material, executes AFMerge, and verifies master key against JSON digest descriptors.
- **BitLocker (Full Volume Encryption) Pipeline (`bitlocker/fve.rs`)**:
  - Identifies `-FVE-FS-` OEM signature in Volume Boot Record (VBR).
  - Recovery key parser: normalizes 48-digit numerical strings (8 groups of 6 digits) and enforces Microsoft modulo-11 checksums per 6-digit block.
  - Derives VMK, validates against `vmk_hash`, unwraps FVEK, and instantiates sector cipher.
- **FileVault Detection & Scope Documentation (`filevault/mod.rs`)**:
  - Detects APFS encrypted container superblocks (`NXSB`) and Apple CoreStorage volume headers.
  - Documents explicit architectural scope limit (deferred to APFS object map expansion).
- **Virtual Decrypted Volume Implementation (`volume.rs`)**:
  - `EncryptedVolume<T: ReadOnlyBlockSource>` implementing `ReadOnlyBlockSource`.
  - Decrypts sectors on-the-fly during `read_blocks` while strictly preserving read-only safety invariants.

---

### C. Workspace & CLI Integration (`vajra-cli`, `vajra-core`)
- **`vajra-core`**:
  - Added transparent `impl<T: ?Sized + ReadOnlyBlockSource> ReadOnlyBlockSource for Box<T>`, enabling dynamic polymorphism across complex multi-layer storage stacks.
- **`vajra-cli` Subcommands**:
  - `raid detect <MEMBERS...>`: Probes and displays mdadm metadata across physical drives or image files.
  - `raid inspect <MEMBERS...> [--level 0|5|6] [--chunk KB] [--degraded IDX...]`: Assembles intact or degraded arrays and hex-dumps decrypted virtual LBA 0.
  - `crypto-vol unlock <SOURCE> [--password PW] [--recovery-key KEY]`: Lawfully unlocks LUKS / BitLocker volumes and validates sector decryption.

---

## 2. Key Decisions & Rationale

1. **Strict Lawful-Only Unlock Policy (§57)**:
   - Zero credential bypassing, brute-forcing, or dictionary guessing was implemented.
   - Any incorrect passphrase or recovery key immediately returns `CryptoVolError::AuthenticationFailed` with zero side effects.
2. **Read-Only Block Source Contract Invariant (§16)**:
   - Neither `RaidArray` nor `EncryptedVolume` implements `WritableBlockSource`. Write paths are strictly prohibited in the forensic layer.
3. **Multi-Layer Trait Composability**:
   - Because `RaidArray` and `EncryptedVolume` both implement `ReadOnlyBlockSource`, they compose arbitrarily without any glue code:
     $$\text{Physical Disks / RAW Images} \longrightarrow \text{RaidArray} \longrightarrow \text{EncryptedVolume} \longrightarrow \text{vajra-carve / vajra-fs}$$
   - Verified end-to-end in `cli_storage_tests.rs`: a 3-disk RAID 5 array with a missing member wrapped in an encrypted volume was passed directly into `RecoveryPipeline::run`, which successfully carved and verified an embedded PNG image.

---

## 3. Real-Tool Cross-Validation & Reference Testing (§15, §16, §57)

To ensure interoperability with real-world forensic evidence rather than only hand-written serializers, reference testing was conducted against authentic Linux forensic tooling (`cryptsetup 2.8.4`, `mdadm 4.5`, `libcryptsetup 2.8.4`):

### 3.1 Real-Tool Findings vs. Self-Serialized Tests

| Storage Format | Reference Tool Status | Method & Outcome | Discrepancies Discovered & Fixed |
|---|---|---|---|
| **LUKS2** | **Genuine Real-Tool (`cryptsetup 2.8.4`)** | Formatted 32MB volume (`luks2_real.raw`) using `cryptsetup luksFormat --type luks2 --pbkdf argon2id`. Extracted ground-truth Master Key via `libcryptsetup.so.12` (`crypt_volume_key_get`). | **1. Base64 vs Hex**: Real LUKS2 JSON metadata encodes `salt` and `digest` in Base64 rather than hex. Fixed by integrating `base64` crate.<br>**2. AFMerge IV**: Standard LUKS specification (RFC 7634) defines IV as a single 32-bit big-endian integer ($\text{iv} = i \cdot B + j$), whereas initial code wrote two 32-bit ints. Fixed in `af_merge`. |
| **LUKS1** | **Genuine Real-Tool (`cryptsetup 2.8.4`)** | Formatted 32MB volume (`luks1_real.raw`) using `cryptsetup luksFormat --type luks1`. Verified headers via `cryptsetup luksDump` and ground-truth key retrieval via `libcryptsetup`. | **1. Keyslot Cipher**: Fixed keyslot area decryption to support AES-XTS (standard in modern cryptsetup LUKS1) alongside ECB/CBC.<br>**2. PBKDF2 Iterations**: `cryptsetup` generated 6.2M PBKDF2 iterations by default, highlighting CPU cost during debug-mode derivation. |
| **Linux Software RAID (mdadm)** | **Self-Serialized + Structural Mdadm Validation** | Evaluated `mdadm --create` against loopback files. In this unprivileged WSL2 environment, `mdadm --create` fails with `Cannot get size of /tmp/b0: Inappropriate ioctl for device` due to kernel `BLKGETSIZE64` ioctl requirements. Array layout, parity distribution, and superblock parsing were tested via exact mdadm 1.2 on-disk structure serialization. | Validated RAID 0, 5, 6 geometry, Left/Right Symmetric/Asymmetric parity rotation, and $GF(2^8)$ dual-parity reconstruction across single and dual failure modes. |
| **BitLocker FVE** | **Structural Header & Modulo-11 Validation** | Evaluated against authentic BitLocker Volume Boot Record (`-FVE-FS-`) layouts and 48-digit Microsoft modulo-11 numerical recovery keys. | Live TPM-bound BitLocker volume generation was not available in Linux user-space without Windows BitLocker administrative provisioning; documented honestly as an environment limitation. |

---

## 4. Physical Storage Device Diagnostic Run (Host Verification)

Executed `vajra-cli list` and `vajra-cli fingerprint` against connected storage drives:
- **Discovered Storage Units**:
  - `/dev/sdd`: 1.10 TB Virtual Disk (`naa.60022480ad4cc93734533f3aaddd1f65`), OS Boot Disk, SHA-256: `ef5a0e44...`
  - `/dev/sdb`: 167.24 MB Virtual Disk (`naa.600224806ca9c06d835376681e4a916b`), OS Read-Only Mount Active, SHA-256: `c6fe9a9a...`
  - `/dev/sdc`: 3.22 GB Virtual Disk (`naa.60022480316191b98b3acdfc6d10df62`), Non-System Storage, SHA-256: `cf1380b8...`
  - `/dev/sda`: 374.25 MB Virtual Disk (`naa.60022480df18deb7e179255b7b21f6fa`), OS Read-Only Mount Active, SHA-256: `52679473...`
- **Safety Invariant Verified**: Non-root `inspect` on raw physical device nodes cleanly and safely halts with `IoError::PermissionDenied` (`Elevated administrator privileges required`).

---

## 5. Verification & Test Summary

All workspace tests pass 100% with zero warnings or errors:


- `vajra-raid`:
  - `test_raid0_intact_reconstruction_and_boundary_reading`: PASSED
  - `test_raid5_intact_and_degraded_xor_reconstruction`: PASSED
  - `test_raid6_dual_parity_intact_and_dual_degraded_reconstruction`: PASSED (Single and dual drive failure recovery via $GF(2^8)$)
  - `test_mdadm_superblock_detection_and_auto_assembly`: PASSED
- `vajra-crypto-vol`:
  - `test_luks1_unlock_success_and_wrong_passphrase_failure`: PASSED
  - `test_luks2_argon2id_unlock_and_wrong_passphrase_failure`: PASSED
  - `test_bitlocker_recovery_key_unlock_and_modulo11_validation`: PASSED (Validates 48-digit modulo-11 and correct/wrong key behavior)
  - `test_composability_encrypted_volume_over_reconstructed_raid5`: PASSED
- `vajra-cli`:
  - `test_e2e_raid_superblock_creation_detection_and_assembly`: PASSED
  - `test_e2e_carving_directly_from_encrypted_volume_over_degraded_raid`: PASSED (Demonstrates end-to-end multi-crate forensic carving on degraded encrypted storage)
