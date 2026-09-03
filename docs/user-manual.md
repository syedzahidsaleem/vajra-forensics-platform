# Vajra User Manual

**Version:** CLI / backend edition
**Applies to:** the `vajra-forensics-platform` workspace, version `0.1.0`
**Verified on:** 2026-09-01, Linux x86-64, `rustc 1.95.0` / `cargo 1.95.0`
**Author:** Vaibhavi — Documentation & Additional File-Type Support

> **Every command example in this manual was actually executed and its output pasted verbatim.** Nothing is transcribed from the source's own help text, and nothing is described as it "should" behave. Where a workflow could not be run to completion in the documentation environment, the manual says so explicitly and shows the real error rather than inventing a successful transcript.

---

## Table of contents

1. [About Vajra](#1-about-vajra)
2. [Current manual scope](#2-current-manual-scope)
3. [Requirements](#3-requirements)
4. [Build and run](#4-build-and-run)
5. [CLI overview](#5-cli-overview)
6. [Creating and managing a case](#6-creating-and-managing-a-case)
7. [Device identification and fingerprinting](#7-device-identification-and-fingerprinting)
8. [Evidence acquisition](#8-evidence-acquisition)
9. [Filesystem analysis](#9-filesystem-analysis)
10. [File recovery and carving](#10-file-recovery-and-carving)
11. [Reports](#11-reports)
12. [Independent report verification](#12-independent-report-verification)
13. [Sanitization](#13-sanitization)
14. [Known limitations](#14-known-limitations)
15. [Troubleshooting](#15-troubleshooting)
16. [UI guide — TODO](#16-ui-guide--todo)
17. [Quick demo workflow](#17-quick-demo-workflow)

---

## 1. About Vajra

Vajra is an **offline-first digital forensics and secure data sanitization platform**. It is a single standalone application that operates on directly connected physical storage devices and on locally accessible forensic disk images. There is no server, agent, network share, or cloud component anywhere in the design — everything runs on one machine, against media physically attached to it.

The platform has two clearly separated operational tracks that share one device abstraction, one case/evidence model, and one cryptographic audit and reporting engine:

**Forensic track.** Identify and fingerprint a storage device, acquire it to a forensic image with cryptographic verification, parse surviving filesystem metadata to recover deleted files, carve unallocated space for files whose metadata is gone, and produce a signed report that a third party can verify independently.

**Sanitization track.** Fingerprint a device, get a media-appropriate sanitization recommendation, execute it behind a two-phase confirmation gate, verify the result through five independent layers, and issue a certificate.

The idea that connects the two halves is the **sanitization assurance loop**: the fifth verification layer runs the platform's *own* recovery engine against the just-sanitized device. If the carver finds anything, sanitization is reported as failed regardless of what the earlier layers said. That is a live, visible use of the forensics engine to prove the sanitization worked, rather than trusting the erase command's own self-report.

Safety is enforced by the Rust type system rather than by convention. Sources opened for forensic work implement a trait that has **no write method at all**, so writing to evidence during acquisition or carving is a compile error, not a runtime check.

---

## 2. Current manual scope

**This edition documents the command-line interface and the backend engines only.**

A desktop UI built with Tauri is under active development by other members of the team. The workspace already contains the `vajra-tauri-app` crate, but at the time of writing it holds only a `main.rs` stub and there is no user-facing interface to document.

Accordingly:

- **In this edition:** the full `vajra-cli` command surface and the standalone `vajra-verify` tool. **Commands that were safe to run in the documentation environment were command-verified, and their real captured output is reproduced here.**
- **Not command-verified:** commands that depend on raw physical-device access could not be completed in the documentation environment. **These are explicitly marked wherever they appear, and no successful transcript is shown for them** — only the actual error that was produced. See sections [7.4](#74-read-only-block-io-smoke-test) and [8.2](#82-starting-an-acquisition).
- **Deferred to a later edition:** screenshots, click-by-click walkthroughs, screen inventory, and any UI-based version of the demo flows. See [section 16](#16-ui-guide--todo).

**Do not read this manual as evidence that every documented workflow has been proven end to end.** It is a mix of workflows demonstrated with captured output and workflows whose commands are documented from source but which remain unproven against real hardware. The table below states which is which.

### 2.1 Verification status

| Area | Status |
|---|---|
| Case management | **Verified** |
| Device enumeration / fingerprinting | **Verified for metadata enumeration** |
| Physical raw-device block I/O | **Not successfully verified in documentation environment** |
| Physical evidence acquisition | **Not successfully verified; real-hardware test pending** |
| Image integrity verification | **Verified** |
| Filesystem analysis / recovery | **Verified** |
| JPEG / PNG / PDF / ZIP / SQLite carving | **Verified on repository synthetic corpus** |
| OLE2 structural validator | **Verified on synthetic OLE2 file** |
| OLE2 precision / recall corpus benchmark | **Pending coordination with Akanksha** |
| Report generation | **Verified** |
| Independent report verification / tamper detection | **Verified** |
| Sanitization mock workflow | **Verified** |
| Physical-device sanitization | **Not tested** |
| Tauri UI | **Pending UI integration** |

"Verified" means the command was executed during the preparation of this manual and its output captured. It does **not** mean the feature has been validated against real evidence media, or benchmarked, or reviewed for forensic soundness.

Once the UI is integrated, sections 6–13 should each gain a short "In the UI" subsection alongside the CLI instructions, rather than being replaced by them — the CLI remains the reference interface and the one used for automated testing.

---

## 3. Requirements

### 3.1 Toolchain

| Requirement | Detail |
|---|---|
| Rust toolchain | Edition 2021. Verified with `rustc 1.95.0` / `cargo 1.95.0`. The repository contains **no** `rust-toolchain.toml`, so your installed default toolchain is used. |
| C compiler | Required. `rusqlite` is declared with the `bundled` feature (workspace `Cargo.toml`), which compiles SQLite from source. |
| Python 3 | Required only to generate the synthetic test images under `scripts/`. Not needed to build or run Vajra itself. |
| Network access | Required for the first `cargo build` to fetch crates. Vajra itself is offline-first; the only outbound call at runtime is the optional RFC 3161 timestamp attempt during report generation, which falls back to a local timestamp when unavailable. |

### 3.2 Operating system

Real device enumeration and I/O are implemented for **Windows and Linux only**. Any other target compiles against a stub module whose functions return `UnsupportedOperation`.

### 3.3 Privileges

Raw block-device access requires elevated privileges — root on Linux, Administrator on Windows. Commands that operate purely on image *files* (`fs`, `carve`, `image inspect`, `acquire verify`) need no special privileges.

---

## 4. Build and run

### 4.1 Build the whole workspace

Command:
```bash
cargo build
```

This builds all 20 workspace crates. The two binaries land at `target/debug/vajra-cli` and `target/debug/vajra-verify`.

### 4.2 Build just the binaries you need

Command:
```bash
cargo build -p vajra-cli
cargo build -p vajra-verify
```

Output (second command):
```
   Compiling vajra-verify v0.1.0 (/…/crates/vajra-verify)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 21.71s
```

### 4.3 Generate the synthetic test corpora

The test images are excluded by `.gitignore` (`*.img`), so they are **not** in a fresh clone and must be generated before the image-based examples in this manual will work.

Command:
```bash
python3 scripts/generate_carve_corpus.py
python3 scripts/generate_ground_truth_images.py
```

Output:
```
Generated Carving Ground-Truth Image: /…/test_data/carve_test.img (204720 bytes, 400 sectors)
Generated FAT32 ground-truth image: /…/test_data/fat32_test.img
Generated ext4 ground-truth image: /…/test_data/ext4_test.img
Generated NTFS ground-truth image: /…/test_data/ntfs_test.img
Generated NTFS Quick-Format ground-truth image: /…/test_data/ntfs_quickformat.img
```

### 4.4 Run the test suite

Command:
```bash
cargo test -p vajra-carve
```

Output (tail):
```
running 13 tests
…
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 2 tests
test test_v_eof_truncated_candidate_handling ... ok
test test_carving_and_bgc_on_synthetic_corpus ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The two integration tests require `test_data/carve_test.img` from step 4.3.

### 4.5 Invoke the CLI

All examples below use the debug binary directly:

Command:
```bash
./target/debug/vajra-cli <COMMAND> [SUBCOMMAND] [OPTIONS]
```

---

## 5. CLI overview

### 5.1 Command structure

`vajra-cli` uses a hand-written argument parser (not `clap`), with the shape:

```
vajra-cli [--db <PATH>] <COMMAND> [SUBCOMMAND] <POSITIONAL ARGS…> [--flags]
```

`--db <PATH>` is a **global** flag. It is stripped from the argument vector before dispatch, so it may appear anywhere on the line. It selects the case-database file; when omitted a built-in default path is used. Commands that never touch the database ignore it.

### 5.2 Complete command reference

The table below was built by reading the dispatch code in `crates/vajra-cli/src/main.rs`, **not** from the built-in help. See the warning in 5.4 for why that distinction matters.

| Command | Required arguments | Optional flags |
|---|---|---|
| `list` | — | — |
| `fingerprint` | — | — |
| `health` | — | `[DEVICE]` (positional filter) |
| `inspect` | `<DEVICE>` | — |
| `case create` | `<ID> <NAME> <INVESTIGATOR_ID>` | — |
| `case close` | `<CASE_ID>` | — |
| `case list` | — | — |
| `evidence add` | `<CASE_ID> <DEVICE_PATH>` | — |
| `evidence list` | `<CASE_ID>` | — |
| `audit log` | `<CASE_ID> <OPERATOR> <OP_NAME> <TARGET>` | `[RESULT]` (positional, defaults to `SUCCESS`) |
| `audit verify` | `<CASE_ID>` | — |
| `audit anchor export` | `<CASE_ID> <OPERATOR_ID> <OUT_PATH>` | — |
| `audit anchor verify` | `[CASE_ID] <ANCHOR_PATH>` | — |
| `custody record` | `<EVID_ID> <EVENT_TYPE>` | `--from`, `--to`, `--loc`, `--purp`, `--cond` |
| `custody history` | `<EVIDENCE_ID>` | — |
| `acquire start` | `<CASE_ID> <EVID_ID> <DEV_PATH> <OUT_PATH>` | `--profile physical\|partial:S:E`, `--operator <ID>` |
| `acquire status` | `<OP_ID>` | — |
| `acquire resume` | `<OP_ID> <DEV_PATH>` | — |
| `acquire verify` | `<IMAGE_PATH> <EXPECTED_SHA256>` | — |
| `image inspect` | `<IMAGE_PATH>` | — |
| `fs detect` | `<SOURCE>` | `--partition-offset N` |
| `fs list` | `<SOURCE>` | `--partition-offset N`, `--show-deleted` |
| `fs inspect` | `<SOURCE> <FILE_ID>` | `--partition-offset N` |
| `fs dump` | `<SOURCE> <FILE_ID> <OUT_FILE>` | `--partition-offset N` |
| `carve run` | `<SOURCE>` | `--tier 1\|2\|3\|all`, `--types a,b,c`, `--partition-offset N`, `--ml` |
| `carve inspect` | `<SOURCE> <ARTIFACT_ID>` | `--partition-offset N` |
| `carve stats` | `<SOURCE>` | `--partition-offset N` |
| `erase recommend` | `<DEVICE>` | — |
| `erase run` | — | `--mock <NAME>`, `--method <M>`, `--operator <ID>`, `--incomplete` |
| `file-erase run` | `<FILE_PATH>` | `--passes <N>` (default 3) |
| `ml classify` | `<FILE_PATH>` | — |
| `report generate` | `<CASE_ID> <TYPE>` | `--out-dir`, `--notes`, `--evidence`, `--operator` |
| `report list` | `<CASE_ID>` | — |
| `report verify` | `<REPORT.vjr>` | `--evidence <PATH>` |
| `help`, `-h`, `--help` | — | — |

### 5.3 Sources accepted by `fs`, `carve` and `image inspect`

These commands resolve their `<SOURCE>` argument in this order:

1. Path ending in `.e01` or `.ex01` → opened as an **E01 (EWF)** image.
2. Any other path that **exists as a file** → opened as a **RAW/DD** image.
3. Otherwise → opened as a **physical device**, read-only.

This is why a typo in an image path produces a confusing "physical drive" error — see [Troubleshooting](#15-troubleshooting).

`acquire start` does **not** use this resolver. It calls the physical-device opener directly and therefore accepts only real device paths.

### 5.4 ⚠️ The built-in help text is stale — trust this manual instead

Command:
```bash
./target/debug/vajra-cli help
```

The built-in help works, but four parts of it are out of date relative to the dispatch code. These were verified by reading both:

| Where | Help says | Dispatch actually requires |
|---|---|---|
| Acquisition section | Heading `ACQUISITION & IMAGING COMMANDS (§19–§20):` is printed with **no commands under it** | `acquire start`, `acquire status`, `acquire resume`, `acquire verify`, and `image inspect` all exist and work |
| `audit log` | `<CASE_ID> <OP> <TARGET> <RESULT>` | `<CASE_ID> <OPERATOR> <OP_NAME> <TARGET> [RESULT]` — the operator argument is missing from the help |
| `audit anchor export` | `<CASE_ID> <OUT>` | `<CASE_ID> <OPERATOR_ID> <OUT_PATH>` — the operator argument is missing from the help |
| `carve run --types` | `jpeg,png,pdf,zip,sqlite` | `ole2` is also registered and accepted (see [section 10.4](#104-supported-file-types)) |

The help output also ends with a literal `\n` printed on screen, caused by an escape sequence inside a non-raw string literal.

**Do not use `help` as the authoritative reference until these are fixed.** They are documentation defects in the built-in help. The command dispatch entries listed in section 5.2 exist in the current source; safe/runnable commands were verified during preparation of this manual, while hardware-dependent commands remain explicitly marked as pending successful real-hardware verification.

---

## 6. Creating and managing a case

Every case lives in a SQLite case database. All examples below use a scratch database via the global `--db` flag.

### 6.1 Create a case

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db case create CASE-2026-001 "Demo Recovery Case" INV-VAIBHAVI
```

Output:
```
[+] Case created successfully in Evidence Vault (§22):
  Case ID:         CASE-2026-001
  Case Name:       Demo Recovery Case
  Investigator:    INV-VAIBHAVI
  Created At:      2026-09-01T13:32:37.086463268+00:00
  Status:          Active
```

### 6.2 List cases

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db case list
```

Output:
```
================================================================================
                   VAJRA EVIDENCE VAULT — CASES (§22)
================================================================================
CASE-2026-001        Demo Recovery Case             Investigator: INV-VAIBHAVI [ACTIVE]
================================================================================
```

### 6.3 Register evidence against a case

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db evidence add CASE-2026-001 /dev/vdf
```

Output:
```
[*] Querying physical device '/dev/vdf' via vajra-device...
[+] Evidence registered into Case 'CASE-2026-001' successfully (§22):
  Evidence ID:          EVID-78F79C60
  Model / Vendor:       0x1af4 Drive vdf
  Serial Number:        55663131650400
  Capacity:             49090560 bytes
  Interface Bus:        SATA/SCSI
  SHA-256 Fingerprint:  78f79c60ec2e6757480ee7a6c2c3b66c89b549c8835acb78e1278f3a9697191d
```

The evidence ID is derived from the first eight hex characters of the device fingerprint, so registering the same physical device twice yields the same ID. Note that this command reads device *metadata* only — it does not open the device for block I/O, which is why it succeeds in environments where `inspect` and `acquire start` do not.

### 6.4 List evidence in a case

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db evidence list CASE-2026-001
```

Output:
```
================================================================================
         EVIDENCE ITEMS FOR CASE: CASE-2026-001 (§22)
================================================================================
[EVID-78F79C60] 0x1af4 Drive vdf (SN: 55663131650400) | Fingerprint: 78f79c60ec2e6757
================================================================================
```

### 6.5 Record chain of custody

Custody events are validated against a state machine: the first event must be `Seized` or `Received`, timestamps must not go backwards, `Transferred` requires both `--from` and `--to`, and nothing may follow a terminal event (`Returned`, `Disposed`).

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db custody record EVID-78F79C60 Seized \
  --to "INV-VAIBHAVI" --loc "Lab A" --purp "Forensic imaging" --cond "Sealed, no damage"
```

Output:
```
[+] Custody event recorded for Evidence 'EVID-78F79C60' (§21):
  Event ID:    20affb5d-3c39-4fa9-b801-fc7c561bca30
  Event Type:  Seized
  To Party:    INV-VAIBHAVI
  Location:    Lab A
  Purpose:     Forensic imaging
```

Available event types: `Seized`, `Received`, `StorageChange`, `Transferred`, `WriteBlockerAttached`, `AnalysisStarted`, `AnalysisCompleted`, `WorkingCopyCreated`, `Returned`, `Disposed`.

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db custody history EVID-78F79C60
```

Output:
```
================================================================================
            CHAIN OF CUSTODY LEDGER: Evidence #EVID-78F79C60 (0x1af4 Drive vdf)
================================================================================
  13:32 UTC (2026-09-01)    Seized by INV-VAIBHAVI [Loc: Lab A] (Purpose: Forensic imaging) [Cond: Sealed, no damage]
  13:32 UTC (2026-09-01)    WriteBlockerAttached [Loc: Lab A]
--------------------------------------------------------------------------------
NOTE: This interface records operator-reported custody events and validates
internal sequence and timestamp consistency. It does not independently verify
physical transfer events occurring outside the application boundary (§21).
================================================================================
```

### 6.6 Audit log

Every state-changing operation appends to a SHA-256 hash chain. Entries can also be appended manually.

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db audit log CASE-2026-001 INV-VAIBHAVI CarveRun /tmp/vm/carve SUCCESS
```

Output:
```
[+] Audit entry #1 appended to sequential hash chain (§39):
  Timestamp (UTC): 2026-09-01T13:32:42.846131846+00:00
  Operator:        INV-VAIBHAVI
  Operation:       CarveRun
  Target:          /tmp/vm/carve
  Result:          SUCCESS
  Prev Hash:       0000000000000000000000000000000000000000000000000000000000000000
  Entry Hash:      931e9d11bb412f67f59fec6342a07446f3305fd0e42cf4938920243f2d085eb6
```

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db audit verify CASE-2026-001
```

Output:
```
================================================================================
                 VAJRA AUDIT LOG INTEGRITY VERIFICATION (§39)
================================================================================
[PASS] Chain Verification: 1 entries [Seq #1 -> #1], Head Hash: 931e9d11bb412f67f59fec6342a07446f3305fd0e42cf4938920243f2d085eb6, Status: INTACT
  All 1 sequential entries verified cryptographically.
  No broken links, modifications, deletions, or sequence gaps detected.
================================================================================
```

### 6.7 External anchoring

Chain verification proves internal consistency of what is currently in the database. It cannot by itself detect deletion of the whole log and regeneration of a fresh, self-consistent chain. Anchoring addresses that: it exports a signed checkpoint of the current chain head that you store somewhere the database cannot reach.

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db audit anchor export CASE-2026-001 INV-VAIBHAVI /tmp/vm/case001.anchor.json
```

Output:
```
[+] Signed external anchor checkpoint exported successfully (§40):
  Destination Path:    /tmp/vm/case001.anchor.json
  Anchored Sequence:   #1
  Chain Head Hash:     931e9d11bb412f67f59fec6342a07446f3305fd0e42cf4938920243f2d085eb6
  Public Key (Hex):    743bc5d41e9a3f0e658b80ecaa60ec8bd2faed728bb5af3066f19d1cf0eac429
  Operator Signature:  4dcde7d31e34fb41ec75306200afd527...
```

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db audit anchor verify CASE-2026-001 /tmp/vm/case001.anchor.json
```

Output:
```
================================================================================
              EXTERNAL ANCHOR INTEGRITY VERIFICATION (§40)
================================================================================
[PASS] Anchor Verification: Case 'CASE-2026-001' at Seq #1 [Hash: 931e9d11bb412f67f59fec6342a07446f3305fd0e42cf4938920243f2d085eb6] — Signature Valid: true, Chain Consistent: true
  Signed checkpoint matches live database chain head at sequence #1.
  No history rewrite or rollback detected.
================================================================================
```

> **The anchor file is only as trustworthy as where you put it.** The command writes a signed JSON file to whatever path you give it. There is no integration with an external notary, ledger, or write-once medium — copying it somewhere safe is a manual step and nothing enforces it.

### 6.8 Close a case

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db case close CASE-2026-001
```

Output:
```
[+] Case 'CASE-2026-001' closed / tombstoned successfully (§22).
  Note: Closed cases are permanent historic records and cannot be modified or deleted.
```

**This is irreversible.** Database triggers prevent a closed case from being reopened or deleted, including by direct SQL. After closing, the case still lists:

```
CASE-2026-001        Demo Recovery Case             Investigator: INV-VAIBHAVI [CLOSED / TOMBSTONED]
```

---

## 7. Device identification and fingerprinting

All four commands in this section are read-only.

### 7.1 Enumerate devices

Command:
```bash
./target/debug/vajra-cli list
```

Output:
```
================================================================================
                   VAJRA STORAGE DEVICE ENUMERATION (§23)
================================================================================

[0] /dev/vdf — 0x1af4 Drive vdf
--------------------------------------------------------------------------------
  Serial Number:        55663131650400
  Capacity:             49.09 MB (46.82 MiB)
  Sector Sizes:         Logical: 512 bytes | Physical: 4096 bytes
  Media Type:           HDD (Magnetic)
  Interface Bus:        SATA/SCSI
  Partition Table:      Raw / Inaccessible
```

The listing also reports system-disk status and write-protection state per device.

### 7.2 Fingerprint devices

Command:
```bash
./target/debug/vajra-cli fingerprint
```

Output:
```
================================================================================
                 VAJRA DEVICE IDENTITY FINGERPRINTING (§23)
================================================================================

Device: /dev/vdf
Manufacturer: 0x1af4           Model: Drive vdf
Serial:       55663131650400   Capacity: 49090560 bytes
Interface:    SATA/SCSI        Partition: Raw / Inaccessible
SHA-256 Fingerprint:  78f79c60ec2e6757480ee7a6c2c3b66c89b549c8835acb78e1278f3a9697191d
```

The fingerprint is SHA-256 over the normalised serial, normalised model, capacity, and a boundary-sector sample. **Manufacturer and interface are deliberately excluded**, so moving a drive between a direct SATA connection and a USB bridge does not change its identity. This is what lets `acquire resume` refuse to continue onto the wrong disk.

### 7.3 Device health

Command:
```bash
./target/debug/vajra-cli health
```

Output:
```
================================================================================
                 VAJRA DEVICE HEALTH DIAGNOSTICS (§23)
================================================================================

>>> DIAGNOSTIC REPORT FOR: /dev/vdf (0x1af4 Drive vdf)
DEVICE HEALTH
Status: GOOD
Recommendation: Drive health indicators are within nominal operational parameters.
--------------------------------------------------------------------------------
```

> ⚠️ **On Linux this output is not read from the hardware.** The Linux health backend returns a hardcoded `Good` status with an empty SMART attribute list for every device, regardless of its actual condition. Real SMART and NVMe health queries are implemented on **Windows only**. Do not rely on a `GOOD` result on Linux. See [Known limitations](#14-known-limitations).

### 7.4 Read-only block I/O smoke test

Command:
```bash
./target/debug/vajra-cli inspect /dev/vdf
```

Output in the documentation environment:
```
================================================================================
             VAJRA READ-ONLY BLOCK I/O SMOKE TEST (LBA 0 / 512B)
================================================================================
Target Device: /dev/vdf

Error opening device in read-only mode: Permission denied accessing device: Permission denied opening /dev/vdf (root privileges required). Elevated administrator privileges required.

Ensure the process is running with elevated Administrator/root privileges.
```

**This is an honest limitation of the documentation environment, not a defect.** The container used to verify this manual blocks raw block-device I/O even for root, so `inspect` could not be shown succeeding. On a normal workstation with appropriate privileges this command opens the device read-only and hex-dumps LBA 0. Exit code on failure is `1`.

---

## 8. Evidence acquisition

### 8.1 Supported image formats — read this before planning a workflow

| Format | Read | Write (acquisition output) |
|---|---|---|
| **RAW / DD** | ✅ Implemented | ✅ Implemented — **the only output format** |
| **E01 (EWF)** | ✅ Implemented, via the third-party `ewf` crate | ❌ **Not implemented.** No E01 writer exists in the workspace. |
| **AFF4** | ❌ Not implemented | ❌ Not implemented |

AFF4 is an explicitly documented stub: the module contains a single function that always returns `UnsupportedFormat("AFF4 format support is deferred to Future Scope")`.

**Practical consequence:** you can *analyse* an E01 image someone else produced (`fs`, `carve`, and `image inspect` all accept `.e01` / `.ex01`), but Vajra can only *produce* RAW images. The acquisition engine is hardcoded to the RAW writer.

### 8.2 Starting an acquisition

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db acquire start CASE-2026-001 EVID-78F79C60 /dev/vdf /tmp/vm/out.img
```

Output in the documentation environment:
```
[*] Opening source block device: '/dev/vdf' (strictly read-only)
[-] Error opening source device: Permission denied accessing device: Permission denied opening /dev/vdf (root privileges required). Elevated administrator privileges required.
```

> **⚠️ A full acquisition could not be demonstrated in the documentation environment, and no successful transcript is shown here because none was produced.**
>
> Two facts combine to make this impossible to demonstrate safely:
>
> 1. `acquire start` accepts **only a real physical device path**. Unlike `fs`, `carve` and `image inspect`, it does not fall back to opening an image file, so you cannot acquire "from" a synthetic test image.
> 2. The container used to verify this manual denies raw device I/O even as root.
>
> The acquisition engine itself is substantial and well covered by the crate's own test suite — chunked reads, bad-sector retry with fallback to single-sector reads, checkpointing, resume with fingerprint validation, preflight free-space checks — but every one of those tests drives it through an in-memory simulated device rather than real hardware. **Nothing in this repository has been verified against a physical disk.** Confirming this workflow on real media, with the spare drives and SD cards being supplied for testing, is outstanding work.

**Optional flags:**

- `--profile physical` (default) acquires the whole device.
- `--profile partial:START:END` acquires an LBA range.
- `--operator <ID>` records the operator on the resulting records.

Note that the `Logical` acquisition profile exists in the underlying library but is currently an LBA range, not filesystem-object-level selection, and is not exposed by the CLI.

### 8.3 Hashing and verification

Acquisition computes SHA-256 in two phases:

- **Phase 1** — a rolling hash fed every chunk as it is read from the source and written to the image.
- **Phase 2** — the finished image file is re-read from disk and re-hashed, then compared against the Phase 1 value.

> **Understand precisely what Phase 2 proves.** It re-reads the **image file**, not the source device. It catches corruption on the destination — a bad write, a failed flush, a dying output disk. It does **not** perform a second independent read of the original media and compare source against image. If your procedure requires two independent physical reads of the original, this implementation does not do that.

### 8.4 Verifying an image later

This works on any file and needs no privileges, so it is fully demonstrable.

Command:
```bash
./target/debug/vajra-cli acquire verify test_data/carve_test.img f89a33cd5ba305373361660c76451090b66a25774a8864cf24bd4d8b7cc89f04
```

Output:
```
[*] Running Phase 2 independent re-read SHA-256 verification on 'test_data/carve_test.img'...
[+] Verification PASSED (§19)!
  File:            test_data/carve_test.img
  Expected SHA-256: f89a33cd5ba305373361660c76451090b66a25774a8864cf24bd4d8b7cc89f04
  Computed SHA-256: f89a33cd5ba305373361660c76451090b66a25774a8864cf24bd4d8b7cc89f04
  Status:          MATCH (Integrity Confirmed)
```

With a deliberately wrong expected hash:

Command:
```bash
./target/debug/vajra-cli acquire verify test_data/carve_test.img 0000000000000000000000000000000000000000000000000000000000000000
```

Output:
```
[*] Running Phase 2 independent re-read SHA-256 verification on 'test_data/carve_test.img'...
[-] Verification FAILED: Post-acquisition verification hash mismatch: rolling SHA-256 was '0000000000000000000000000000000000000000000000000000000000000000', but re-read verification SHA-256 was 'f89a33cd5ba305373361660c76451090b66a25774a8864cf24bd4d8b7cc89f04'
```

### 8.5 Inspecting an image container

Command:
```bash
./target/debug/vajra-cli image inspect test_data/carve_test.img
```

Output:
```
[*] Inspecting forensic container: 'test_data/carve_test.img'
  Format:          RAW / DD Flat Stream
  Total Size:      204720 bytes
  Block Count:     400 blocks (@ 512B/block)
  Fingerprint:     09bbee4b1d5705c56fa0ea7343be26c522bca8c79baf36cd84ec796c7cd691aa

  [LBA 0 First 64 Bytes]:
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

### 8.6 Checkpoint, status and resume

`acquire status <OP_ID>` reports progress of a recorded acquisition operation, and `acquire resume <OP_ID> <DEV_PATH>` continues an interrupted one. Resume validates that the device now attached has the **same fingerprint** as the one recorded in the checkpoint and refuses to continue otherwise.

Neither could be demonstrated here, because both depend on a successful `acquire start` (see 8.2).

---

## 9. Filesystem analysis

Tier-1 recovery uses surviving filesystem metadata. Supported parsers: **NTFS**, **ext4**, **FAT**. These commands accept image files, so everything in this section is fully demonstrated.

### 9.1 Detect the filesystem

Command:
```bash
./target/debug/vajra-cli fs detect test_data/fat32_test.img
```

Output:
```
================================================================================
                 VAJRA FILESYSTEM SIGNATURE DETECTION (§25)
================================================================================
  Source Target:       test_data/fat32_test.img
  Partition Offset:    LBA 0
  Detected Filesystem: FAT32
  Detection Method:    BPB FAT32 signature & boot signature 0x55, 0xAA at LBA 0
  Parser Engine:       vajra-fs-fat (FAT32 Cluster Chains, 8.3 & LFN Slack Recovery)
================================================================================
```

On an NTFS image:

Command:
```bash
./target/debug/vajra-cli fs detect test_data/ntfs_test.img
```

Output (tail):
```
  Detected Filesystem: NTFS
  Detection Method:    OEM ID signature 'NTFS    ' at LBA 0 (offset 3..11)
  Parser Engine:       vajra-fs-ntfs (MFT, $LogFile, USN Journal, $Bitmap)
```

On a target with no recognisable filesystem, detection reports honestly rather than guessing:

Command:
```bash
./target/debug/vajra-cli fs detect test_data/carve_test.img
```

Output (tail):
```
  Detected Filesystem: Unknown
  Status:              Unparsed or unsupported filesystem type: Unknown
```

If the filesystem does not start at LBA 0 — a whole-disk image with a partition table — pass `--partition-offset N` with the partition's starting LBA.

### 9.2 List active and deleted files

Command:
```bash
./target/debug/vajra-cli fs list test_data/fat32_test.img
```

Output:
```
========================================================================================================================
                   VAJRA FILESYSTEM RECOVERY & FILE ENUMERATION (§25)
========================================================================================================================
  Source: test_data/fat32_test.img | Filesystem: FAT32 | Partition Offset: LBA 0
------------------------------------------------------------------------------------------------------------------------
ID       | STATUS    | SIZE (B)   | CONFIDENCE         | FILENAME                     | ORIGINAL PATH
------------------------------------------------------------------------------------------------------------------------
3        | [ACTIVE]  | 70         | Confirmed          | active_document.txt          | /active_document.txt
4        | [DELETED] | 75         | Confirmed          | confidential_plan.pdf        | /confidential_plan.pdf
========================================================================================================================
Total Entries: 2
```

To show only recoverable deleted entries:

Command:
```bash
./target/debug/vajra-cli fs list test_data/fat32_test.img --show-deleted
```

Output (tail):
```
4        | [DELETED] | 75         | Confirmed          | confidential_plan.pdf        | /confidential_plan.pdf
========================================================================================================================
Total Entries: 1
```

### 9.3 Inspect file metadata

Command:
```bash
./target/debug/vajra-cli fs inspect test_data/fat32_test.img 4
```

Output:
```
================================================================================
                   VAJRA FILE METADATA INSPECTION (§25)
================================================================================
  Record / Inode ID:   4
  Filename:            confidential_plan.pdf
  Original Path:       /confidential_plan.pdf
  Filesystem:          FAT32
  Status:              [DELETED / UNLINKED]
  Size:                75 bytes
  Metadata Confidence: Confirmed (Metadata Intact & Blocks Free)
  Created:             2026-08-30T00:00:00+00:00
  Modified:            2026-08-30T00:00:00+00:00
  Accessed:            -
  Data Location:       Contiguous { start_lba: 112, block_count: 8 }
================================================================================
```

`Metadata Confidence` is one of `Confirmed`, `Partial`, `Reconstructed`, `Low`, or `None`, and feeds directly into the composite confidence score.

### 9.4 Extract a file

Command:
```bash
./target/debug/vajra-cli fs dump test_data/fat32_test.img 4 /tmp/vm/recovered_plan.pdf
```

Output:
```
[*] Extracting payload for 'confidential_plan.pdf' (ID: 4)...
[+] File extracted successfully (§25):
  Output File:         /tmp/vm/recovered_plan.pdf
  Extracted Size:      75 bytes
  Payload SHA-256:     23ec5df7d91b96534efb36deddccf910bf753d45c41af84d9eebe45a5c634882
  Metadata Confidence: Confirmed (Metadata Intact & Blocks Free)
```

Confirming the recovered content:

Command:
```bash
head -c 80 /tmp/vm/recovered_plan.pdf
```

Output:
```
 TOP SECRET DELETED FORENSIC DATA: Vajra tier-1 recovery ground truth test.
```

---

## 10. File recovery and carving

Carving recovers files when filesystem metadata is gone. The engine runs three tiers in strict precedence.

### 10.1 How the three tiers relate

**Tier 1 — filesystem metadata.** Delegates to the NTFS/ext4/FAT parsers (section 9). Regions resolved with `Confirmed` or `Partial` metadata confidence are marked claimed so later tiers do not re-carve them. Weak hits deliberately do *not* suppress carving, so a poor metadata guess cannot mask a pristine signature candidate.

**Tier 2 — signature carving with structural validation.** Scans for header signatures, then passes each candidate to a format-specific validator that actually parses it. **Only a fully valid object is accepted** — a truncated or corrupt candidate produces nothing at this tier. This is what keeps false positives at zero on the ground-truth corpus.

**Tier 3 — Bifragment Gap Carving.** For candidates that fail as one contiguous run, attempts two-fragment reassembly, testing gap sizes in an empirically-ordered sequence (8, 16, 32, 4, 64, 24, 40 sectors and beyond) drawn from published real-world fragmentation data rather than a naive linear sweep. The same validator judges the reassembled candidate.

### 10.2 `carve run` — full pipeline

Command:
```bash
./target/debug/vajra-cli carve run test_data/carve_test.img
```

Output:
```
========================================================================================================================
                                  VAJRA MULTI-TIER RECOVERY & FILE CARVING (§25–§32)
========================================================================================================================
  Target Source:       test_data/carve_test.img
  Partition Offset:    LBA 0
  Enabled Tiers:       Tier 1: true | Tier 2: true | Tier 3: true
  Entropy Analysis:    Deterministic Heuristic (§29)
------------------------------------------------------------------------------------------------------------------------
ID       | RECOVERY METHOD        | SIZE (B)   | CONFIDENCE   | FILENAME / TYPE              | LOCATIONS         
------------------------------------------------------------------------------------------------------------------------
2001     | Tier 2 (Signature)     | 45         | 66.5%        | carved_file_2001.png         | LBA 10..11        
2002     | Tier 2 (Signature)     | 33         | 66.5%        | carved_file_2002.jpeg        | LBA 20..21        
2003     | Tier 2 (Signature)     | 146        | 80.0%        | carved_file_2003.pdf         | LBA 30..31        
2004     | Tier 2 (Signature)     | 1024       | 69.5%        | carved_file_2004.sqlite      | LBA 40..42        
2005     | Tier 2 (Signature)     | 153        | 66.5%        | carved_file_2005.zip         | LBA 50..51        
3150     | Tier 3 (BGC)           | 524        | 66.5%        | reconstructed_file_150.png   | LBA 150..151 + 159..160
========================================================================================================================
Total Recovered Artifacts: 6
```

**This output is a ground-truth result, not just a demonstration.** The synthetic corpus contains 5 intact files, 1 genuinely two-fragmented PNG, 2 truncated files, and 3 deliberately corrupted candidates. All 6 real files were recovered; all 3 corrupted candidates and both truncated files were correctly rejected. That is precision 100%, recall 100% against this corpus.

> These precision/recall figures apply only to the existing `carve_test.img` ground-truth corpus and do not include OLE2. OLE2 precision/recall benchmarking on the shared corpus remains pending.

### 10.3 Filtering by tier and type

> **About the image used below.** The repository's shipped corpus (`carve_test.img`) contains no OLE2 file, so the OLE2 example uses a separate synthetic image built specifically to verify the OLE2 validator. **It is not part of the repository and the path below will not exist in your checkout.** The command and its output are real, but to reproduce them you need an image containing a compound file. Adding OLE2 fixtures to `scripts/generate_carve_corpus.py` is outstanding work, coordinated with Akanksha, who owns that script.

Command:
```bash
./target/debug/vajra-cli carve run /tmp/ole2demo/ole2_test.img --tier 2 --types ole2
```

Output (tail):
```
ID       | RECOVERY METHOD        | SIZE (B)   | CONFIDENCE   | FILENAME / TYPE              | LOCATIONS         
------------------------------------------------------------------------------------------------------------------------
2001     | Tier 2 (Signature)     | 6144       | 80.0%        | carved_file_2001.ole2        | LBA 10..22        
========================================================================================================================
Total Recovered Artifacts: 1
```

`--tier` accepts `1`, `2`, `3`, or `all`. `--types` takes a comma-separated list matched case-insensitively against the `file_type` field in the signature database; unrecognised names are silently ignored rather than rejected.

### 10.4 Supported file types

Read from `config/signatures.json` in this branch:

| `--types` value | Format | Validation performed |
|---|---|---|
| `jpeg` | JPEG / JFIF | Marker-segment walk, byte-stuffing handling, EOI terminator |
| `png` | PNG | Per-chunk CRC32 verification |
| `pdf` | PDF | Header, object body, xref/trailer, `startxref` / `%%EOF` consistency |
| `zip` | ZIP, DOCX, XLSX, PPTX | Local headers, central directory, EOCD, `[Content_Types].xml` well-formedness |
| `sqlite` | SQLite 3 | Magic string, page geometry, root b-tree page structure |
| `ole2` | Legacy DOC / XLS / PPT (OLE2/CFB) | Header geometry, DIFAT, FAT assembly, FAT self-consistency, directory chain, MiniFAT, loop and bounds detection |

`ole2` is new in this branch. **The built-in CLI help does not list it yet** (see 5.4), but it is registered and works, as the output in 10.3 shows.

The signature database is a plain JSON file and new *signatures* can be added without recompiling. A new *validator*, however, is a compiled component registered in code, so adding a genuinely new format does require a rebuild.

### 10.5 `carve inspect` — provenance for one artifact

Command:
```bash
./target/debug/vajra-cli carve inspect test_data/carve_test.img 2003
```

Output:
```
================================================================================
                 VAJRA RECOVERED ARTIFACT PROVENANCE (§31)
================================================================================
Recovered File #R-2003
Recovery method: Tier 2 (Signature + Structural Validation)
Source: LBA 30 -> 31
Confidence: 80.0% (Structural: 100.0%, Meta: 0.0%, Entropy: 100.0%)
  Entropy Signal Basis: ML GBDT Classifier: predicted pdf (100.0% prob) | Key Drivers: [bigram_variance: 0.0002, byte_freq_11: 0.0000, byte_freq_4c: 0.0000]
Recovered bytes: 146 / 146
SHA-256: 402d94f8c7f375b698d34f2354727cce33b95df5196cd7a96f5008294c27095a
Recovery limitations: None (Complete & verified payload)

  Confidence Signal Breakdown (§29):
    - Header / Footer Integrity (0.20):     100.0%
    - Structural Validity (0.25):           100.0%
    - Metadata Cross-Reference (0.20):      0.0%
    - Entropy Profile Consistency (0.15):   100.0%
      * Explainable Basis: ML GBDT Classifier: predicted pdf (100.0% prob) | Key Drivers: [bigram_variance: 0.0002, byte_freq_11: 0.0000, byte_freq_4c: 0.0000]
    - Fragmentation Confidence (0.15):      100.0%
    - Non-Overwrite Probability (0.05):     100.0%
================================================================================
```

The confidence score is a weighted sum of six named, individually inspectable signals — never an opaque percentage. `Metadata Cross-Reference` is 0.0% here because this is a pure carved artifact with no surviving filesystem metadata; that is expected, not a fault.

Note that `carve inspect` engages the ML classifier automatically, which is why its confidence figure can differ from the same artifact's figure in `carve run` without `--ml`.

### 10.6 `carve stats` — summary and benchmark

Command:
```bash
./target/debug/vajra-cli carve stats test_data/carve_test.img
```

Output:
```
================================================================================
                     VAJRA RECOVERY STATISTICS & BENCHMARK (§30, §46)
================================================================================
  Target Image:                test_data/carve_test.img
  Total Candidates Recovered:  6
  - Tier 1 (Metadata):         0
  - Tier 2 (Signature+Valid):  5
  - Tier 3 (BGC Fragmented):   1
  Total Recovered Data:        1925 bytes (1.88 KB)
  Mean Confidence Score:       69.1%
  Precedence Verification:     Intact (Tier 1 overrides Tier 2/3 collisions)
  Validator False Positives:   0 Accepted (Corrupted bitstreams cleanly rejected)
================================================================================
```

### 10.7 ML-augmented entropy scoring

`--ml` swaps the heuristic entropy analyser for a gradient-boosted tree classifier.

Command:
```bash
./target/debug/vajra-cli carve run test_data/carve_test.img --tier 2 --ml
```

Output (head):
```
  Entropy Analysis:    ML-Augmented (vajra-ml GBDT ONNX/Tree Model §33)
------------------------------------------------------------------------------------------------------------------------
ID       | RECOVERY METHOD        | SIZE (B)   | CONFIDENCE   | FILENAME / TYPE              | LOCATIONS         
------------------------------------------------------------------------------------------------------------------------
2001     | Tier 2 (Signature)     | 45         | 66.5%        | carved_file_2001.png         | LBA 10..11        
2002     | Tier 2 (Signature)     | 33         | 79.9%        | carved_file_2002.jpeg        | LBA 20..21        
```

The ML layer is a **secondary, explainable signal only**. It contributes to one of six confidence components and never decides whether an artifact is recovered — that remains the structural validator's job.

### 10.8 Standalone classification

Command:
```bash
./target/debug/vajra-cli ml classify /tmp/vm/recovered_plan.pdf
```

Output:
```
================================================================================
          VAJRA ML EXPLAINABLE FILE-TYPE CLASSIFIER (§33)
================================================================================
  Target File:            /tmp/vm/recovered_plan.pdf
  File Size:              75 bytes (0.07 KB)
  Predicted File Type:    PDF
  Confidence Probability: 100.00%
--------------------------------------------------------------------------------
  Class Probability Distribution:
    - jpeg       0.00%  
    - png        0.00%  
    - pdf      100.00%  ██████████████████████████████
    - zip        0.00%  
    - sqlite     0.00%  
    - unknown    0.00%  

  Top-5 Informative Features (Explainable Forensic Basis §33, §31):
     1. bigram_variance              (Value:     0.0000 | Global Imp: 0.1648)
     2. byte_freq_11                 (Value:     0.0000 | Global Imp: 0.1180)
     3. byte_freq_4c                 (Value:     0.0133 | Global Imp: 0.1055)
     4. byte_freq_4b                 (Value:     0.0000 | Global Imp: 0.1050)
     5. entropy_chunk_0              (Value:     2.0000 | Global Imp: 0.0854)
================================================================================
```

> **The classifier knows only six classes:** `jpeg`, `png`, `pdf`, `zip`, `sqlite`, `unknown`. **OLE2 is not among them** and will classify as `unknown`, which slightly lowers the entropy component of an OLE2 artifact's confidence score. This is a model-coverage gap, not a validator problem — the OLE2 structural validator is unaffected.

---

## 11. Reports

Six report types are generated, signed and persisted through the CLI.

### 11.1 Report types

| `<TYPE>` argument | Report |
|---|---|
| `exam` | Forensic Examination Report |
| `sanitization` | Sanitization Certificate |
| `acquisition` | Acquisition Report |
| `recovery` | Recovery Report |
| `health` | Device Health Report |
| `custody` | Chain of Custody Report |

An invalid type prints the valid list and exits.

### 11.2 Generating a report

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db report generate CASE-2026-001 exam \
  --out-dir /tmp/vm/reports --notes "Tier-2 carving of synthetic corpus" --evidence EVID-78F79C60
```

Output:
```
================================================================================
          VAJRA FORENSIC REPORT GENERATION (§41, §40)
================================================================================
  Report ID:              fac4f029-ccf2-4334-a626-f3bb868736f7
  Case ID:                CASE-2026-001
  Report Type:            Forensic Examination Report
  Generated At (UTC):     2026-09-01T13:33:56.601108364+00:00
  Signing Operator:       OP-CHIEF
--------------------------------------------------------------------------------
  CRYPTOGRAPHIC ATTESTATION & INTEGRITY:
  Content SHA-256:        `d686e9cbf1a979b2ab0b0d3f3faf99fa74216533ef46089e50ef29603c4ba90c`
  Digital Signature:      Ed25519 (4eda7a829d44e260... bytes)
  Signing Certificate:    X.509 PKI Attestation (Self-Signed)
  Timestamp Attestation:  Local timestamp — RFC 3161 unavailable at generation time
  Audit Log Seq Number:   Seq #2
--------------------------------------------------------------------------------
  EXPORTED REPORT ARTIFACTS:
  - JSON Package (.vjr):  /tmp/vm/reports/forensicexamination_fac4f029.vjr
  - Markdown Document:    /tmp/vm/reports/forensicexamination_fac4f029.md
================================================================================
```

Each report produces two files: a `.vjr` signed JSON envelope (the verifiable artifact) and a human-readable `.md`. **There is no PDF output** — no PDF generation exists in the codebase.

Generating a report also appends an entry to the case's audit chain, visible above as `Seq #2`.

`--operator <ID>` sets the signing operator; it defaults to `OP-CHIEF`.

### 11.3 Listing reports

Command:
```bash
./target/debug/vajra-cli --db /tmp/vm/manual.db report list CASE-2026-001
```

Output:
```
================================================================================
          VAJRA GENERATED REPORTS FOR CASE: CASE-2026-001
================================================================================
  REPORT ID                              TYPE                     TIMESTAMP ATTESTATION
  ------------------------------------------------------------------------------
  dc6a91f8-1300-4fa3-918d-111d0a01d563   ChainOfCustodyReport     Local timestamp — RFC 3161 unavailable at generation time
  fac4f029-ccf2-4334-a626-f3bb868736f7   ForensicExamination      Local timestamp — RFC 3161 unavailable at generation time
================================================================================
```

### 11.4 About the timestamp attestation

The `Local timestamp — RFC 3161 unavailable at generation time` line above is the honest, expected result for offline operation.

Report generation attempts a real RFC 3161 timestamp request to a public authority with a short timeout. When that fails — which it always will on an air-gapped forensic workstation — it falls back to the local system clock and **labels itself as having done so**. Always read the attestation line rather than assuming a trusted timestamp is present.

Be aware of two further constraints: the timestamp response is not cryptographically validated even when one is received, and the signing keypair is generated fresh per report generator instance and never persisted — so a signature proves the report has not been altered since signing, but does not by itself attribute it to a durable operator identity.

---

## 12. Independent report verification

`vajra-verify` is a separate binary that deliberately shares no data structures with the report generator — it redefines the envelope format independently, so that a bug or a compromise in the generator cannot make a bad report verify clean.

### 12.1 Usage

Command:
```bash
./target/debug/vajra-verify
```

Output (head):
```
Vajra Independent Report Verifier (§42)

USAGE:
  vajra-verify <REPORT_FILE.vjr> [--evidence <EVIDENCE_PATH>]

ARGUMENTS:
```

### 12.2 Verifying a valid report

Command:
```bash
./target/debug/vajra-verify /tmp/vm/reports/forensicexamination_fac4f029.vjr
```

Output:
```
================================================================================
          VAJRA INDEPENDENT REPORT VERIFIER (§42)
================================================================================
  Report ID:       fac4f029-ccf2-4334-a626-f3bb868736f7
  Report Type:     ForensicExamination
  Case ID:         CASE-2026-001
  Signing Operator:OP-CHIEF
--------------------------------------------------------------------------------
  INDEPENDENT VERIFICATION CHECKS:

  [PASS] 1. Content Hash:           SHA-256 matches content payload exactly
  [PASS] 2. Digital Signature:      Valid Ed25519 signature by signing certificate key
  [PASS] 3. X.509 Certificate:      Well-formed PEM certificate with matching Subject DN
  [PASS] 4. Audit Chain Segment:    Sequential hash links unbroken from Genesis
  [PASS] 5. Timestamp Attestation:  Valid timestamp record (RFC 3161 or labeled local fallback)
--------------------------------------------------------------------------------
  OVERALL INTEGRITY STATUS: VALID / UNTAMPERED
================================================================================
```

Exit code `0`.

The same verification is reachable through the main CLI as `report verify <FILE.vjr>`, which produces identical output.

### 12.3 Verifying a tampered report

To demonstrate that verification actually detects modification, a copy of the report above was edited to change the examiner's notes from `Tier-2 carving of synthetic corpus` to `NOTHING WAS FOUND`.

Command:
```bash
./target/debug/vajra-verify /tmp/vm/tampered.vjr
```

Output:
```
================================================================================
          VAJRA INDEPENDENT REPORT VERIFIER (§42)
================================================================================
  Report ID:       fac4f029-ccf2-4334-a626-f3bb868736f7
  Report Type:     ForensicExamination
  Case ID:         CASE-2026-001
  Signing Operator:OP-CHIEF
--------------------------------------------------------------------------------
  INDEPENDENT VERIFICATION CHECKS:

  [FAIL] 1. Content Hash:           Hash mismatch: expected 'd686e9cbf1a979b2ab0b0d3f3faf99fa74216533ef46089e50ef29603c4ba90c', computed '5f2f83f95ca14d6833d9ab5b341d9784ae11fadf0803eda2c255e6c871a0efd9'
  [FAIL] 2. Digital Signature:      Ed25519 signature verification failed against certificate public key
  [PASS] 3. X.509 Certificate:      Well-formed PEM certificate with matching Subject DN
  [PASS] 4. Audit Chain Segment:    Sequential hash links unbroken from Genesis
  [PASS] 5. Timestamp Attestation:  Valid timestamp record (RFC 3161 or labeled local fallback)
--------------------------------------------------------------------------------
  OVERALL INTEGRITY STATUS: TAMPER DETECTED / INVALID
================================================================================
```

Exit code `1`.

Note that check 2 fails independently of check 1. The signature is verified against the **recomputed** content digest, not the stored one, so an attacker who edits the content *and* updates the stored hash to match still fails signature verification. Patching the hash does not help.

### 12.4 Verifying an evidence file alongside the report

Passing `--evidence <PATH>` additionally hashes a file on disk and checks it against the report's evidence manifest, adding a sixth check to the output.

---

## 13. Sanitization

> ### ⚠️ Read this before running anything in this section
>
> Sanitization is **irreversible**. Nothing in this section was executed against a physical drive during the preparation of this manual, and you should not do so casually either.
>
> `erase run` as shipped is **always safe**: it operates on an in-memory mock device and never touches real hardware, whatever `--mock` name you give it. The `--mock <NAME>` argument is only a label in the output.

### 13.1 What actually works on real hardware — the important table

This distinction matters more than any other in this manual.

| Method | Modelled | Executable on real hardware | Notes |
|---|---|---|---|
| Host overwrite, single pass | ✅ | ✅ **Yes** | Zero/ones/CSPRNG patterns; reaches the logical address space only |
| Host overwrite, multi-pass | ✅ | ✅ **Yes** | Composed from single passes; used for legacy DoD 5220.22-M policy compatibility |
| ATA Secure Erase (normal) | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| ATA Enhanced Secure Erase | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| NVMe Sanitize (Block) | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| NVMe Sanitize (Crypto) | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| NVMe Format (User Data Erase) | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| TCG Cryptographic Erase | ✅ | ❌ **No** | Returns `UnsupportedOperation` |
| SCSI Sanitize (Overwrite / Crypto) | ✅ | ❌ **No** | Returns `UnsupportedOperation` |

**Every controller-native command is modelled in the type system, recommended by the decision engine, and executed successfully against the mock — but returns an error when issued to a real drive.** The underlying stub carries the message *"Hardware protocol command execution will be integrated in Module 1 sanitization engine (Conversation 6)"*.

Practical consequence: **on real flash media (SSD, NVMe, SED), Vajra can currently perform only host-level logical overwrite.** It cannot perform the controller-native operations that NIST SP 800-88 relies on for Purge-level assurance on those media. The decision engine will still *recommend* those methods, so a user who follows its advice on an SSD will hit an error at execution time.

### 13.2 Getting a recommendation (read-only, safe)

Command:
```bash
./target/debug/vajra-cli erase recommend /dev/vdf
```

Output:
```
RECOMMENDED SANITIZATION
Device: 0x1af4 Drive vdf | Media: HDD (Magnetic) | Interface: SATA/SCSI | Self-encrypting: No | Capacity: 0.05 GB
Recommended: NIST SP 800-88 Clear (Single-Pass Logical Overwrite)
Reason: Magnetic HDD media is reliably cleared by single-pass logical overwrite across all addressable LBAs. Modern magnetic force microscopy cannot reconstruct overwritten PRML/EPRML tracks on post-2001 HDDs.
Alternative available: Multi-pass overwrite (DoD 5220.22-M 3-pass) for legacy policy compliance.
```

This command only reads device metadata and never writes. Note that DoD 5220.22-M is correctly offered as a legacy alternative and never as the recommendation.

### 13.3 The two-phase safety gate

Destructive operations require an unforgeable capability token that **cannot be obtained in a single call**. Phase 1 checks the device and takes a serial-number confirmation; Phase 2 takes a second, separate confirmation immediately before writing. OS system disks are blocked unconditionally.

Command:
```bash
./target/debug/vajra-cli erase run --mock samsung_pm9a3_nvme
```

Output (head):
```
================================================================================
              VAJRA SANITIZATION ENGINE — SAFE MOCK SIMULATION MODE (§43)
================================================================================
  Target:                 Mock In-Memory Block Source (samsung_pm9a3_nvme)
  Operator ID:            forensic_examiner_01
  Method Requested:       Host Overwrite (1 pass - NIST Clear)
  Incomplete Sim Mode:    None (Standard Purge)
--------------------------------------------------------------------------------

[PHASE 1] Device Identity Confirmation Gate (§43.1, §43.2, §43.4)
  Device Fingerprint:     PM9A3 NVMe Enterprise SSD
  Serial Number:          S5GXNF0R123456
  Capacity:               1920.00 GB
  System Disk Check:      PASSED (Non-system device)
  Write Blocker Check:    PASSED (No write blocker)
  [OPERATOR CONFIRMATION 1]: Typing serial 'S5GXNF0R123456' to confirm...
[+] Phase 1 Passed. Authorization ticket minted: PendingSanitization

[PHASE 2] Pre-Execution Final Reconfirmation (§43.3)
  [OPERATOR CONFIRMATION 2]: Affirmative pre-exec confirmation verified.
[+] Capability Token Issued: GATE-AUTH-e270fffd-fc30-4570-9614-6e3653b307f6
```

In this mock mode both confirmations are supplied automatically so the flow can be demonstrated non-interactively.

### 13.4 Full mock run with five-layer verification

Command:
```bash
./target/debug/vajra-cli erase run --mock samsung_pm9a3_nvme --method host-overwrite --operator INV-VAIBHAVI
```

Output (tail):
```
[EXECUTION] Running sanitization method: Host Overwrite (1 pass - NIST Clear)...
  Pass 1/1: 2000/2000 blocks written (100.0%)
[+] Method execution finished in TimeDelta { secs: 0, nanos: 1344268 }

[VERIFICATION] Executing 5-Layer Multi-Layer Verification Suite (§37)...
  Layer 1 (Command Level):       PASS
  Layer 2 (Device Status):       PASS
  Layer 3 (Deterministic):       PASS
  Layer 4 (Statistical Sample):  PASS
  Layer 5 (Recovery-Engine Scan):PASS
  ------------------------------------------------------------------
  Overall Assurance Level:       MEDIUM
  Verification Summary:          All 5 verification layers passed on addressable LBAs, but assurance is structurally capped at MEDIUM per §33a (NIST SP 800-88 §2.4) because host-level overwrite on flash media cannot reach FTL wear-leveling or over-provisioning pools.

================================================================================
                 VAJRA — SECURE MEDIA SANITIZATION CERTIFICATE
================================================================================
Certificate ID: SAN-2026-6F429777

Device Details:
  Manufacturer: Samsung          Model: PM9A3 NVMe Enterprise SSD Serial: S5GXNF0R123456
  Capacity:     1920.00 GB       Interface: NVMe         Media: NVMe SSD
  Device SHA-256 Fingerprint: e37c14e10a59a3e36dda1b9eedfb7024f0ede490b00fc9fd21bc8023e5d549ab

Sanitization Execution:
  Method:             Host Overwrite (1 pass - NIST Clear)
  Standard Reference: NIST SP 800-88 Rev. 2 (Clear tier); IEEE 2883-2022
  Started:            2026-09-01T13:34:37.913719886+00:00
  Completed:          2026-09-01T13:34:37.915064154+00:00

Independent Multi-Layer Verification (§37):
  Layer 1 (Command Level):       PASS
  Layer 2 (Device Status):       PASS
  Layer 3 (Deterministic):       PASS (4 sample sectors verified clean)
  Layer 4 (Statistical Sample):  PASS (99.9% confidence, 0.01% defect rate, 1998 sectors sampled)
  Layer 5 (Recovery-Engine Scan):PASS — 0 artifacts recoverable

Overall Assurance: MEDIUM

Residual Risk Disclosure (§33a):
  RESIDUAL RISK DISCLOSURE (§33a, NIST SP 800-88 §2.4): Host-level logical overwrite cannot address unmapped, wear-leveled, or over-provisioned NAND flash blocks managed by the device controller (FTL). Residual raw data may remain accessible via physical chip-off extraction. Overall assurance is structurally capped at MEDIUM.

Operator ID:             INV-VAIBHAVI
Certificate SHA-256:     fbc9f9a34ff1815fd15663de3f458fa311adfbfd353b5283862cd3a899f250cc
Ed25519 Signature:       1ad26c4b40ab43aff2f8f927f43dd044e7ec01688fd368c061b0c62fe9e6e24c945a711105d56c1ec020e378528e17f79af5cc7f2383a397e0fdcdeb05095c06
Trusted Timestamp:       Not available — generated offline, local timestamp only
================================================================================
```

> ### ⚠️ The `IEEE 2883-2022` label in the certificate above is not an implementation claim
>
> The captured output contains the line:
>
> ```
> Standard Reference: NIST SP 800-88 Rev. 2 (Clear tier); IEEE 2883-2022
> ```
>
> That text is **emitted verbatim by the current implementation** and is reproduced above because it is real output. It is retained here unaltered, not endorsed.
>
> **This repository does not implement IEEE 2883-specific guidance.** IEEE 2883 appears in the codebase only in doc comments and display strings such as this one; there is no code path, decision rule, parameter, or verification step that is specific to IEEE 2883 as distinct from the NIST-derived logic. This is recorded in `docs/standards-mapping.md`, which maps both IEEE 2883-2022 and IEEE 2883.1-2025 as **Not implemented**.
>
> Do not treat this certificate line as evidence of IEEE 2883 compliance, conformance, or implementation, and do not repeat it as such in a submission or demonstration. It is a hardcoded label in a string, and the label should be corrected in the code.

Two other things in this output deserve attention. The assurance level is honestly capped at **MEDIUM** with a stated reason rather than being reported as a clean success, and the residual-risk disclosure explains exactly what host-level overwrite cannot reach.

**The five verification layers:**

| Layer | What it checks |
|---|---|
| 1 — Command level | Did the sanitize command report success? |
| 2 — Device status | Does the device's own status agree? |
| 3 — Deterministic | Read-verify a bounded sample of sectors |
| 4 — Statistical | Hypergeometric-corrected random sampling; defaults 99.9% confidence, 0.01% defect rate |
| 5 — Recovery scan | Run Vajra's own carving engine against the sanitized device |

### 13.5 Layer 5 in action — the assurance loop

`--incomplete` deliberately leaves a recoverable PDF behind so you can see Layer 5 override an otherwise-clean result.

Command:
```bash
./target/debug/vajra-cli erase run --mock samsung_pm9a3_nvme --incomplete --operator INV-VAIBHAVI
```

Output (verification section):
```
[VERIFICATION] Executing 5-Layer Multi-Layer Verification Suite (§37)...
  Layer 1 (Command Level):       PASS
  Layer 2 (Device Status):       PASS
  Layer 3 (Deterministic):       PASS
  Layer 4 (Statistical Sample):  PASS
  Layer 5 (Recovery-Engine Scan):FAILED
  ------------------------------------------------------------------
  Overall Assurance Level:       FAILED
```

**This is the platform's central idea made visible.** Layers 1–4 all report success — the erase command said it worked, the device agreed, sampled sectors looked clean. Layer 5 runs the recovery engine, finds a recoverable artifact, and the overall result becomes FAILED regardless. The recovery engine has no privileged knowledge that sanitization "should have" succeeded; it simply looks for recoverable data the same way it would on any other device.

> **State Layer 5's scope accurately when presenting it.** "Layer 5 found nothing" means "the carver found none of the six registered signature types". It is strong independent evidence, and it is genuinely more than trusting the erase command's self-report — but it is not a proof that no data of any kind survives.

### 13.6 Secure file erasure

`file-erase run` securely overwrites and unlinks a single file through the host OS. It is destructive to that file. The example below uses a throwaway file created for the purpose.

Command:
```bash
./target/debug/vajra-cli file-erase run /tmp/vm/scratch_secret.txt --passes 3
```

Output:
```
================================================================================
       VAJRA SECURE LOCAL FILE ERASURE — HOST OS PRIMITIVE (§36)
================================================================================
  Target File:            /tmp/vm/scratch_secret.txt
  Overwrite Passes:       3 (CSPRNG ChaCha20 + NIST SP 800-88 Zero Fill)
--------------------------------------------------------------------------------

[PHASE 1] Validating target path and resolving file size...
  File Path:              /tmp/vm/scratch_secret.txt
  Size on Disk:           56 bytes (0.05 KB)

[PHASE 2] Executing 3 CSPRNG data overwrite passes with OS fsync() flush...
  Pass 1/3: Overwrite data blocks with ChaCha20 CSPRNG Random + fsync()
  Pass 2/3: Overwrite data blocks with 0xFF (Fixed Fill) + fsync()
  Pass 3/3: Overwrite data blocks with 0x00 (Zero Fill - NIST Clear) + fsync()

[PHASE 3] Truncating file length to 0 bytes and syncing...
  [+] File truncated to 0 bytes (sync_all confirmed).

[PHASE 4] Unlinking directory entry from host filesystem...
  [+] Directory entry unlinked via remove_file().

[PHASE 5] Verifying post-erasure path non-existence...
  [+] Path verification confirmed: file no longer resolves on host filesystem.

[SCOPE DISCLOSURE (§36)]
  Host-level file erasure securely overwrites allocated file content and unlinks the
  directory pointer via the OS VFS layer. Journal and raw metadata scrubbing on live
  mounted OS volumes is mediated by the OS kernel. For raw block-level extent and MFT
  journal scrubbing on unmounted media, use the block-device pipeline.

================================================================================
  LOCAL FILE SANITIZATION RESULT: SUCCESS
  Total Bytes Overwritten: 56 bytes (0.05 KB)
  Final Status:            Sanitized (0 bytes remaining, unlinked)
================================================================================
```

The file is genuinely gone afterwards:

Command:
```bash
ls -la /tmp/vm/scratch_secret.txt
```

Output:
```
ls: cannot access '/tmp/vm/scratch_secret.txt': No such file or directory
```

> **Two steps in this pipeline report success without doing any work.** The `journal_scrubbed` and `free_after_overwrite_verified` flags in the result record are hardcoded to `true` in the source; no journal scrubbing is actually performed. The scope disclosure printed above is accurate about OS mediation, but the underlying flags are asserted rather than checked. Treat "journal scrubbed" as unverified.
>
> Note also that on a copy-on-write or log-structured filesystem, or on flash media with an FTL, overwriting a file's bytes in place is not guaranteed to overwrite the physical blocks that held the original data. This is a limitation of host-level file erasure generally, not of Vajra specifically.

---

## 14. Known limitations

Everything here was confirmed against the source, not inferred. These are the limitations a user would actually run into.

### 14.1 Acquisition

1. **RAW is the only output format.** No E01 writer exists; the acquisition engine is hardcoded to the RAW writer. E01 can be read but not produced.
2. **AFF4 is not implemented at all** — a stub that returns `UnsupportedFormat`.
3. **`acquire start` accepts only physical device paths**, not image files, so device-to-device or image-to-image acquisition is not possible.
4. **Post-acquisition verification re-reads the image, not the source.** It does not compare a fresh read of the original media against the image.
5. **Nothing has been verified against real hardware.** All acquisition tests drive an in-memory simulated device.

### 14.2 Device layer

6. **Linux device health is a hardcoded stub.** `query_device_health` returns `Good` with no SMART attributes for every device. Real SMART/NVMe queries exist on Windows only.
7. **Hardware write-blocker VID/PID detection never fires.** The table of known forensic blockers exists and is tested in isolation, but the enumeration code passes no VID/PID values to it, so detection falls back to vendor/model string matching plus the OS read-only flag.
8. **HPA/DCO detection is not implemented** on either platform, though the data type exists.

### 14.3 Carving

9. **Only fully valid objects are recovered at Tier 2.** Truncated files produce a `V_EOF` result and no artifact.
10. **Tier 2 reads a window capped at 1 MB per candidate.** Files larger than that may not validate within the window. For OLE2 specifically, a compound file larger than ~1 MB will return `V_EOF` and not be recovered.
11. **OLE2 truncation with a zero-filled tail is undetectable.** The CFB format has no checksums anywhere, so a compound file whose trailing sectors were zeroed still validates as intact. This is a property of the format, not a bug.
12. **New file *signatures* need no rebuild; new *validators* do.** The signature database is data, but the validator registry is compiled in.
13. **The ML classifier knows six classes only.** OLE2 classifies as `unknown`, marginally lowering the entropy component of its confidence score.

### 14.4 Sanitization

14. **All controller-native sanitize commands fail on real hardware** — see the table in [13.1](#131-what-actually-works-on-real-hardware--the-important-table). Only host-level overwrite executes.
15. **The decision engine recommends methods that cannot be executed** on SSD, NVMe and SED media.
16. **`journal_scrubbed` and `free_after_overwrite_verified` are hardcoded `true`** in file erasure and reflect no actual check.
17. **Sanitization certificates never carry a trusted timestamp** — the field is a hardcoded "not available" string, even though the report engine has a working RFC 3161 client.

### 14.5 Reports, audit and storage

18. **The case database is not encrypted at rest.** The code issues a SQLCipher `PRAGMA key`, but `rusqlite` is built with the plain-SQLite `bundled` feature, so the pragma is silently ignored. Despite the crate describing itself as encrypted persistence, the `.db` file is ordinary unencrypted SQLite. **Protect the case database with filesystem or full-disk encryption.**
19. **Signing keys are ephemeral.** A fresh Ed25519 keypair is generated per report-generator instance and never persisted, so signatures prove integrity but not durable operator identity. Certificates are self-signed with no CA.
20. **RFC 3161 responses are not validated** even when received, and the client silently falls back to local time.
21. **There is no PDF report output.**
22. **There is no log retention, rotation or archival mechanism.** Cases are undeletable once closed.
23. **"External anchoring" writes a local file.** There is no integration with any external notary, ledger or write-once medium.

### 14.6 Documentation

24. **The built-in `help` output is stale** in four places — see [5.4](#54--the-built-in-help-text-is-stale--trust-this-manual-instead).

---

## 15. Troubleshooting

### "Failed to open physical drive: Device not found" when you passed an image path

Command:
```bash
./target/debug/vajra-cli carve run /tmp/vm/nope.img
```

Output (tail):
```
[-] Error: Failed to open physical drive: Device not found: /tmp/vm/nope.img
```

**Cause:** the source resolver falls through to "physical device" when the path does not exist as a file (see [5.3](#53-sources-accepted-by-fs-carve-and-image-inspect)). The message mentions a drive because that was the last thing tried.

**Fix:** check the path. This is nearly always a typo or a missing test image — run the generator scripts from [4.3](#43-generate-the-synthetic-test-corpora). Exit code `1`.

### "Permission denied opening /dev/… (root privileges required)"

**Cause:** raw block-device access needs elevated privileges.

**Fix:** run with `sudo` on Linux or from an elevated prompt on Windows. If you are already root and still see this — as in the environment used to verify this manual — the container or VM is denying device access at a level above the process, and there is no workaround from within the application.

### `panic: Test image not found` when running `cargo test`

**Cause:** `test_data/carve_test.img` is gitignored and absent from a fresh clone.

**Fix:** `python3 scripts/generate_carve_corpus.py`.

### "Unknown command" / usage message and exit code 1

Command:
```bash
./target/debug/vajra-cli frobnicate
```

Prints `Unknown command: 'frobnicate'` followed by the full usage text. Exit code `1`.

Missing subcommand arguments produce a targeted usage line instead:

Command:
```bash
./target/debug/vajra-cli case create
```

Output:
```
Usage: vajra-cli case create <ID> <NAME> <INVESTIGATOR_ID>
```

Exit code `1`.

### A command's help text disagrees with what it accepts

Trust the reference table in [5.2](#52-complete-command-reference). The built-in help is stale in four known places — see [5.4](#54--the-built-in-help-text-is-stale--trust-this-manual-instead). Most commonly this bites with `audit log` and `audit anchor export`, both of which need an operator argument the help omits.

### `fs detect` reports "Unknown" on an image you know has a filesystem

**Cause:** most often the filesystem does not begin at LBA 0 because the image contains a partition table.

**Fix:** find the partition's starting LBA and pass `--partition-offset N`.

### A report shows "Local timestamp — RFC 3161 unavailable"

This is expected on any offline machine and is not an error. See [11.4](#114-about-the-timestamp-attestation).

### `vajra-verify` reports TAMPER DETECTED

Checks 1 and 2 failing together means the content was modified after signing. Check 4 failing means the embedded audit-chain segment is broken. Exit code `1`. If you did not expect this, treat the report as untrustworthy and regenerate it from the case database.

---

## 16. UI guide — TODO

**This section is intentionally empty and will be written once the Tauri UI is integrated.**

The desktop UI is under development by Nitya and Hari Priya using Rust and Tauri. At the time of writing, `crates/vajra-tauri-app` contains only a `main.rs` stub, so there is no interface to document and no screenshots to take. Writing speculative UI instructions now would guarantee they are wrong.

When the UI lands, this section should cover:

- [ ] Installation and first launch
- [ ] Screen inventory and navigation
- [ ] Creating a case and registering evidence
- [ ] Device selection, with the write-blocker and system-disk indicators
- [ ] Acquisition progress, checkpoint and resume
- [ ] The recovery results view, including the disk/block map visualisation
- [ ] Confidence and provenance display for a selected artifact
- [ ] Report generation and in-app verification
- [ ] The sanitization flow, both confirmation dialogs, and the five-layer verification display
- [ ] Screenshots for each of the above

Sections 6–13 of this manual should then gain a short "In the UI" subsection each, **alongside** the existing CLI instructions rather than replacing them — the CLI remains the reference interface and the one exercised by the automated tests.

The demo script should also be revisited at that point to decide, flow by flow, whether the CLI or the UI tells the story better.

---

## 17. Quick demo workflow

### Safe synthetic recovery-and-report demo

**This is deliberately not a complete forensic pass.** It starts from synthetic forensic images that already exist on disk, because **successful physical-device acquisition could not be demonstrated in the documentation environment** (see [8.2](#82-starting-an-acquisition)). The acquisition step — attaching real evidence media and imaging it — is therefore absent from the sequence below, and its absence is the point at which this demo differs from a real investigation.

**The final SIH forensic demo must add acquisition once real-hardware testing is complete.** Until then, this sequence covers everything downstream of acquisition: recovery through two independent mechanisms, provenance, the audit trail, signed reporting, independent verification, and the sanitization assurance loop.

Every step runs on synthetic images or the in-memory mock, needs no special privileges, and touches no physical device. The full sequence below was executed from a clean temporary database immediately before publication and reproduces as shown.

**Step 0 — prepare, from a clean state.**

Command:
```bash
rm -rf /tmp/demo.db /tmp/demo_reports /tmp/demo_recovered.pdf /tmp/demo.anchor.json
cargo build -p vajra-cli -p vajra-verify
python3 scripts/generate_carve_corpus.py
python3 scripts/generate_ground_truth_images.py
```

> **Start from a clean database every time you rehearse this.** Case IDs are unique, so re-running Step 1 against an existing `/tmp/demo.db` fails with `UNIQUE constraint failed: cases.case_id` and exit code 1. The `rm -rf` line above is what makes the sequence repeatable — do not skip it, particularly when practising the demo more than once.

**Step 1 — open a case.**

Command:
```bash
./target/debug/vajra-cli --db /tmp/demo.db case create CASE-DEMO-01 "SIH Demonstration" INV-VAIBHAVI
```

**Step 2 — identify the evidence image.**

Command:
```bash
./target/debug/vajra-cli image inspect test_data/fat32_test.img
./target/debug/vajra-cli fs detect test_data/fat32_test.img
```

Establishes the container format, size, fingerprint, and that the filesystem is FAT32.

**Step 3 — Tier 1: recover a deleted file from surviving metadata.**

Command:
```bash
./target/debug/vajra-cli fs list test_data/fat32_test.img --show-deleted
./target/debug/vajra-cli fs inspect test_data/fat32_test.img 4
./target/debug/vajra-cli fs dump test_data/fat32_test.img 4 /tmp/demo_recovered.pdf
```

Recovers `confidential_plan.pdf` with a SHA-256 of the extracted payload.

**Step 4 — Tier 2 and 3: carve where metadata is gone.**

Command:
```bash
./target/debug/vajra-cli carve run test_data/carve_test.img
```

Six artifacts across two tiers, including one reassembled from two fragments across an 8-sector gap — and zero false positives from the three deliberately corrupted candidates.

**Step 5 — show the provenance behind one result.**

Command:
```bash
./target/debug/vajra-cli carve inspect test_data/carve_test.img 2003
```

Six named confidence signals, each individually inspectable. This is the answer to "why should I believe this recovery?"

**Step 6 — record the audit trail and anchor it.**

Command:
```bash
./target/debug/vajra-cli --db /tmp/demo.db audit log CASE-DEMO-01 INV-VAIBHAVI CarveRun test_data/carve_test.img SUCCESS
./target/debug/vajra-cli --db /tmp/demo.db audit verify CASE-DEMO-01
./target/debug/vajra-cli --db /tmp/demo.db audit anchor export CASE-DEMO-01 INV-VAIBHAVI /tmp/demo.anchor.json
```

**Step 7 — generate a signed report.**

Command:
```bash
./target/debug/vajra-cli --db /tmp/demo.db report generate CASE-DEMO-01 exam \
  --out-dir /tmp/demo_reports --notes "Tier 1 + Tier 2/3 recovery demonstration"
```

**Step 8 — verify it with the independent tool.**

Command:
```bash
./target/debug/vajra-verify /tmp/demo_reports/forensicexamination_*.vjr
```

Five checks pass; exit code 0. Then edit one character of the `.vjr` and run it again to watch checks 1 and 2 fail and the status flip to `TAMPER DETECTED / INVALID`.

**Step 9 — the sanitization assurance loop.**

Command:
```bash
./target/debug/vajra-cli erase run --mock samsung_pm9a3_nvme --operator INV-VAIBHAVI
./target/debug/vajra-cli erase run --mock samsung_pm9a3_nvme --incomplete --operator INV-VAIBHAVI
```

The first run passes all five layers and issues a certificate capped honestly at MEDIUM assurance. The second leaves a recoverable artifact behind: Layers 1–4 still report PASS, Layer 5 finds the artifact, and the overall result becomes FAILED.

**Both runs are safe** — the target is an in-memory mock and no hardware is touched.

---

## Document history

| Date | Author | Change |
|---|---|---|
| 2026-09-01 | Vaibhavi | First edition. CLI/backend only; every command example executed and captured live. Acquisition workflow documented as not demonstrable in the verification environment. UI guide deferred pending Tauri integration. |
| 2026-09-02 | Vaibhavi | Added verification-status distinctions, scoped corpus precision/recall claims, clarified IEEE 2883 certificate-label limitation, and re-verified the safe synthetic demo workflow. |
