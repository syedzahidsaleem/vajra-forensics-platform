# Conversation 04 — Filesystem Parsers (`vajra-fs-ntfs`, `vajra-fs-ext4`, `vajra-fs-fat`)

**Date:** 2026-08-30  
**Scope:** Offline-First Tier-1 Filesystem Analysis and Recovery Engines  
**Crates Implemented:** `vajra-core` (fs module), `vajra-fs-fat`, `vajra-fs-ext4`, `vajra-fs-ntfs`, `vajra-cli` (`fs` subcommands)  
**Reference Codebase Consulted:** The Sleuth Kit (TSK) v4.12+ (`reference/sleuthkit/tsk/fs/`)

---

## 1. Architectural Overview & Shared Contracts

Per §25 and §29 of the Vajra Master Technical Document, Tier-1 Filesystem-Aware Recovery is the highest-confidence recovery tier in digital forensics. Unlike naive file carving (Tier-2), filesystem parsers leverage surviving on-disk metadata records to reconstruct exact original filenames, folder hierarchies, directory timestamps, and complete physical extent maps.

### 1.1 Canonical Domain Types (`vajra-core::fs`)
- **[`RecoverableFileEntry`](file:///d:/Coding/Vajra/crates/vajra-core/src/fs.rs)**: The unified cross-filesystem output structure consumed by Tier-1 recovery and the upcoming Tier-2 carving engine:
  - `id`: Numeric record/inode identifier (MFT record number, Inode number, or start cluster).
  - `original_path`: Full reconstructed directory path (`Option<String>`).
  - `filename`: Recovered filename (`Option<String>`).
  - `size_bytes`: Logical file size in bytes (`Option<u64>`).
  - `created`, `modified`, `accessed`: Standardized UTC timestamps (`Option<DateTime<Utc>>`).
  - `deleted`: Boolean indicating active (`false`) vs unallocated/deleted (`true`) status.
  - `data_location`: Physical block location mapping (`DataLocation`).
  - `metadata_confidence`: Calibrated confidence assessment (`MetadataConfidence`).
  - `source_filesystem`: Classified originating filesystem (`FilesystemType`).
- **[`DataLocation`](file:///d:/Coding/Vajra/crates/vajra-core/src/fs.rs)**:
  - `Resident(Vec<u8>)`: Small payloads embedded directly inside metadata structures (e.g. NTFS resident `$DATA`).
  - `Contiguous { start_lba, block_count }`: Single contiguous range of physical blocks.
  - `Fragmented(Vec<(u64, u64)>)`: Multi-extent fragmented allocations.
  - `Unresolved`: Metadata recovered but block pointers zeroed or missing.
- **[`MetadataConfidence`](file:///d:/Coding/Vajra/crates/vajra-core/src/fs.rs)**:
  - `Confirmed`: Metadata is 100% intact and cluster bitmap confirms data blocks remain unallocated or active.
  - `Partial`: Metadata is intact, but some data blocks may have been overwritten or reallocated.
  - `Reconstructed`: Recovered from transactional journal/log replay or directory slack.
  - `Low`: Corrupted or incomplete metadata record.

### 1.2 Strict Filesystem Signature Detection Priority
To avoid false positives where generic MBR boot code (containing `0x55, 0xAA` at bytes 510..511) is misclassified as FAT, [`detect_filesystem`](file:///d:/Coding/Vajra/crates/vajra-core/src/fs.rs) enforces strict signature evaluation priority:
1. **NTFS**: Boot sector OEM ID at offset 3..11 strictly equals `b"NTFS    "`.
2. **exFAT**: Boot sector OEM ID at offset 3..11 strictly equals `b"EXFAT   "`.
3. **ext4 / ext3 / ext2**: Superblock magic `0xEF53` at byte offset 1080 (LBA 2).
4. **APFS**: Container superblock magic `b"NXSB"` at offset 32.
5. **FAT32 / FAT16 / FAT12**: Requires BOTH valid jump instruction (`0xEB` or `0xE9`) AND `0x55, 0xAA` signature AND valid BPB geometry (power-of-2 sectors/cluster <= 128, valid sector size, num FATs in {1,2}, reserved sectors > 0) combined with `fat_size_16 == 0` or cluster count thresholds.

---

## 2. Crate Implementations & SleuthKit Citations

### 2.1 `vajra-fs-fat` (FAT12/16/32 Parser)
*TSK Reference: `reference/sleuthkit/tsk/fs/fatfs.c`, `fatxxfs.c`, `fatxxfs_dent.c`*
- **BPB Geometry Parsing ([`bpb.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-fat/src/bpb.rs))**: Decodes sectors per cluster, reserved sectors, FAT table sizes, and computes precise LBAs for cluster indexes, FAT tables, and root directories.
- **FAT Allocation Tables ([`fat_table.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-fat/src/fat_table.rs))**: Traverses cluster chains, detects EOF markers (`>= 0x0FFFFFF8`), loop detection via visited sets, and checks cluster free status (`0x00000000`).
- **Deleted Entry & LFN Recovery ([`dir_entry.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-fat/src/dir_entry.rs))**:
  - Identifies deleted standard entries by lead byte `0xE5`.
  - Reconstructs multi-entry Long Filename (LFN) sequences across both active and deleted files. For deleted LFNs (where `seq_num` is overwritten with `0xE5`), the sequence is reconstructed by reversing the on-disk chunk order.
  - Converts MS-DOS 16-bit packed Date and Time fields to UTC timestamps.
- **Directory Slack Scanning ([`parser.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-fat/src/parser.rs))**: Deep-scans unallocated cluster space for orphaned 32-byte directory fragments.

### 2.2 `vajra-fs-ext4` (ext4 Parser)
*TSK Reference: `reference/sleuthkit/tsk/fs/ext2fs.c`, `ext2fs_dent.c`, `ext2fs_journal.c`*
- **Superblock & Group Descriptors ([`superblock.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ext4/src/superblock.rs), [`group_desc.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ext4/src/group_desc.rs))**: Parses 32-bit and 64-bit block group descriptor tables to resolve `inode_table_block` locations.
- **Modern Extent Trees & Legacy Indirect Blocks ([`inode.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ext4/src/inode.rs))**:
  - Evaluates `0xF30A` extent tree headers (`ext4_extent_header`, `ext4_extent`, `ext4_extent_idx`) with recursive multi-level depth traversal.
  - Supports legacy direct (0..11) and indirect block pointers.
- **Directory Entry & Slack Space Scanning ([`dir.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ext4/src/dir.rs))**:
  - Parses `ext4_dir_entry_2` records.
  - Inspects intra-record slack space where unlinking expanded `rec_len` over deleted directory entries, recovering the original inode and filename.
- **Inode Table Sweep ([`parser.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ext4/src/parser.rs))**: Scans all inode tables across all block groups to locate unlinked inodes (`i_dtime > 0` or `i_links_count == 0` with surviving extents).

### 2.3 `vajra-fs-ntfs` (NTFS Parser)
*TSK Reference: `reference/sleuthkit/tsk/fs/ntfs.c`, `tsk_ntfs.h`, `usn_journal.c`*
- **Update Sequence Fixup ([`mft.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ntfs/src/mft.rs))**: Implements verbatim TSK multi-sector fixup array replacement across 1024-byte MFT records before attribute parsing.
- **MFT Attributes**:
  - `$STANDARD_INFORMATION` (0x10): Converts 64-bit Windows FILETIME (100ns intervals since 1601) to UTC timestamps.
  - `$FILE_NAME` (0x30): Extracts Win32, DOS, and POSIX filenames, parent MFT references, and file sizes.
  - `$DATA` (0x80):
    - Resident: Extracts inline byte buffer directly into `DataLocation::Resident`.
    - Non-Resident: Decodes variable-length compression runlists (signed delta LCN calculations) into physical LBA extents.
- **Bitmap & Confidence Assessment ([`bitmap.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ntfs/src/bitmap.rs))**: Cross-references cluster allocations against `$Bitmap` to calibrate `MetadataConfidence::Confirmed` vs `MetadataConfidence::Partial`.
- **Quick-Format Surviving MFT Scanner ([`parser.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ntfs/src/parser.rs))**: Deep-scans unallocated cluster space across the volume to discover and recover surviving MFT record clusters from previous filesystem instances.
- **Journal & VSS Presence ([`journal.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ntfs/src/journal.rs), [`vss.rs`](file:///d:/Coding/Vajra/crates/vajra-fs-ntfs/src/vss.rs))**: Parses USN Change Journal records (`$UsnJrnl:$J`) and flags Volume Shadow Copy snapshot stores.

---

## 3. Empirical ext4 Unlink Behavior Verification

Per §25 requirement ("must be verified empirically, not assumed"), raw inode and directory structure behavior upon file deletion was tested against a Linux kernel/e2fsprogs 1.47.2 generated filesystem image.

### Empirical Findings:
1. **Directory Slack Entry Retention**:
   - When a file (e.g. `secret_deleted.txt`, inode 14) is unlinked, the ext4 driver does not zero out the directory entry. Instead, it expands the `rec_len` field of the preceding active entry (`live_evidence.txt`, inode 13) from 16 bytes to `4040` bytes to cover the rest of the 4096-byte directory block.
   - The directory entry bytes at byte offset `16444` (`0x403C`) remain completely intact:
     - `inode`: `0x0000000E` (14)
     - `name_len`: `0x12` (18 bytes)
     - `file_type`: `0x01` (regular file)
     - `name`: `"secret_deleted.txt"`
2. **Inode Extent Tree & Metadata Preservation**:
   - Inode 14's size (`73` bytes), extent tree header (`0xF30A`), extent leaf mapping to block `1228` (`(0):1228`), flags (`0x80000`), and timestamps are completely preserved.
   - Data block `1228` remains untouched and contains the ground-truth payload.
   - `vajra-fs-ext4`'s directory slack scanner successfully discovers this unlinked entry, correlates it with inode 14, and recovers the file content byte-for-byte.
3. **Block Allocation Bitmap Checking & Confidence Calibration**:
   - `Ext4BlockBitmap::load_all` reads block group bitmaps (`bg.block_bitmap_block`).
   - When inode 14's data block 1228 is checked against the block bitmap, bit 1228 is confirmed free (0), resulting in `MetadataConfidence::Confirmed` rather than a generic fallback.

---

## 4. Partition Offset Handling & Scope

**Explicit Scope Decision:** Manual `--partition-offset N` entry (defaulting to LBA 0 for raw partition/volume images) is a deliberate scope decision for Conversation 04, while `vajra-device`'s Conversation 01 GPT/MBR partition detection remains available for inspecting multi-partition disk images and physical drives via `vajra-cli device inspect`.

- **Safety Invariant (§16)**: All filesystem crates operate exclusively on `&mut dyn ReadOnlyBlockSource`. No writable block traits are imported or exposed, guaranteeing mathematical impossibility of write operations against source evidence.

---

## 5. Ground-Truth Test & Verification Summary

### 5.1 Named Unit Tests in `vajra-core`
The following specific, named tests prove signal priority and verify that generic MBRs and other filesystems are never misclassified as FAT:
- `fs::tests::test_detect_ext4_signature_and_no_fat_misidentification`: Proves that a boot sector containing `0x55, 0xAA` with an ext4 superblock at byte 1080 is detected as `FilesystemType::Ext4` and never misclassified as FAT.
- `fs::tests::test_generic_mbr_not_misidentified_as_fat`: Proves that a generic MBR with `0x55, 0xAA` boot signature but lacking valid BPB geometry/jump instructions yields `FilesystemType::Unknown` rather than FAT.
- `fs::tests::test_detect_ntfs_signature`: Proves NTFS OEM ID detection priority.
- `fs::tests::test_detect_fat32_signature`: Proves FAT32 detection with valid BPB geometry.

### 5.2 Automated Ground-Truth Integration Tests (`vajra-cli`)
- `test_fat32_ground_truth_recovery`: PASSED (Active + Deleted LFN recovered byte-for-byte, `MetadataConfidence::Confirmed`).
- `test_ext4_ground_truth_recovery`: PASSED (Active + Deleted directory slack recovered byte-for-byte, `MetadataConfidence::Confirmed`).
- `test_ntfs_ground_truth_recovery`: PASSED (Active resident + Deleted non-resident recovered byte-for-byte, `MetadataConfidence::Confirmed`).
- `test_ntfs_quickformat_scenario_recovery`: PASSED (Pre-format resident MFT record recovered across quick-format boundary, `MetadataConfidence::Confirmed`).

### 5.3 Live CLI Demonstration Evidence:
```
$ vajra-cli fs detect test_data/fat32_test.img
  Detected Filesystem: FAT32
  Parser Engine:       vajra-fs-fat (FAT32 Cluster Chains, 8.3 & LFN Slack Recovery)

$ vajra-cli fs detect test_data/ext4_test.img
  Detected Filesystem: ext4
  Parser Engine:       vajra-fs-ext4 (Extent Trees, Inode Tables, Directory Slack)

$ vajra-cli fs detect test_data/ntfs_test.img
  Detected Filesystem: NTFS
  Parser Engine:       vajra-fs-ntfs (MFT, $LogFile, USN Journal, $Bitmap)

$ vajra-cli fs list test_data/fat32_test.img
ID       | STATUS    | SIZE (B)   | CONFIDENCE         | FILENAME                     | ORIGINAL PATH
3        | [ACTIVE]  | 70         | Confirmed          | active_document.txt          | /active_document.txt
4        | [DELETED] | 75         | Confirmed          | confidential_plan.pdf        | /confidential_plan.pdf

$ vajra-cli fs list test_data/ext4_test.img
ID       | STATUS    | SIZE (B)   | CONFIDENCE         | FILENAME                     | ORIGINAL PATH
13       | [ACTIVE]  | 64         | Confirmed          | live_evidence.txt            | /live_evidence.txt
14       | [DELETED] | 73         | Confirmed          | secret_deleted.txt           | /secret_deleted.txt

$ vajra-cli fs list test_data/ntfs_test.img
ID       | STATUS    | SIZE (B)   | CONFIDENCE         | FILENAME                     | ORIGINAL PATH
30       | [ACTIVE]  | 55         | Confirmed          | system_audit.log             | /system_audit.log
31       | [DELETED] | 69         | Confirmed          | financial_records_2026.xlsx  | /financial_records_2026.xlsx

$ vajra-cli fs list test_data/ntfs_quickformat.img
ID       | STATUS    | SIZE (B)   | CONFIDENCE         | FILENAME                     | ORIGINAL PATH
2000     | [DELETED] | 80         | Confirmed          | pre_format_evidence.docx     | /pre_format_evidence.docx

$ vajra-cli fs dump test_data/fat32_test.img 4 /tmp/recovered_fat32.pdf
[+] File extracted successfully (§25):
  Output File:         /tmp/recovered_fat32.pdf
  Extracted Size:      75 bytes
  Payload SHA-256:     23ec5df7d91b96534efb36deddccf910bf753d45c41af84d9eebe45a5c634882
  Metadata Confidence: Confirmed (Metadata Intact & Blocks Free)
```

---

## 6. Handoff Contract for Conversation 05 (`vajra-carve`)

- `vajra-core::fs::RecoverableFileEntry` serves as the primary output of Tier-1 recovery.
- Conversation 05 (`vajra-carve`) will consume unallocated blocks identified by `vajra-fs-*` bitmap analysis to execute signature/heuristic Tier-2 carving without scanning already-recovered allocated blocks.
