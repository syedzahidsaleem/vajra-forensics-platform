# Vajra — Your Role: Project Lead & Advanced Storage Features
## Syed Zahid

This document is derived from `Vajra_Master_Technical_Document.md` (the full project blueprint — keep it in the repo, refer back to it constantly; section numbers below (§NN) always refer to it). It summarizes what's already built, then defines your specific scope for the next phase.

---

## Part 1 — What's Already Built (read this before touching anything)

Across 8 Antigravity conversations, the full backend was built and independently verified — every claim below is backed by real terminal output, real hardware testing where the operation was read-only, and mock/simulated devices for every destructive operation (per the project's standing safety rule: no destructive operation has ever been run against real hardware).

- **01 — Foundation & Device Layer**: `vajra-core` (the `ReadOnlyBlockSource`/`WritableBlockSource` type-level safety split — this is the single most important architectural decision in the codebase; `DeviceFingerprint`, `IoError`, `MediaType`, `SanitizeMethod`), `vajra-device` (Windows + Linux device enumeration, SMART/NVMe health diagnostics, hardware write-blocker detection, boot-disk detection including LVM/device-mapper slave traversal), `vajra-cli` skeleton.
- **02 — Evidence Vault, Audit Log & Chain of Custody**: `vajra-case-db` (SQLCipher-encrypted §22 schema, two-state case tombstoning — Active→Closed only, enforced by DB triggers), `vajra-audit` (hash-chained `AuditEntry` log, X.509/Ed25519 signing, external chain-head anchoring — defends against a fully-compromised machine regenerating a self-consistent forged history), `vajra-custody` (state-machine-validated custody events with honest, non-overclaiming framing).
- **03 — Evidence Acquisition & Imaging**: `vajra-acquire` (physical/logical/partial profiles, §20's bad-sector retry→reduce→mark-unreadable flowchart with a non-ambiguous placeholder and an authoritative `BadSectorMap`, dual-phase rolling+independent-re-read hashing, checkpoint/resume verified against device fingerprint), `vajra-image` (RAW/DD full read+write, E01 read via the `ewf` crate, AFF4 stubbed for future work).
- **04 — Filesystem Parsers**: `vajra-fs-ntfs` ($MFT resident+non-resident, $Bitmap-cross-referenced confidence, $LogFile/$UsnJrnl, VSS detection, verified against a real quick-format scenario), `vajra-fs-ext4` (superblock/group-descriptor/inode/extent-tree, empirically-verified unlink behavior, block-bitmap-verified confidence), `vajra-fs-fat` (FAT chain, 8.3+LFN including deleted-entry recovery). Shared `RecoverableFileEntry`/`DataLocation`/`MetadataConfidence` types and `detect_filesystem` live in `vajra-core`.
- **05 — File Carving & Recovery Engine**: `vajra-carve` — Tier 1 (thin orchestration over `vajra-fs-*` with `AllocatedBlockMap` precedence), Tier 2 (extensible external signature database + Garfinkel's V_OK/V_ERR/V_EOF validator framework for JPEG/PNG/PDF/ZIP/SQLite), Tier 3 (2-fragment Bifragment Gap Carving with the empirically-derived gap-search order), the full §29 six-signal confidence formula with named tunable weights, §31 `RecoveredArtifact` provenance.
- **06 — Sanitization Engine**: `vajra-erase` (a two-phase `begin()`/`finalize()` device-confirmation gate producing an unforgeable `SanitizationAuthorizationToken`, the §34 Sanitization Decision Engine, §35 per-media-type methods including nwipe-derived CSPRNG/IO patterns, §37's five-layer verification with the Layer-5 vajra-carve-based override rule, §38 Sanitization Certificates with a structural cap preventing HIGH assurance from ever being claimed for host-overwrite-on-flash-media), `vajra-file-erase` (block-level pipeline for images/unmounted media, a separate live-OS-file primitive, five-state Residual Artifact Scanner).
- **07 — ML/AI Layer**: `vajra-ml` — a CPU-only, pure-Rust, explainable file-type classifier wired into `vajra-carve`'s `EntropyAnalyzer` trait as a swap-in for the earlier heuristic, with per-prediction feature-importance shown, trained on an honestly-scoped synthetic corpus.
- **08 — Reporting & Independent Verifier**: `vajra-audit` report generation (all six §41 report types pulling real data from every crate above, RFC 3161 timestamping with graceful offline fallback), `vajra-verify` (a genuinely independent standalone binary — does not share verification logic with `vajra-audit` — implementing every §42 check, proven against multiple distinct tamper scenarios).

**Explicitly not yet built** — this is the pool the whole team's remaining work comes from: the Tauri+React UI, RAID, encrypted volumes, macOS device support, APFS/deeper exFAT, AFF4, N-fragment carving, additional file-type validators, the full §45–50 testing/calibration program, and standards/user-manual/demo documentation.

---

## Part 2 — Your Scope

You own two things: **advanced storage features** (extending the crates you already understand best) and **project integration** (merging everyone else's branches, resolving conflicts, keeping `docs/agent-log/` current as the single continuity mechanism for the whole team, same role it's played across all 8 conversations so far).

### 2a. RAID Reconstruction — `vajra-raid` (§15/Part III, §53)

Currently a stub crate. Build:
- RAID 0 (striping — detect stripe size/order from metadata, e.g. `mdadm` superblocks)
- RAID 5 (single XOR parity; implement **degraded-mode reconstruction** specifically — this is the realistic forensic scenario, per the blueprint's own emphasis)
- RAID 6 (dual parity, Reed-Solomon)
- Expose the reconstructed array as a `ReadOnlyBlockSource` — this is why the trait-based architecture from Conversation 01 pays off here: every downstream crate (`vajra-carve`, `vajra-erase`) needs zero RAID-specific logic once this exists.
- Scope reminder: local, directly-attached member drives only — never network-attached RAID (Part 0's exclusions still apply).

### 2b. Encrypted Volume Support — `vajra-crypto-vol` (§53)

Currently a stub crate. Build BitLocker/FileVault/LUKS unlock **given valid credentials only** — this is an explicit, non-negotiable design boundary (§8, §57): the tool unlocks volumes given a password/recovery key/keyfile the operator already lawfully has, never a bypass mechanism. Once unlocked, expose the decrypted volume as a standard `ReadOnlyBlockSource`/`WritableBlockSource` per the same pattern as everything else.

### 2c. macOS Device Support — extending `vajra-device`

Conversations 01–08 built Windows+Linux only, deliberately deferring macOS (per your own earlier decision). If time allows: extend `vajra-device`'s device enumeration for macOS (IOKit-based), being explicit about the SIP (System Integrity Protection) constraint documented in the blueprint — scope this to user-data and external volumes rather than fighting SIP for system-volume access, exactly as the blueprint recommends.

### 2d. Integration Lead

- Own merging Nitya/Hari Priya/Akanksha/Vaibhavi's branches back toward a shared integration point.
- Keep `docs/agent-log/` updated as each person's work lands — every prior conversation in this project wrote a numbered agent-log entry; continue that numbering (09-raid-crypto-vol.md, etc.) so the continuity mechanism holds for the whole team the same way it did for the solo backend build.
- Watch specifically for merge conflicts in `vajra-core` and `vajra-cli` — these are the two crates every other person's work will also touch (shared types, CLI subcommand registration).

## Suggested Antigravity Conversation Structure

Same format as Conversations 01–08: **Step 0** (read the exact blueprint sections above plus all 8 existing agent-logs), **Step 1+** (implementation broken into RAID → encrypted volumes → macOS, in that priority order since RAID/crypto-vol are more central to the platform's stated feature set), **Definition of Done** (real hardware testing where safe — read-only RAID/decrypt operations are non-destructive and fine to test against real hardware; write operations follow the same standing safety rule as every prior conversation), and a new agent-log entry.

## Definition of Done

- [ ] `vajra-raid` implements RAID 0/5/6 with degraded-mode reconstruction, exposed as `ReadOnlyBlockSource`
- [ ] `vajra-crypto-vol` implements BitLocker/FileVault/LUKS unlock given valid credentials, exposed as `ReadOnlyBlockSource`
- [ ] macOS device support added or explicitly scope-deferred with reasons documented
- [ ] All teammates' branches successfully merged with no unresolved conflicts
- [ ] `docs/agent-log/` continues the established numbering and format for every new piece of work landed
