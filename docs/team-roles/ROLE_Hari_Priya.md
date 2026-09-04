# Vajra — Your Role: UI Co-Lead — Visualization & Integration Layer
## Hari Priya

This document is derived from `Vajra_Master_Technical_Document.md` (the full project blueprint — keep it in the repo, refer back to it constantly; section numbers below (§NN) always refer to it). It summarizes what Syed has already built, then defines your specific scope.

---

## Part 1 — What's Already Built (read this before touching anything)

Everything below is a working, tested Rust backend — 8 conversations, each independently verified with real terminal output and (where safe) real hardware.

- **Foundation & Device Layer**: `vajra-core` (the `ReadOnlyBlockSource`/`WritableBlockSource` type-level split, `DeviceFingerprint`, `IoError`, `MediaType`), `vajra-device` (Windows+Linux enumeration, health, write-blocker/boot-disk detection).
- **Evidence Vault, Audit Log & Chain of Custody**: `vajra-case-db`, `vajra-audit` (hash-chained log, X.509 signing, external anchoring), `vajra-custody`.
- **Evidence Acquisition & Imaging**: `vajra-acquire` (bad-sector map, checkpoint/resume), `vajra-image` (RAW/E01).
- **Filesystem Parsers**: `vajra-fs-ntfs`/`ext4`/`fat` — produce `RecoverableFileEntry` records with `DataLocation` (Contiguous/Fragmented/Resident/Unresolved) and `MetadataConfidence`.
- **File Carving & Recovery Engine**: `vajra-carve` — the three-tier pipeline (Tier 1 metadata, Tier 2 signature+structural-validator, Tier 3 fragment reconstruction), producing `RecoveredArtifact` records with full `ConfidenceBreakdown` (six named, weighted signals) and fragment provenance (source LBAs, gap size, both fragment ranges). **This is the data model your Recovery Browser and Hex/Raw Explorer are built around — read Conversation 05's agent-log in full before starting, the exact struct shapes matter.**
- **Sanitization Engine**: `vajra-erase`/`vajra-file-erase` — the two-phase `DeviceConfirmationGate` (`begin()`/`finalize()`), producing a `SanitizationAuthorizationToken` that gates every destructive call. **You need the exact API shape of this gate before wiring the Safety/Policy Engine's UI-side enforcement — read Conversation 06's agent-log in full.**
- **ML/AI Layer**: `vajra-ml` — feeds explainable feature-importance data into `RecoveredArtifact`'s confidence breakdown when active.
- **Reporting & Independent Verifier**: `vajra-audit` report generation, `vajra-verify` (a genuinely independent standalone checker).

---

## Part 2 — Your Scope: Data-Heavy Visualization + the IPC/Safety Layer

You own the more backend-adjacent half of the UI — the screens that display complex recovery/device data, and the plumbing that connects the UI to the Rust backend safely. Coordinate closely with Nitya (she owns the workflow screens — Dashboard, Acquisition Wizard, Sanitization Console) on shared design tokens so the app feels like one product.

### 2a. Recovery Browser

- Grid/list view of `RecoveredArtifact` records — filterable by type/confidence tier/recovery tier (Tier 1/2/3).
- Per-artifact detail panel showing the full `ConfidenceBreakdown` (all six signals with their weights and values, not just the composite score — §29's whole design point is that the breakdown is more meaningful than the number alone) and the `recovery_limitations` text field (§31 — never hide or summarize this away, it's explicit for a reason).

### 2b. Hex/Raw Data Explorer (§32)

- Hex view, raw sector map, filesystem-mapping overlay for any recovered artifact.
- **For fragmented files specifically**: visually mark original fragments, gaps, and reconstructed regions with their source LBAs — this directly uses the fragment provenance data Conversation 05 built (gap_size, both fragment LBA ranges). This is one of the highest-value features for making the recovery algorithm demonstrable/understandable at a glance — prioritize getting this specific view right, it's genuinely a good demo centerpiece per the blueprint's own note about this.

### 2c. Storage/Block Visualization (§32)

- A colored bar/map across a drive's LBA range: allocated, unallocated, bad-sector, recovered-fragment, and (during Sanitization Mode) sanitized regions.
- Shown both during Forensic Mode analysis and during Sanitization Mode execution — coordinate with Nitya on how this embeds into her Sanitization Console screen versus standing alone in your Recovery Browser context.

### 2d. Tauri ↔ Rust IPC Bridge

- The typed command/event bridge connecting the React frontend to the actual backend crates (not mock data — every screen should call real Rust functions).
- Reference §18's IPC rationale: Tauri's typed command system reduces "UI sent malformed parameters to a destructive operation" bugs — lean into strong typing here specifically for anything touching `vajra-erase`.

### 2e. Safety/Policy Engine — UI-Side Enforcement (§13, §15, §43)

- The architecture diagram (§13) places a Safety/Policy Engine between the UI and every backend engine. Your job: make sure the UI genuinely cannot reach a destructive call without passing through the real backend gate — i.e., the UI should hold and pass through the actual `SanitizationAuthorizationToken` from Conversation 06's gate, not reimplement a parallel "looks safe" check in JavaScript/TypeScript that could drift from the real Rust enforcement.
- Confirm and document: is there any UI code path that could call a `vajra-erase` destructive function without a valid token from the real gate? There should be zero.

## Suggested Antigravity Conversation Structure

Same format as the backend conversations: **Step 0** (read §32, §13, §15, §18, §43 in full, plus Conversation 05's and Conversation 06's agent-logs in full — you specifically need their exact struct/API shapes, don't guess), implementation broken down Recovery Browser → Hex Explorer → Storage Visualization → IPC/Safety wiring, **Definition of Done** including a real demonstration that the safety-gate enforcement is genuinely backend-sourced, not a UI-side approximation.

## Definition of Done

- [ ] Recovery Browser and Hex/Raw Explorer built against real `RecoveredArtifact` data from `vajra-carve`
- [ ] Storage Visualization built and integrated into both Forensic and Sanitization Mode contexts
- [ ] IPC bridge connects every screen to real backend calls, no mock data remaining
- [ ] Explicit confirmation (with reasoning shown) that no UI code path can reach a destructive operation without holding a real `SanitizationAuthorizationToken` from the backend gate
- [ ] Coordinated with Nitya on shared visual language (mode-separation colors, component styling) so the app is coherent
