# Vajra — Your Role: UI Lead
## Nitya

This document is derived from `Vajra_Master_Technical_Document.md` (the full project blueprint — keep it in the repo, refer back to it constantly; section numbers below (§NN) always refer to it). It summarizes what Syed has already built, then defines your specific scope.

---

## Part 1 — What's Already Built (read this before touching anything)

Everything below is a working, tested Rust backend — 8 conversations, each independently verified with real terminal output and (where safe) real hardware. **You are not building any of this — you are building the interface on top of it.**

- **Foundation & Device Layer**: `vajra-core` (the `ReadOnlyBlockSource`/`WritableBlockSource` split — this is why the UI can trust that read-only screens are *actually* read-only, not just conventionally so; `DeviceFingerprint`), `vajra-device` (real device enumeration, fingerprinting, SMART/NVMe health, write-blocker and boot-disk detection).
- **Evidence Vault, Audit Log & Chain of Custody**: `vajra-case-db` (encrypted case database — cases, evidence, operations), `vajra-audit` (tamper-evident audit log, digital signing), `vajra-custody` (custody event history).
- **Evidence Acquisition & Imaging**: `vajra-acquire` (device→forensic-image acquisition with bad-sector handling, progress reporting, resumability), `vajra-image` (RAW/E01 image formats).
- **Filesystem Parsers**: `vajra-fs-ntfs`/`ext4`/`fat` — parse deleted and active files with real confidence scores.
- **File Carving & Recovery Engine**: `vajra-carve` — the three-tier recovery pipeline producing `RecoveredArtifact` records with full confidence breakdowns and provenance (§31) — this is the data your Recovery Browser screen will display.
- **Sanitization Engine**: `vajra-erase`/`vajra-file-erase` — the device-confirmation gate, Sanitization Decision Engine, five-layer verification, and Sanitization Certificates — this is what your Sanitization Console screen wraps.
- **ML/AI Layer**: `vajra-ml` — a secondary, explainable signal feeding into recovery confidence; largely invisible to the UI except as extra detail in provenance display.
- **Reporting & Independent Verifier**: `vajra-audit` report generation (six report types) and the standalone `vajra-verify` tool — this is what your Report Center screen generates and can trigger verification of.

**Existing CLI (`vajra-cli`)** already exposes every one of these as commands (`list`, `fingerprint`, `health`, `case create`, `evidence add`, `audit verify`, `acquire start`, `fs list`, `carve run`, `carve inspect`, `erase run`, `file-erase run`, `report generate`, etc.) — this is your reference for exactly what data and operations exist to build a UI around. Read the actual CLI dispatch code before designing a screen; don't guess at what's available.

---

## Part 2 — Your Scope: The Core UI Shell and Workflow Screens

§43a of the blueprint names the exact screen inventory this project needs. You own the shell and the following screens (Hari Priya owns the remaining, more data-visualization-heavy ones — see her doc, coordinate with her on shared components like the device-list widget).

### 2a. Tauri + React App Shell — `vajra-tauri-app`

Currently a stub crate. This is where the actual desktop application lives:
- Set up the Tauri shell wrapping the existing Rust backend (§13, §18 — read the rationale for why Tauri specifically: no bundled Chromium runtime, no listening network port required for the IPC transport, which matters for this project's offline-first/no-network architecture constraint).
- Establish the base navigation/layout: **Case Dashboard** as the entry point, with navigation to every other screen.
- **Mode separation must be visually, not just functionally, distinct** (§15, §43a) — Forensic Mode (read-only: acquisition, recovery, analysis) and Sanitization Mode (destructive) need different color language and icon sets throughout, with no shared "in-progress" screen where the two could be confused. This is a safety requirement stated explicitly in the blueprint, not a design preference — treat it as a hard requirement in your component structure, not just a color choice.

### 2b. Case Dashboard

- Create/open a case, list evidence items and their custody status, case status (Active/Closed).
- Pulls from `vajra-case-db` / the `case`/`evidence` CLI commands' underlying functions.

### 2c. Device Selection Screen

- Enumerate connected devices with media-type badges, health-status indicators, and full fingerprint display **before any operation is offered** — this maps directly to `vajra-cli list`/`fingerprint`/`health`.

### 2d. Acquisition Wizard

- Guided flow: profile selection (physical/logical/partial) → image-format choice → live progress with throughput and bad-sector-map visualization → completion summary.
- Maps to `vajra-cli acquire start/status/resume/verify`.

### 2e. Sanitization Console

- This is the highest-stakes screen in the whole application — implement the **exact** safety sequence from §43, which Conversation 06 already built the backend enforcement for (`DeviceConfirmationGate::begin()`/`finalize()` — read this before building the UI flow, since the UI must call these in the same two-phase, non-collapsible sequence the backend enforces):
  1. Device fingerprint display
  2. Explicit initial confirmation (not a default-focused "OK" button)
  3. Sanitization Decision Engine's recommendation display (§34's exact "RECOMMENDED SANITIZATION / Reason: ..." format)
  4. A **second, separate** reconfirmation — deliberately placed after intervening screens, never satisfiable by the same click as step 2
  5. Type-to-confirm: operator types the device's displayed serial number
  6. Live, per-pass verification status during execution (§43a's "per-pass, not only post-completion, feedback" principle — don't just show a spinner until it's done)
  7. Final Sanitization Certificate display

### 2f. Report Center

- Generate/view/export the six report types (§41), and trigger `vajra-verify` from within the UI as a convenience (in addition to its standalone CLI use — §42 is explicit the standalone tool must remain independently usable, don't make it UI-only).

## Suggested Antigravity Conversation Structure

Same format the backend conversations used: **Step 0** (read §13, §15, §18, §43, §43a in full, plus the agent-logs for whichever backend crates a given screen wraps — e.g. read Conversation 06's agent-log in full before building the Sanitization Console, since the UI must mirror the backend's exact safety sequence, not invent its own), then implementation broken screen-by-screen, then **Definition of Done** including a live demonstration of the full mode-separation visual distinction and the Sanitization Console's exact confirmation sequence.

## Definition of Done

- [ ] Tauri app shell established, wired to the real Rust backend (not mocked)
- [ ] Case Dashboard, Device Selection, Acquisition Wizard, Sanitization Console, Report Center built and functional against real backend calls
- [ ] Mode separation is visually distinct throughout — demonstrate this explicitly
- [ ] Sanitization Console's confirmation sequence exactly matches the backend's two-phase gate — no UI shortcut that collapses the two confirmations
- [ ] Coordinate component library/design tokens with Hari Priya so the two halves of the UI feel like one application, not two
