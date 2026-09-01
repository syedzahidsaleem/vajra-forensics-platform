# Vajra — Your Role: Additional File-Type Support + Documentation & Demo Prep
## Vaibhavi

This document is derived from `Vajra_Master_Technical_Document.md` (the full project blueprint — keep it in the repo, refer back to it constantly; section numbers below (§NN) always refer to it). It summarizes what Syed has already built, then defines your specific scope.

You do not need deep systems-programming background for this role. Part 2a is a bounded, well-defined technical task that extends an existing, already-proven pattern (you're adding new entries to an established system, not designing a new one), and Part 2b is documentation/presentation work that's genuinely high-value for how the project gets evaluated.

---

## Part 1 — What's Already Built (read this before touching anything)

A full backend was built across 8 conversations, each independently verified with real terminal output.

- **Foundation & Device Layer**: `vajra-core`/`vajra-device` — real device access on Windows+Linux.
- **Evidence Vault, Audit Log & Chain of Custody**: `vajra-case-db`, `vajra-audit`, `vajra-custody` — encrypted case storage, tamper-evident logging, custody history.
- **Evidence Acquisition & Imaging**: `vajra-acquire`, `vajra-image` — device-to-forensic-image acquisition, RAW/E01 formats.
- **Filesystem Parsers**: `vajra-fs-ntfs`/`ext4`/`fat` — recover deleted files with real confidence scores.
- **File Carving & Recovery Engine**: `vajra-carve` — the three-tier recovery pipeline. **This is what your Part 2a work extends.** It currently supports JPEG, PNG, PDF, ZIP (covering DOCX/XLSX/PPTX), and SQLite — each with a real structural validator (not just a magic-byte check) built on the exact framework from Garfinkel's 2007 paper (V_OK/V_ERR/V_EOF states, with specific per-format flags).
- **Sanitization Engine**: `vajra-erase`/`vajra-file-erase` — the safety-gated sanitization system with certificates.
- **ML/AI Layer**: `vajra-ml` — a secondary, explainable classification signal.
- **Reporting & Independent Verifier**: `vajra-audit` report generation and `vajra-verify` — six report types, and a standalone tool that can check a report's integrity independently.

**What's explicitly not yet built**, which is the source of both your and the rest of the team's remaining work: UI, RAID, encrypted volumes, macOS support, APFS/deeper exFAT, AFF4, additional file-carving formats (this is your Part 2a), the full testing/calibration program (Akanksha owns this), and standards/user-manual/demo materials (your Part 2b).

---

## Part 2 — Your Scope

### 2a. Additional File-Type Support in `vajra-carve` (§26, §28)

The blueprint names two specific formats worth adding, both explicitly flagged as harder than what's already built — read the reasoning in §28 before starting, since it explains exactly why these are harder and what to watch for:

**MP4/MOV** (§28 rates this "hard" specifically because of the `moov` atom problem — worth reading closely): parse the atom/box tree (`ftyp`, `moov`, `mdat`). The specific hard sub-problem the blueprint calls out: when a recording is interrupted (e.g. power loss during capture), the `moov` atom (the index, often written last) can be missing or truncated while `mdat` (the raw frame data) is intact — a validator that can reconstruct even a minimal `moov` from `mdat`'s structure recovers otherwise-"lost" video. This is a genuinely valuable, demonstrable feature if you get it working — a good thing to show live in a demo, since "recovers a video most tools would give up on" is a strong, concrete story.

**Legacy DOC/XLS/PPT (OLE2/Compound File Binary format)**: §26.2 specifies validating the FAT/MiniFAT sector-chain consistency within the compound file structure — structurally quite different from the ZIP-based formats already supported, so this is a genuinely new validator, not a copy of the existing ZIP one.

**How to add either one**, following the exact pattern Conversation 05 already established (read its agent-log for the full validator-framework details before starting):
1. Add a new signature entry (header/footer/max_size/validator_id) to the external signature database — it's already designed to be extensible without recompiling, per §26.1.
2. Write the structural validator implementing the same `V_OK`/`V_ERR`/`V_EOF` framework every existing validator uses — decide and document (same as every prior validator) the `err_is_prefix`/`appended_data_ignored`/`no_zblocks` flag values for this specific format, with your reasoning, the same way the PNG validator's flags were justified with a one-line rationale rather than just asserted.
3. Test against both intact and deliberately corrupted/truncated synthetic files, proving the validator actually rejects bad candidates, not just accepts good ones (this is the same standard every existing validator was held to).
4. Add real, measured precision/recall numbers for the new format, following the exact same benchmarking approach Conversation 05 used — coordinate with Akanksha here, since this feeds directly into her corpus/benchmarking work.

### 2b. Documentation & SIH Demo Preparation

**`docs/standards-mapping.md`** — the blueprint (§58) already specifies exactly which standard maps to which feature (NIST SP 800-88 Rev.2 → §33a/§34/§35; ISO/IEC 27037 → the acquisition/evidence-vault modules; IT Act 2000/CERT-In/DPDP Act → the audit-trail and sanitization modules, etc.). Turn this into a real, filled-in document mapping each standard to the *actual, real* feature/crate that satisfies it — not the aspirational mapping from the blueprint, but a checked one confirming each mapping is genuinely true of what's been built.

**User manual** — a practical walkthrough of the actual `vajra-cli` (and once it exists, the UI) from a new user's perspective: creating a case, acquiring evidence, running recovery, generating a report. Write this by actually running the commands yourself and capturing real output, the same evidence discipline the whole project has used throughout — don't describe what a command "should" do, run it and show what it actually does.

**SIH demonstration script** (§52) — the blueprint specifies two demo flows explicitly: a **Forensics demo** (acquire → recover → report, ending with `vajra-verify` checking the signed report live) and a **Sanitization demo** (fingerprint → decision engine recommendation → sanitize → multi-layer verify → certificate, with the independent-recovery-scan step as the actual centerpiece — "this is the project's real differentiator," per the blueprint's own framing). Write the actual script: what gets typed, what should appear on screen, and — critically — what narration ties it back to why each step matters (e.g., "this step is the platform using its own recovery engine to independently prove the sanitization worked, not just trusting the erase command's own report"). Coordinate with Nitya/Hari Priya once the UI exists to update this from CLI-based to UI-based where it improves the demo.

## Suggested Antigravity Conversation Structure

**Step 0**: read §26, §28 in full (for 2a) and §52, §58 in full (for 2b), plus Conversation 05's agent-log in full (you need the exact validator trait/signature-database shapes before adding to them). These two halves of your work can run somewhat independently — consider treating them as two separate Antigravity conversations rather than one, since they touch very different parts of the project (Rust carving code vs. documentation).

## Definition of Done

- [ ] At least one new file-type validator added (MP4 moov-repair or legacy OLE2), following the exact existing V_OK/V_ERR/V_EOF pattern, with documented flag reasoning
- [ ] New validator tested against intact and corrupted synthetic files
- [ ] `docs/standards-mapping.md` filled in and checked against what's actually built, not aspirational
- [ ] A real, command-verified user manual
- [ ] A complete, narrated SIH demo script for both the Forensics and Sanitization demo flows
