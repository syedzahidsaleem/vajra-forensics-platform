# Vajra — Your Role: Testing, Validation & Benchmarking
## Akanksha

This document is derived from `Vajra_Master_Technical_Document.md` (the full project blueprint — keep it in the repo, refer back to it constantly; section numbers below (§NN) always refer to it). It summarizes what Syed has already built, then defines your specific scope.

You do not need deep systems-programming background for this role — you're extending test patterns that already exist and work, not building new architecture from scratch. This role is genuinely one of the most valuable for the project's credibility: judges and evaluators respond far more to real measured numbers than to feature lists, and this is where those numbers come from.

---

## Part 1 — What's Already Built (read this before touching anything)

A full backend was built across 8 conversations. Each one already includes *some* real testing (this project has a strong existing habit of "show real command output, real measured numbers, never invented ones" — you are extending that habit at scale, not introducing it):

- **Foundation & Device Layer**: `vajra-device` was tested against real Windows (NVMe SSD) and real Linux hardware, with device fingerprinting, health diagnostics, and LVM/device-mapper boot-disk detection all verified with real output.
- **Filesystem Parsers**: `vajra-fs-ntfs`/`ext4`/`fat` were tested against small synthetic ground-truth disk images (`scripts/generate_ground_truth_images.py`) with known deleted files, including a real NTFS quick-format scenario, with byte-for-byte recovered content verified via SHA-256.
- **File Carving & Recovery Engine**: `vajra-carve` was benchmarked against a synthetic corpus (`test_data/carve_test.img`) containing intact, truncated, corrupted, and genuinely 2-fragmented test files, producing real measured precision/recall/F1 (100%/100%/100% on that specific small corpus — see below for why this needs to grow).
- **Sanitization Engine**: `vajra-erase` was tested exclusively against mock/simulated devices (per the project's standing safety rule — never real hardware for destructive operations), including specific isolated scenarios proving the Layer-5 independent-recovery-scan override rule actually works.
- **ML/AI Layer**: `vajra-ml` was evaluated on a synthetic ~1,800-sample dataset with measured (not estimated) accuracy/precision/recall, and includes a required train/serve feature-parity test (Python vs. Rust implementations of the same feature extraction, checked for numerical agreement).

**The honest gap, stated plainly** (this is literally your job to close): every benchmark above ran against a small, hand-built synthetic corpus. The blueprint's own testing methodology (§45) calls for something considerably more thorough, and §46/§50 are explicit that benchmark numbers must be *measured*, never invented — that discipline needs to scale up to a real corpus, not just apply to the small one that exists today.

---

## Part 2 — Your Scope

### 2a. Expand the Ground-Truth Test Corpus (§45)

The blueprint specifies a scenario matrix — build it out properly, reusing and extending the existing generator scripts (don't start from scratch; `scripts/generate_ground_truth_images.py` from the filesystem-parser work and the carving-corpus generator from Conversation 05 are your starting points):
- Normal deletion, quick format, filesystem corruption, partial overwrite, fragmentation, random corruption, bad sectors, mixed file types, large files, small files, nested directories, and files with similar/colliding signatures.
- Cross this against all three filesystems (NTFS/ext4/FAT32) and all the file types `vajra-carve` supports (JPEG/PNG/PDF/ZIP/SQLite).
- Every scenario must be reproducible from a documented script/seed — this is explicit in §45, since reported metrics need to be independently regenerable by anyone reviewing the work (including SIH judges, if they ask).

### 2b. Recovery Benchmarking — Real Precision/Recall/F1 at Scale (§46)

- Once the corpus above exists, re-run `vajra-cli carve run`/`carve stats` against it and report real precision, recall, F1, byte-level recovery accuracy, and false-positive rate — per the exact metric definitions in §46.
- Specifically test the case the small corpus couldn't: does precision/recall hold up as the corpus grows and gets harder (more collision-prone signatures, more fragmentation, more corruption variety)? This is the real test of whether the recovery engine generalizes, not just whether it passes the same six files it was built against.

### 2c. Confidence Calibration (§30) — this is the headline result to aim for

- Bucket every recovered artifact's *predicted* confidence score into deciles (0–10%, 10–20%, ... 90–100%).
- For each bucket, measure *actual* correctness against your ground truth (is a file scored 80–90% actually correct 80–90% of the time?).
- Plot/report this as a calibration curve. **This is explicitly called out in the blueprint as one of the single strongest pieces of evidence the whole confidence-scoring system is real, not decorative** — genuinely worth prioritizing, and a great thing to have in the final presentation.
- If the curve isn't well-calibrated (predicted ≠ actual), that's a legitimate, useful finding — report it honestly and, if you have time, suggest adjusted weights for the six-signal formula in `vajra-carve`'s `confidence.rs` (the weights are already named, tunable constants specifically so a calibration pass like yours can adjust them, per §29's explicit note that they're "initial values, not final").

### 2d. Sanitization Verification Metrics (§47) and Comparison Against Existing Tools (§46/§49)

- Sanitization metrics run only against mocks (per the standing safety rule) — completion rate, verification rate, residual-recovery rate (should trend to zero).
- Where practical, run the same synthetic test scenarios against PhotoRec/TestDisk (freely available) as an external baseline comparison — real measured numbers from real runs of both tools, side by side. Never invent or estimate a competitor's numbers; if you can't run a comparison tool in your environment, say so honestly and leave the entry as "TBD — not run in this environment" rather than guessing.

### 2e. `docs/validation-report.md`

- This is the living document the whole project's testing effort should write into — every number above belongs here, with the method used to produce it stated explicitly (per §37/§46's repeated emphasis: a claimed result needs a stated, reproducible method behind it, not just a number).

## Suggested Antigravity Conversation Structure

**Step 0**: read §30, §45, §46, §47, §49, §50 in full, plus the agent-logs for Conversations 04, 05, 06, and 07 (you need to know exactly what test infrastructure already exists before extending it — don't rebuild what's already there). **Step 1+**: corpus expansion → recovery benchmarking → calibration → sanitization metrics → comparison tooling, in that order, since each builds on the last. **Definition of Done**: real numbers, real reproducible scripts, `docs/validation-report.md` populated.

## Definition of Done

- [ ] Ground-truth corpus expanded per §45's scenario matrix, fully reproducible from scripts
- [ ] Recovery precision/recall/F1/byte-accuracy measured at scale, not just on the original small corpus
- [ ] A real confidence calibration curve produced and reported honestly
- [ ] Sanitization verification metrics measured against mocks
- [ ] At least an attempted comparison against PhotoRec/TestDisk, honestly reported either way
- [ ] `docs/validation-report.md` written with every number traceable to a stated method
