# Vajra — Standards and Compliance Mapping

**Status:** Living document (§58 requires this to be maintained during implementation)
**Prepared by:** Vaibhavi — Documentation & Additional File-Type Support
**Date of verification:** 2026-09-01
**Basis:** The `vajra-forensics-platform` source tree as it exists on the `vaibhavi` branch at the time of writing
**Supersedes:** The aspirational mapping table in `Vajra_Master_Technical_Document.md` §58

---

## 1. Introduction

§58 of the Master Technical Document contains a table mapping eight standards and regulations to the sections of the blueprint that are intended to satisfy them. That table is, in the blueprint's own words, *"a specification of intended coverage, to be verified against the real, shipped implementation before final submission."*

This document is that verification.

Every row below was produced by reading the actual source code, not by restating the blueprint. Where the code does what §58 claims, the row says so and cites the file. Where the code does **not** do what §58 claims — and there are several such cases, some of them significant — the row says that instead, in plain language, with the same level of citation.

This is deliberate. A compliance mapping that overstates coverage is worse than no mapping at all: it is the document a reviewer will use to decide what to trust, and every unearned claim in it converts into a false assurance downstream. The project's own blueprint makes this argument about sanitization in §33a — *"applying the wrong method produces a false sense of assurance, which is a worse outcome than doing nothing, because it actively misleads whoever relies on the 'sanitized' label"* — and the same reasoning applies to compliance claims. Accordingly, this document errs toward under-claiming.

Two findings in particular should be read before anything else, because they contradict claims made elsewhere in the project's own documentation:

- **The case database is not encrypted at rest** (§7.3, mapping IT-1 and 27001-2). The Argon2id key-derivation machinery is real, but the SQLCipher `PRAGMA key` it feeds is issued against a plain-SQLite build and has no effect.
- **Controller-native sanitization commands cannot be executed against real hardware** (§7.1, mappings NIST-3 and NIST-2). ATA Secure Erase, NVMe Sanitize, NVMe Format and TCG Cryptographic Erase are all modelled, recommended by the decision engine, and executable against the in-memory mock — but every one of them returns `UnsupportedOperation` when issued to a real drive.

Neither finding invalidates the project. Both need to be stated accurately rather than discovered by a reviewer.

A third point is about *which* obligations actually bite today. The DPDP Act 2023's erasure provisions — sections 8 and 12 — **are not yet in force as at this document's verification date**, and commence only on the expiry of 18 months from 13 November 2025. The DPDP mappings in §6.8 are therefore labelled prospective throughout. Conversely, because the DPDP provision that would omit section 43A of the IT Act 2000 sits in that same deferred tranche, **section 43A remains in force**, which makes the unencrypted-database finding an operative gap rather than a theoretical one. Getting this distinction right matters: a submission that claims present-day DPDP compliance while overlooking a live section 43A exposure would have the picture exactly backwards.

---

## 2. How to read this document

### 2.1 Status definitions

| Status | Meaning |
|---|---|
| **Implemented** | The feature exists in code, is reachable from real execution paths, and does what this document says it does. Where the only in-repo verification is against mocks or synthetic fixtures, that is stated in the caveat rather than downgrading the status. |
| **Partial** | The feature exists but is incomplete in a way that matters to the mapped requirement — it works on one platform only, in one configuration only, against mock targets only, or covers part of the requirement. |
| **Not implemented** | There is no code, or the code is a stub that returns an error, a hardcoded value, or a placeholder string. A type or enum variant that exists but is never constructed or never reachable counts as *not implemented*. |

### 2.2 Structure

Each standard gets a section containing a summary table (requirement → feature → implementing file → status), followed by numbered **Evidence and caveats** entries giving the repository evidence and the limitation for each row. Mapping IDs (`NIST-1`, `27037-4`, …) are stable and can be cited from other documents.

---

## 3. Scope

**In scope.** The Rust workspace in this repository: `vajra-core`, `vajra-device`, `vajra-image`, `vajra-acquire`, `vajra-fs-ntfs` / `-ext4` / `-fat`, `vajra-carve`, `vajra-erase`, `vajra-file-erase`, `vajra-case-db`, `vajra-audit`, `vajra-custody`, `vajra-ml`, `vajra-verify`, `vajra-cli`; the configuration in `config/`; and the tests under each crate's `tests/` directory and inline `#[cfg(test)]` modules.

**Partially in scope — the text of the standards and regulations themselves.** This task was scoped to the repository, and the requirement statements in the left-hand column of each table are generally drawn from how the Master Technical Document (§33a, §39, §58) characterises each standard, **not** from a reading of the primary standards documents. **A requirement mis-stated here would make a correct implementation look compliant against the wrong bar**, so this remains a significant limitation.

Three exceptions have since been checked against external sources as of the verification date and are marked ✅ **externally verified** where they appear:

| Regulatory fact | Status |
|---|---|
| DPDP Act 2023 phased commencement, incl. §§7–17 and §44(2) | ✅ Externally verified — see §6.8 |
| CERT-In Directions of 28 April 2022 — 180-day log retention and NTP synchronisation | ✅ Externally verified — see §6.7 |
| NIST SP 800-88 Rev. 2 scope relative to IEEE 2883 | ✅ Externally verified — see §6.1 |

Everything else — the full text of NIST SP 800-88 Rev. 2, IEEE 2883-2022 / 2883.1-2025, ISO/IEC 27001, ISO/IEC 27037, and the Information Technology Act 2000 — is **still unverified against primary sources** and must be checked before submission.

**Out of scope.**
- The Tauri UI (`vajra-tauri-app` currently contains only `main.rs`), which is under separate development.
- `vajra-raid`, `vajra-crypto-vol`, `vajra-fs-apfs` — declared workspace members whose `lib.rs` files contain no implemented functionality.
- Any deployment, organisational, procedural or physical-security control. Every standard in scope has requirements that software cannot satisfy on its own.

**Verification method.** Direct source reading, targeted `grep` across the workspace, and inspection of test assertions. Where a claim rested on build configuration rather than source code — most importantly the SQLCipher question — the relevant `Cargo.toml` was checked directly. No standard was assumed satisfied because a doc comment or module name referenced it; several are referenced in comments and implemented nowhere.

---

## 4. This is an implementation mapping, not a legal compliance certification

**This document does not certify compliance with anything.**

It is an engineering record of which features in this codebase relate to which externally-defined requirements, produced by student developers reading their own source code. It is not a legal opinion, an audit, an accreditation, a conformity assessment, or a certification, and it must not be presented, summarised, or excerpted as any of those things.

Specifically:

1. **No accredited body has assessed this software.** Certification against ISO/IEC 27001, conformity assessment against ISO/IEC 27037, and formal validation of sanitization tooling are all performed by qualified external assessors under defined schemes. None has occurred.

2. **Compliance is a property of organisations, not of software.** ISO/IEC 27001 certifies an information-security management system. The IT Act 2000, the CERT-In directions and the DPDP Act 2023 impose obligations on bodies corporate and data fiduciaries. A tool can support an obligation; it cannot discharge one. An organisation deploying Vajra would still need its own policies, defined responsibilities, access control, physical security, personnel vetting, incident response and record-keeping — none of which live in this repository.

3. **The requirement statements here are unverified against primary sources.** See §3, *Out of scope*. They are the project's own characterisation of each standard, not the standards' text.

4. **"Implemented" means the code does the thing. It does not mean the thing is sufficient.** A hash-chained audit log is implemented; whether hash-chaining meets any given regulator's evidentiary expectation is a legal question this document does not address.

5. **Nothing here speaks to the admissibility of evidence.** Admissibility is determined by a court under the applicable rules of evidence, on the facts of a case, considering the tool, the operator, the procedure and the chain of custody together. §41 of the blueprint makes the same point about the platform's reports.

6. **This document reflects one point in time** — 2026-09-01, on the `vaibhavi` branch. It goes out of date on the next commit.

Anyone needing an actual compliance position must obtain qualified legal and assessment advice. This document is an input to that work, not a substitute for it.

---

## 5. Summary

| # | Standard / regulation | Mappings | Implemented | Partial | Not implemented |
|---|---|---|---|---|---|
| 1 | NIST SP 800-88 Rev. 2 | 6 | 2 | 2 | 2 |
| 2 | IEEE 2883-2022 / 2883.1-2025 | 2 | 0 | 0 | 2 |
| 3 | DoD 5220.22-M (legacy) | 2 | 1 | 1 | 0 |
| 4 | ISO/IEC 27001 | 4 | 1 | 1 | 2 |
| 5 | ISO/IEC 27037 | 9 | 5 | 4 | 0 |
| 6 | IT Act 2000, s. 43A † | 3 | 1 | 1 | 1 |
| 7 | CERT-In Directions, 28 Apr 2022 | 3 | 1 | 1 | 1 |
| 8 | DPDP Act 2023 ‡ | 3 | 1 | 2 | 0 |
| | **Total** | **32** | **12** | **12** | **8** |

† **Operative today.** Section 43A remains in force as at 2026-09-01; the DPDP provision that omits it (s. 44(2)) has not yet commenced. See §6.6.

‡ **Prospective only.** DPDP Act sections 7–17, including sections 8 and 12, are **not in force** as at 2026-09-01 and commence on the expiry of 18 months from 13 November 2025. The three DPDP rows are future-effective mappings and must not be cited as compliance with a current obligation. See §6.8.

The strongest area by a clear margin is **ISO/IEC 27037** (evidence handling): read-only enforcement is a genuine type-system guarantee, the audit chain and custody state machine are real and tamper-tested, and the independent verifier is a substantive standalone implementation with a rigorous test suite.

The weakest area is **sanitization against real hardware**, where the modelling is complete and the execution is not — compounded by the IEEE 2883 gap, which under SP 800-88 Rev. 2 is part of the technique-level layer rather than a separate optional item (§6.1, §6.2).

**Read the operative and prospective mappings differently.** The mappings most relevant to current deployment are ISO/IEC 27001, ISO/IEC 27037, IT Act s. 43A and the CERT-In Directions. ISO standards are voluntary unless adopted by policy, contract or applicable regulation. NIST SP 800-88 and IEEE 2883 are voluntary technical standards adopted by policy rather than by force of law. The DPDP rows are not yet in force. Weight them accordingly.

---

## 6. The mappings

### 6.1 NIST SP 800-88 Rev. 2

§58 maps this to blueprint §33a, §34, §35 — the Clear/Purge/Destroy framework and per-media-type method selection.

> **Scope of this section.** ✅ **Externally verified.** What follows is a **technical-feature mapping only**. It compares specific Vajra features against specific sanitization techniques and verification behaviours. It is **not** an assessment of coverage against SP 800-88 Rev. 2 as a whole.
>
> SP 800-88 describes a *media sanitization programme*, not just a set of techniques: it covers sanitization and disposal policy, roles and responsibilities, categorisation of information by confidentiality impact, the decision logic for choosing Clear / Purge / Destroy relative to that categorisation and to whether media leaves organisational control, verification and representative sampling, and the retention of sanitization records. **The great majority of that is organisational and procedural, and lives outside any software tool.** Nothing in this section should be read as claiming programme-level coverage; a tool can supply techniques, verification and records, and Vajra addresses parts of those three only.
>
> **One structural point about Rev. 2 matters directly for how the rows below should be read.** Rev. 2 moves detailed, technology-specific sanitization *technique* guidance out of the publication itself and toward dedicated technology standards — IEEE 2883 in particular — while SP 800-88 retains the overall framework, decision logic and programme requirements. That has a consequence this document must state plainly: **the IEEE 2883 gap recorded in §6.2 is not a separate, optional shortfall sitting alongside the NIST mapping. Under Rev. 2 it is part of how technique-level guidance is now expected to be met.** Rows NIST-2, NIST-3 and NIST-4 should therefore be read together with §6.2, not independently of it. The project's own blueprint anticipated this — §33a lists IEEE 2883 as supplementing NIST with "more granular, media-technology-specific sanitization guidance" — but the code does not follow through.

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| NIST-1 | Clear / Purge / Destroy categorisation used throughout | *No such categorisation exists in code* | — | **Not implemented** |
| NIST-2 | Media-appropriate sanitization method selection | Sanitization Decision Engine | `crates/vajra-erase/src/decision_engine.rs` | **Partial** |
| NIST-3 | Purge via controller-native commands (ATA/NVMe/TCG) | `SanitizeMethod` dispatch | `crates/vajra-device/src/drive.rs`, `crates/vajra-erase/src/methods/hardware.rs` | **Not implemented** (real hardware) |
| NIST-4 | Clear via host-level logical overwrite | Overwrite engine | `crates/vajra-erase/src/methods/overwrite.rs` | **Implemented** |
| NIST-5 | Verification of sanitization effectiveness | Five-layer verification incl. independent recovery scan | `crates/vajra-erase/src/verify/layer1_command.rs` … `layer5_recovery.rs` | **Implemented** |
| NIST-6 | Sanitization record / certificate of media disposal | Sanitization Certificate | `crates/vajra-erase/src/certificate.rs` | **Partial** |

#### Evidence and caveats

**NIST-1 — Clear/Purge/Destroy categorisation — Not implemented.**
*Evidence:* There is no enum, type, or field anywhere in the workspace representing the Clear / Purge / Destroy categories. A `grep` for these terms across `crates/vajra-erase/src/` returns exactly two hits, both string literals inside other text: `decision_engine.rs:167` (`"NIST SP 800-88 Clear (Single-Pass Logical Overwrite)"`, a display label) and `methods/overwrite.rs:17` (`/// Zero fill (0x00) - NIST SP 800-88 Clear.`, a doc comment). `SanitizeMethod` (`crates/vajra-core/src/sanitize.rs:10-31`) enumerates ten *techniques* (`AtaSecureErase`, `NvmeSanitizeBlock`, `CryptographicErase`, `HostOverwriteSinglePass`, …) but carries no category classification and no mapping from technique to category.
*Limitation:* No output of the platform — not the decision engine's recommendation, not the certificate, not any report — can state which NIST category a given operation achieved. The blueprint's claim that this framework is "used throughout this document" is true of the document and false of the code. This is a small, well-bounded piece of work (a `SanitizationCategory` enum plus a technique→category function) and is the single highest-value gap to close before submission.

**NIST-2 — Media-appropriate method selection — Partial.**
*Evidence:* `decision_engine.rs:60-182` implements real branching on `MediaType` and device capability: self-encrypting drives → `CryptographicErase` (line 79); NVMe → `NvmeSanitizeBlock`, falling back to `NvmeFormat` (lines 95-118); SATA SSD → `AtaEnhancedSecureErase`, falling back to `AtaSecureErase` (lines 128-151); HDD → `HostOverwriteSinglePass` (lines 161-167); and a final fallback (lines 180-182) with the honest reason string *"Device controller does not expose hardware-level ATA Secure Erase or NVMe Sanitize commands. Host-level overwrite is the only available fallback."* Each recommendation carries a human-readable label and rationale.
*Limitation:* The selection logic is sound, but for every media type except HDD the method it selects **cannot actually be executed against real hardware** — see NIST-3. On a real SSD or NVMe drive the engine will recommend a technique the platform cannot perform. The recommendation is read-only and safe, but a user following it will hit `UnsupportedOperation` at execution time.

**NIST-3 — Purge via controller-native commands — Not implemented against real hardware.**
*Evidence:* `crates/vajra-erase/src/methods/hardware.rs` is a three-line pass-through: it calls `target.issue_sanitize(method)` and returns. There are exactly two implementations of `issue_sanitize` in the workspace. The real one, `crates/vajra-device/src/drive.rs:273-296`, handles `SanitizeMethod::HostOverwriteSinglePass` by looping a host-side zero-fill, and for **every other variant** returns `IoError::UnsupportedOperation` with the reason *"Hardware protocol command execution will be integrated in Module 1 sanitization engine (Conversation 6)"*. The other implementation, `crates/vajra-erase/src/mock.rs:143-155`, is an in-memory mock that logs the method and calls `self.buffer.fill(0x00)`.
*Limitation:* ATA Secure Erase, ATA Enhanced Secure Erase, NVMe Sanitize (Block and Crypto), NVMe Format, TCG Cryptographic Erase, and both SCSI Sanitize variants are modelled in the type system, recommended by the decision engine, exercised by the mock, and **not implemented against hardware**. NIST SP 800-88's Purge level for flash media depends on exactly these commands. No claim of Purge-level sanitization on SSD, NVMe or SED media is supportable from this codebase today. The stub's own reason string points at a conversation that has already concluded, so this is a known, tracked gap rather than an oversight.

**NIST-4 — Clear via host-level overwrite — Implemented.**
*Evidence:* `methods/overwrite.rs:29-80+` implements a genuine pass over all addressable logical blocks, with three patterns (`Zeros`, `Ones`, `Random`). The random pattern uses ChaCha20 seeded from OS entropy (`ChaCha20Rng::from_entropy()`, line 48), writes in block-aligned ~1 MB chunks, and reports progress via a callback. It is generic over `&mut dyn WritableBlockSource`, so it operates identically against the mock and against a real `WritablePhysicalDrive`. The write path underneath is real: `crates/vajra-device/src/os/linux/mod.rs:349-386` opens with `O_DIRECT|O_SYNC`, and `os/windows/mod.rs:808-846` opens with `GENERIC_READ | GENERIC_WRITE` and refuses on `ERROR_WRITE_PROTECT`.
*Limitation:* Host-level overwrite reaches only the logical address space. It cannot reach reallocated sectors, over-provisioned flash, or wear-levelled pages — which is precisely why NIST distinguishes Clear from Purge, and why NIST-3 matters. In-repo verification is against `MockBlockDevice`; no test in the workspace overwrites a physical disk.

**NIST-5 — Verification of sanitization effectiveness — Implemented.**
*Evidence:* All five layers exist as separate modules under `crates/vajra-erase/src/verify/`. Layer 1 checks command-level success; Layer 2 checks device status; Layer 3 performs deterministic read-verify on a bounded sample; Layer 4 performs statistical sampling with a documented hypergeometric-corrected formula and stated default parameters (99.9% confidence, 0.01% defect rate — `layer4_statistical.rs:3-6`), using seeded `ChaCha20Rng` for reproducible sampling. Layer 5 is genuine: `layer5_recovery.rs:11-12` imports `vajra_carve::pipeline::{PipelineOptions, RecoveryPipeline}` and line 25 constructs and runs a real recovery pipeline against the sanitized target. The conservative override rule from §37 is implemented and documented at `layer5_recovery.rs:6-8`.
*Limitation:* Verified against mock targets only. Layer 5's strength is bounded by the recovery engine's own coverage — it looks for the file types in `config/signatures.json`, so "found nothing" means "found none of the six supported signature types", not "no data survives". This is worth stating explicitly in the demo narration, because Layer 5 is the project's headline differentiator and overstating it is the easiest mistake to make. It is nonetheless real, working, and genuinely novel: the crate dependency and the pipeline call are both there in the source.

**NIST-6 — Sanitization certificate — Partial.**
*Evidence:* `certificate.rs:39-56` defines a certificate carrying device identity, method, verification results, operator, and a `digital_signature_hex` field. Signing uses the real Ed25519 keypair from `vajra-audit` when one is supplied (`certificate.rs:142-145`).
*Limitation:* Two defects. First, the signing key is optional: when none is passed, `certificate.rs:146` writes the literal string `"UNSIGNED_LOCAL_TEST_KEY"` into the signature field — an unsigned certificate that still renders as a certificate. Second, `certificate.rs:161` hardcodes `trusted_timestamp` to the fixed string *"Not available — generated offline, local timestamp only"*, so the certificate never carries a trusted timestamp even though `vajra-audit` has a working RFC 3161 client (see 27037-9). The honest disclaimer is good practice; the fact that it is unconditional is the limitation.

---

### 6.2 IEEE 2883-2022 / IEEE 2883.1-2025

§58 maps these to §33a and §35 — technology-specific sanitization detail supplementing NIST.

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| IEEE-1 | Technology-specific sanitization guidance for flash/SSD | *None* | — | **Not implemented** |
| IEEE-2 | IEEE 2883.1-2025 refinements | *None* | — | **Not implemented** |

#### Evidence and caveats

**IEEE-1 and IEEE-2 — Not implemented.**
*Evidence:* IEEE 2883 appears in the workspace only in doc comments and display strings. There is no code path, decision rule, parameter, or verification step that is specific to IEEE 2883 as distinct from the NIST-derived logic in `decision_engine.rs`. The flash-specific handling that does exist (SED → cryptographic erase, NVMe → sanitize/format) is generic media-type branching, not an implementation of IEEE 2883's guidance, and in any case is unexecutable per NIST-3.
*Limitation:* §58 claims IEEE 2883 is satisfied at §33a and §35. **This claim is not supported by the code.** It should be removed from any submission material or restated as intended future scope.

*Why this gap is larger than it first appears.* Because SP 800-88 Rev. 2 devolves technology-specific sanitization *technique* guidance toward standards including IEEE 2883 (see the scope note in §6.1), this is not an independent, nice-to-have shortfall that sits beside the NIST mapping — under Rev. 2 it is part of the technique-level layer itself. Combined with NIST-3, where none of the controller-native flash commands are executable on real hardware, the practical position is that **the project currently has neither the standard-level technique guidance for flash media nor a working implementation of the flash sanitization commands.** For a platform whose stated differentiator is sanitization assurance, this is the most consequential standards gap in the document and should be described as such rather than as one row among several.

*Caveat on the requirement statement:* the IEEE 2883 and 2883.1 requirement text itself remains unverified against the primary standards (§3). Only the relationship between SP 800-88 Rev. 2 and IEEE 2883 has been externally checked.

---

### 6.3 DoD 5220.22-M

§58 maps this to §33a as *"explicitly legacy/compatibility-only, never presented as current best practice."*

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| DoD-1 | Multi-pass overwrite available as a legacy option | `SanitizeMethod::HostOverwriteMultiPass { passes }` + overwrite engine | `crates/vajra-core/src/sanitize.rs:26`, `crates/vajra-erase/src/methods/overwrite.rs` | **Implemented** |
| DoD-2 | Never presented as current best practice; labelled legacy in UI/reports | Decision-engine alternative field | `crates/vajra-erase/src/decision_engine.rs:169` | **Partial** |

#### Evidence and caveats

**DoD-1 — Implemented.**
*Evidence:* `sanitize.rs:26` defines `HostOverwriteMultiPass { passes: u32 }`, documented as *"e.g. DoD 5220.22-M, 3 passes"*. `execute_overwrite_pass_destructive` takes `pass_number` and `total_passes` parameters and supports `Zeros`, `Ones` and `Random` patterns, which is sufficient to compose a multi-pass sequence.
*Limitation:* The multi-pass *sequence* is not itself a named, pre-configured routine — the caller supplies the pattern per pass. There is no `DoD5220` constant or pattern table encoding the specific standard's pass sequence.

**DoD-2 — Partial.**
*Evidence:* This is handled correctly where it appears. DoD is never a `recommended_method` in any branch of `decision_engine.rs`; it appears only at line 169 as an `alternative_available` string, explicitly qualified *"for legacy policy compliance."* The blueprint's requirement that it never be the recommendation is honoured.
*Limitation:* The blueprint also requires that *"the UI/report language must say so explicitly."* There is no UI, and the certificate (`certificate.rs`) contains no field distinguishing a legacy-compatibility method from a current-practice one — the method is recorded, but not its standing. If a certificate is issued for a multi-pass run, nothing on it says the method is withdrawn/legacy. This should be added to `SanitizationCertificate` alongside the NIST category from NIST-1. Flagged for Nitya and Hari Priya as a UI requirement.

---

### 6.4 ISO/IEC 27001

§58 maps this to §39 and §44 — audit logging and security-management posture.

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| 27001-1 | Tamper-evident logging of security-relevant events | Hash-chained audit log | `crates/vajra-audit/src/chain.rs`, `entry.rs` | **Implemented** |
| 27001-2 | Protection of stored information (encryption at rest) | Case-database encryption | `crates/vajra-case-db/src/db.rs`, `key.rs` | **Not implemented** |
| 27001-3 | Cryptographic key management | Operator Ed25519 keypair | `crates/vajra-audit/src/pki.rs` | **Not implemented** |
| 27001-4 | Access control / user authentication | *None* | — | **Not implemented** |

#### Evidence and caveats

**27001-1 — Implemented.**
*Evidence:* `entry.rs:36-44` defines the hashed payload (`seq`, `timestamp_utc`, `operator_id`, `case_id`, `operation`, `target_descriptor`, `result`); `entry.rs:71-78` computes `entry_hash = SHA-256(json(payload) || "||" || prev_hash)`. `chain.rs:33-63` appends with `prev_hash` set to the current head. `chain.rs:87-152` verifies sequence monotonicity, chain linkage and per-entry content integrity, returning distinct errors (`SequenceGap`, `ChainBrokenAtSeq`, `HashMismatchAtSeq`). Two tests in `crates/vajra-audit/tests/audit_tests.rs` prove tamper detection by mutating the database with raw SQL: `test_tamper_detection_content_modification` (lines 50-81) and `test_tamper_detection_entry_deletion_or_reordering` (lines 83-106). External anchoring (`anchor.rs`) additionally detects a wholesale chain rewrite, proven by `test_external_anchoring_and_history_rewrite_detection` (lines 131-191).
*Limitation:* Chain verification proves internal consistency of what is currently in the database; it cannot by itself detect deletion of the entire log and regeneration of a fresh consistent chain. That is what anchoring addresses — but an "anchor" is a signed JSON file written to a caller-supplied path (`anchor.rs:114`). There is no integration with any external service, notary, ledger or write-once medium; the operator must copy the file somewhere trustworthy themselves, and nothing enforces that. Minor cosmetic defect: `entry.rs:9-10` comments the genesis constant as "64 zero hex characters" but the literal is 68 characters.

**27001-2 — Encryption at rest — Not implemented. This contradicts the project's own documentation.**
*Evidence:* `crates/vajra-case-db/src/key.rs:30-45` derives a 32-byte key from a passphrase using Argon2id via `Argon2::default()`, wrapped in `Zeroize`/`ZeroizeOnDrop`. That part is real. `db.rs:49-51` then issues `PRAGMA key = "x'<hex>'"` — **SQLCipher syntax**. But the workspace `Cargo.toml:42` declares `rusqlite = { version = "0.32", features = ["bundled"] }`, and `crates/vajra-case-db/Cargo.toml:11` inherits it unchanged. The `bundled` feature statically links **plain SQLite**. Neither `sqlcipher` nor `bundled-sqlcipher` is enabled anywhere in the workspace. Against plain SQLite, an unrecognised pragma is silently ignored — it does not error. The `.db` file on disk is therefore ordinary unencrypted SQLite whether or not a key is passed.
*Limitation:* `crates/vajra-case-db/src/lib.rs:3` describes the crate as *"Encrypted SQLite/SQLCipher persistence"*. That description is currently false. Compounding this: encryption is optional in the API (`open_file(path, key: Option<&DatabaseKey>)`) and is called with `None` in existing code, and `open_in_memory()` takes no key at all. No test opens a file-backed database and asserts the on-disk bytes are unreadable — the only encryption test, `test_argon2id_key_derivation_and_zeroize` (`db_tests.rs:89-106`), exercises the KDF in isolation and never touches a file. Separately, the docstring at `key.rs:28` claims Argon2id parameters of 64 MB / 3 iterations / parallelism 1, which `Argon2::default()` at line 38 does not set. **Fix: enable the SQLCipher feature and add a test that reads the raw file bytes and asserts they are not plaintext.** Until then, no claim of encryption at rest is supportable — and that claim currently appears in the crate's own documentation, in §58's IT Act row, and in the project's summary materials.

**27001-3 — Key management — Not implemented.**
*Evidence:* `pki.rs:14-24` generates a fresh Ed25519 keypair from `OsRng` on each call. There is no keystore, no persistence, no OS-keychain integration, and no passphrase-protected key file anywhere in the workspace. `report/generator.rs:27-33` — `ReportGenerator::new()` — calls `OperatorKeyPair::generate()` internally, so by default every report is signed with a brand-new, never-persisted key. `with_keypair` (`generator.rs:35-41`) allows supplying one, but no non-test code does.
*Limitation:* A signature verifies against a key that exists only for the lifetime of the process that made it. This does not provide operator attribution over time — two reports by the same operator carry unrelated keys, and a key cannot be revoked, rotated or trusted. Certificates are self-signed only (`pki.rs:47-74`); there is no CA, no chain, and `certificate_chain_pem` is always `None` in generated reports (`generator.rs:122`). Unlike `vajra-case-db`, `pki.rs` does not apply `zeroize` to signing keys.

**27001-4 — Access control — Not implemented.**
*Evidence:* No authentication, authorisation, session, role or user-management code exists in the workspace. `operator_id` is a caller-supplied string recorded in audit entries and custody events; nothing verifies it corresponds to a real, authenticated person.
*Limitation:* This is arguably correct for an offline, single-investigator desktop application (§10 of the blueprint constrains the architecture this way) and access control may legitimately be an OS-level and organisational control. But it should not be claimed as covered. Related security note found while verifying custody: `crates/vajra-custody/src/tracker.rs:44-57` builds SQL via `format!` with unescaped interpolation of `owner`, `loc` and `evidence_id` values. That is a SQL-injection-shaped pattern. It is outside this document's mapping scope, but it belongs in Akanksha's test plan and should be raised with Syed.

---

### 6.5 ISO/IEC 27037

§58 maps this to Part IV (§19–§24) and the Evidence Vault schema (§22), covering identification, collection, acquisition and preservation of digital evidence. This is the project's strongest area.

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| 27037-1 | Integrity preservation — no alteration of source evidence | Type-level read-only block source | `crates/vajra-core/src/traits.rs:23-63`, `crates/vajra-device/src/drive.rs` | **Implemented** |
| 27037-2 | Device identification and unique attribution | SHA-256 device fingerprint | `crates/vajra-core/src/fingerprint.rs:42-80` | **Implemented** |
| 27037-3 | Write-blocking during acquisition | OS-level read-only open + write-blocker detection | `crates/vajra-device/src/os/linux/mod.rs:313-346`, `os/windows/mod.rs:774-806`, `detection.rs:35-102` | **Partial** |
| 27037-4 | Forensic acquisition to an image | Acquisition engine + RAW writer | `crates/vajra-acquire/src/engine.rs`, `crates/vajra-image/src/raw/writer.rs` | **Partial** |
| 27037-5 | Cryptographic verification of the acquired copy | Two-phase SHA-256 | `crates/vajra-acquire/src/hasher.rs:13-81` | **Partial** |
| 27037-6 | Documentation of damaged/unreadable media | Bad-sector map | `crates/vajra-acquire/src/bad_sector.rs`, `engine.rs:519-616` | **Implemented** |
| 27037-7 | Chain of custody record | Custody event state machine | `crates/vajra-custody/src/events.rs`, `tracker.rs` | **Implemented** |
| 27037-8 | Contemporaneous, auditable record of process | Hash-chained audit log | `crates/vajra-audit/src/chain.rs` | **Implemented** — see 27001-1 |
| 27037-9 | Independent verifiability by a third party | Standalone verifier binary | `crates/vajra-verify/` | **Implemented** |

#### Evidence and caveats

**27037-1 — Integrity preservation — Implemented, and this is the project's best engineering.**
*Evidence:* `traits.rs:23-47` defines `ReadOnlyBlockSource` with only read methods — `read_blocks`, `total_blocks`, `block_size`, `media_type`, `is_write_blocked`, `write_blocker_info`, `device_fingerprint`. No write method exists on the trait. `traits.rs:52-63` defines `WritableBlockSource` as a **separate** trait. `drive.rs:26-30, 98-130` — `PhysicalDrive` implements only `ReadOnlyBlockSource` and has no write method at all, so it cannot be coerced to `dyn WritableBlockSource`. `engine.rs:99` binds acquisition generically to `S: ReadOnlyBlockSource + ?Sized`, making a write from inside the acquisition engine a compile error rather than a runtime check. The OS layer agrees: Linux opens read-only with `O_DIRECT` and no `write(true)`; Windows opens with `GENERIC_READ` only. There is a defence-in-depth runtime check as well (`linux/mod.rs:432-437`, `windows/mod.rs:909-914`).
*Limitation:* A fully functional write path does exist in the same crate — `WritablePhysicalDrive` (`drive.rs:135-296`), reachable only via the distinct `open_writable()` constructor, used only by the sanitization engine. This is the correct design (§15's Forensic/Sanitization mode separation), and `vajra-acquire` never references it. But the guarantee is "acquisition cannot write", not "this binary cannot write" — worth stating precisely rather than overclaiming, since the distinction is exactly what §15 is about.

**27037-2 — Device identification — Implemented.**
*Evidence:* `fingerprint.rs:42-80` computes SHA-256 over length-prefixed normalised serial, length-prefixed normalised model, capacity as little-endian `u64`, and a boundary-sector sample. Manufacturer and interface are deliberately excluded (documented at lines 6-8, 40-41) so a drive moved between a SATA port and a USB bridge keeps its identity. Unit tests at `fingerprint.rs:96-163` cover determinism, interface-invariance, sensitivity to each hashed field, and whitespace/case normalisation.
*Limitation:* None material. The fingerprint is also used well elsewhere — `engine.rs:382-389` refuses to resume an interrupted acquisition onto a different device, with a dedicated `DeviceMismatchOnResume` error, tested at `acquire_tests.rs:445-523`.

**27037-3 — Write-blocking — Partial.**
*Evidence:* OS-level read-only opening is real on both platforms (cited above). Windows additionally detects `ERROR_WRITE_PROTECT` and refuses to open for write (`windows/mod.rs:832-837`). Read-only status is queried through real OS mechanisms: the `ro` sysfs attribute on Linux (`linux/mod.rs:207`) and `IOCTL_DISK_IS_WRITABLE` on Windows (`windows/mod.rs:415-428`). `detection.rs:35-102` implements three-tier write-blocker identification — a table of 12 known forensic-blocker VID/PID pairs (Tableau/OpenText, WiebeTech/CRU, Coolgear) at lines 15-32, a vendor/model string heuristic at lines 62-83, and an OS-read-only fallback at lines 86-99 — and is unit-tested at `detection.rs:139-185`.
*Limitation:* **The VID/PID table is unreachable from real enumeration.** Both call sites pass `vid=None, pid=None` unconditionally (`linux/mod.rs:226`, `windows/mod.rs:431`), because neither backend enumerates USB descriptors — there is no `libusb`, `udev` or `SetupDi*` code in the crate. In practice, hardware write-blocker detection degrades to the vendor/model string heuristic (which fires only if the blocker's firmware puts its name in the SCSI/ATA product string) plus the OS read-only flag. Also, `WriteBlockerDetectionMethod::ScsiCommand` (`write_blocker.rs:14`) is defined but never constructed anywhere — no SCSI Mode Sense implementation exists.

**27037-4 — Acquisition — Partial.**
*Evidence:* The acquisition engine is substantial and real: chunked reads, configurable checkpoint interval (default 10,000 blocks, `engine.rs:70`), checkpoint/resume with fingerprint validation (`engine.rs:368-517`), preflight free-space checking via `statvfs` / `GetDiskFreeSpaceExW` (`engine.rs:643-694`), and integration with the case database, audit chain and custody tracker (`engine.rs:139-207, 293-352`). RAW read and write are both fully implemented and round-trip tested byte-for-byte (`image_tests.rs:13-61`, resume-append at 84-112).
*Limitation:* Format coverage is narrower than the blueprint implies. **E01 is read-only** — `e01/reader.rs:25-104` wraps the third-party `ewf` crate v0.4.10 and extracts case metadata and stored MD5/SHA-1; there is no E01 writer anywhere (`impl ForensicImageWriter` appears only at `raw/writer.rs:85`), and `engine.rs:28` is hardcoded to `RawImageWriter`. **AFF4 is an empty stub** — `aff4/mod.rs` contains a single function returning `UnsupportedFormat("AFF4 format support is deferred to Future Scope")`, and its only test asserts that it reports itself unimplemented. There is no E01 integration test and no `.E01` fixture in the repository. Finally, every acquisition test drives the engine through `SimulatedFaultyBlockSource` (`mock.rs`); nothing in the workspace acquires from a real physical device. `profile.rs:15` notes that `Logical` acquisition is currently an LBA range, not filesystem-object-level selection.

**27037-5 — Verification of the acquired copy — Partial. Read this one carefully; the nuance matters.**
*Evidence:* Two SHA-256 hashes are computed. Phase 1 is a rolling hash fed every chunk as it is read and written (`hasher.rs:13-43`, `engine.rs:236`). Phase 2 re-reads the finalised image file from disk and recomputes SHA-256, comparing against Phase 1 (`hasher.rs:49-81`, called at `engine.rs:288`; a full re-hash also runs after resume at `engine.rs:450-452`). Hash equality is asserted in `acquire_tests.rs`.
*Limitation:* **Phase 2 re-reads the image file, not the source device.** It proves the file on disk matches what was streamed to it — which catches destination write/flush corruption — but it does **not** independently re-read the source media and compare source-against-image. If the mapped requirement is understood as two independent physical reads of the original, this implementation does not meet it. This distinction is easy to blur in a demo and should not be. Additionally, `verify_image_file` is only called internally during acquire/resume; there is no standalone "re-verify this stored image against its recorded hash" operation exposed later.

**27037-6 — Damaged media documentation — Implemented.**
*Evidence:* `engine.rs:519-616` implements real degradation handling: up to `max_retries` with linear backoff (lines 531-542), recursive fallback from multi-sector to single-sector reads when a chunk fails (lines 545-563), and substitution of a fixed 16-byte `VAJRA_BAD_SECTOR` marker at the exact failing LBA (lines 565-580). `bad_sector.rs` implements a serializable, range-mergeable `BadSectorMap` documented as the single source of truth, so legitimate data that happens to contain the marker bytes is never misclassified — proven by a deliberate test at `acquire_tests.rs:150-220`.
*Limitation:* Exercised only against the fault-injecting mock, though the logic is generic over the trait and would run identically on real hardware.

**27037-7 — Chain of custody — Implemented.**
*Evidence:* `events.rs:7-28` defines ten event types (`Seized`, `Received`, `StorageChange`, `Transferred`, `WriteBlockerAttached`, `AnalysisStarted`, `AnalysisCompleted`, `WorkingCopyCreated`, `Returned`, `Disposed`), with `Returned`/`Disposed` terminal (`events.rs:46-48`). Each event records evidence id, type, from/to party, UTC timestamp, location, purpose and evidence condition (`events.rs:77-99`). `tracker.rs:94-142` enforces a real state machine — must open with `Seized`/`Received`, no events after terminal, `Transferred` requires both parties, timestamps monotonically non-decreasing — each invariant backed by a passing rejection test in `custody_tests.rs`. History is queryable (`tracker.rs:64-91`) and renders as a ledger (`tracker.rs:145-201`).
*Limitation:* The `signature_ref` field (`events.rs:97-98`) exists but is never populated or verified — custody events are not individually signed. Credit where due: `tracker.rs:194-196` prints an unprompted, accurate disclaimer in the report itself — *"This interface records operator-reported custody events and validates internal sequence and timestamp consistency. It does not independently verify physical transfer events occurring outside the application boundary."* That is exactly the standard of honesty this document is trying to hold the rest of the project to.

**27037-9 — Independent verifiability — Implemented.**
*Evidence:* `vajra-verify` is genuinely standalone: `models.rs:1-4` documents that it redefines the envelope types rather than importing them, *"to ensure zero dependency on `vajra-audit`'s internal data structures"*, and no `use vajra_audit` or `use vajra_case_db` appears in the crate. It ships as a binary taking `<report.vjr> [--evidence <path>]` and runs six checks (`verifier.rs:209-381`): content hash recomputation, Ed25519 public-key extraction from the embedded X.509, signature verification **against the recomputed digest** (so patching the stored hash does not help an attacker), independent audit-chain recomputation, timestamp record shape, and optional evidence-file hashing. `tests/tamper_tests.rs` proves detection across five distinct attacks — content modified without resigning, hash recomputed without resigning, imposter keypair, audit entry modified, timestamp stripped — with real assertions.
*Limitation:* The verifier extracts the public key from the certificate but does not validate the certificate's own signature or validity dates, which follows from there being no CA (27001-3). Timestamp checking is a shape check, not cryptographic revalidation of an RFC 3161 token.

---

### 6.6 IT Act 2000, Section 43A (India)

§58 maps this to §39 and §17 — *"audit trail and encrypted case database support 'reasonable security practices' documentation."*

> **Section 43A is still in force as at the verification date, 2026-09-01.** ✅ **Externally verified.** Section 44(2) of the DPDP Act 2023 — the provision that omits section 43A from the IT Act — falls within the tranche that commences only on the expiry of 18 months from 13 November 2025 (see §6.8). Until then, section 43A has not been omitted and continues to apply.
>
> This matters for how the whole document is read. The DPDP erasure mappings in §6.8 are **prospective**; the mappings in *this* section are **operative today**. Of the two, these are the ones a reviewer should weigh now — which makes the finding in IT-1 the most consequential compliance gap in the document, not merely the most technically interesting one.

| ID | Requirement (as characterised by the blueprint) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| IT-1 | Encrypted case database | Argon2id key derivation + SQLCipher pragma | `crates/vajra-case-db/src/key.rs`, `db.rs:49-51` | **Not implemented** |
| IT-2 | Audit trail evidencing security practices | Hash-chained audit log + signed reports | `crates/vajra-audit/` | **Implemented** |
| IT-3 | Documentation of the security practices themselves | This document; §44 of the blueprint | `docs/` | **Partial** |

#### Evidence and caveats

**IT-1 — Not implemented. See 27001-2 for the full evidence.**
*Limitation:* This is the row where the §58 claim and the code diverge most directly. §58 names the "encrypted case database" as one of the two things supporting this mapping, and the case database is not encrypted. Half of the §58 IT Act mapping therefore does not currently hold. The KDF is real and the fix is a build-configuration change plus a test, but until that lands the claim must not be made.

**IT-2 — Implemented.** Evidence as per 27001-1. Six report types are defined and all six are generated, signed and persisted, proven end-to-end by `test_all_six_report_types_generation_and_signing` (`report_tests.rs:40-175`): Forensic Examination, Sanitization Certificate, Acquisition, Recovery, Device Health, Chain of Custody (`report/model.rs:11-24`). Output is JSON plus Markdown, wrapped in a signed `.vjr` envelope.
*Limitation:* No PDF output exists — `ReportRecord.file_path_pdf` is always `None` (`generator.rs:132`) and there is no PDF dependency in any manifest. Signing is subject to the ephemeral-key problem in 27001-3.

**IT-3 — Partial.** This document exists and §44 of the blueprint describes an application security model. The user manual and demonstration script called for in `ROLE_Vaibhavi.md` are not yet written.

---

### 6.7 CERT-In Directions of 28 April 2022 (India)

§58 maps this to §39 — *"incident-grade audit logging and report retention format."*

> ✅ **Externally verified.** Unlike most rows in this document, the requirements below are taken from the **CERT-In Directions dated 28 April 2022** (issued under section 70B(6) of the Information Technology Act 2000), not from the blueprint's paraphrase. Two obligations in those Directions bear directly on this codebase:
>
> - **Log retention.** Entities must enable logs of all their ICT systems and **maintain them securely for a rolling period of 180 days**, maintained within Indian jurisdiction. CERT-In's subsequent FAQs clarify that logs may be stored outside India provided a copy is retained within India, and that they must be producible to CERT-In when ordered in connection with a cyber-security incident.
> - **Clock synchronisation.** Entities must **connect and synchronise all their ICT system clocks to the Network Time Protocol servers of the National Informatics Centre (NIC) or the National Physical Laboratory (NPL)**, or to an accurate and standard time source traceable to and not deviating from those servers — the latter allowance being made for infrastructure spanning multiple geographies.
>
> These are obligations on the *deploying organisation*, not on a software product. Vajra cannot discharge them. What it can do is make them achievable or unachievable for its operator, and that is what the rows below assess.

| ID | Requirement (CERT-In Directions, 28 April 2022) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| CERT-1 | Enable and securely maintain logs of ICT systems; tamper-evidence | Hash-chained audit log | `crates/vajra-audit/src/chain.rs` | **Implemented** |
| CERT-2 | Maintain logs for a **rolling 180 days**, within Indian jurisdiction | *None* | — | **Not implemented** |
| CERT-3 | Synchronise ICT system clocks to **NIC / NPL NTP** or a traceable equivalent | `chrono` UTC timestamps from the local system clock | `crates/vajra-audit/src/entry.rs` | **Partial** |

#### Evidence and caveats

**CERT-1 — Implemented.** Evidence as per 27001-1.

**CERT-2 — 180-day rolling retention — Not implemented.**
*Evidence:* A case-insensitive `grep` for "retention" across `vajra-audit`, `vajra-custody`, `vajra-case-db` and `vajra-verify` returns zero matches. There is no TTL, expiry, purge, rotation, archival or retention-policy mechanism anywhere in the workspace, and no concept of a retention *window* at all — nothing computes an age, and nothing acts on one. What exists is the opposite: SQL triggers `prevent_case_reopening` and `prevent_case_deletion` (`crates/vajra-case-db/src/schema.rs:127-141`) forbid deleting or reopening a closed case, so the database is designed never to release data — with no corresponding managed archival path.
*Limitation:* §58 explicitly names "report retention format" as part of this mapping; no retention capability exists. Signed `.vjr` report export and signed anchor export are evidentiary export mechanisms, not retention mechanisms — neither is time-bound, neither tracks age, and neither supports verified export-then-purge.

Two nuances worth stating precisely rather than glossing:

- **Never deleting data is not the same as satisfying a 180-day rolling retention requirement**, and it should not be presented as if it were. A rolling 180-day obligation is a *floor* — logs younger than 180 days must still exist and be producible. Vajra's audit chain is append-only and its cases are undeletable, so as a matter of fact nothing within the window is lost. But this is an emergent side-effect of the tamper-evidence design, not an implemented retention control: there is no policy setting, no age tracking, no producibility/export-on-demand function scoped to a period, and no verification that the floor is being met. An organisation could not point at a Vajra feature as evidence of meeting the obligation.
- **The jurisdiction element is entirely outside the software.** Where the database file physically resides is a deployment decision. Vajra is offline-first and single-machine by design (§10), which makes in-India storage straightforward in practice, but nothing in the code enforces, records, or reports on storage location.

*Recommendation:* this is a documentation-and-deployment item more than a code item. The user manual should state where the case database and report files are written, so a deploying organisation can reason about the jurisdiction requirement; and if a retention feature is ever built, it must not purge anything inside the 180-day window.

**CERT-3 — NIC/NPL clock synchronisation — Partial.**
*Evidence:* Audit entries carry `timestamp_utc` from `chrono::Utc::now()`, and the custody state machine enforces monotonically non-decreasing timestamps (`tracker.rs`), so ordering within the log is internally consistent. A real RFC 3161 client exists in `report/timestamp.rs`.
*Limitation:* **Timestamps come from the local system clock, and nothing in the codebase synchronises it, checks it, or records its provenance.** There is no NTP client, no reference to NIC or NPL time servers anywhere in the workspace, no clock-drift detection, and no field on any record indicating whether the host clock was trustworthy when an entry was written. This matters more than usual for an offline-first tool: a forensic workstation deliberately kept off the network is exactly the machine whose clock is most likely to have drifted, and every audit entry, custody event, certificate and report inherits that clock unquestioned.

Rated **Partial** rather than *Not implemented* because timestamps are captured in UTC, ordering is enforced, and a genuine external-time mechanism exists in the RFC 3161 path — but that path does not satisfy this requirement either, for two reasons. First, it is used only for report timestamping, not for audit entries, custody events, or the sanitization certificate (which hardcodes a "not available" string — see NIST-6). Second, it is incomplete: `timestamp.rs:19-68` builds genuine ASN.1 DER and `timestamp.rs:71-125` performs a real HTTP POST to a TSA (default `freetsa.org`, 2-second timeout), but it **does not validate the response** — the comment at `timestamp.rs:95-96` describes a PKIStatus check that is not implemented, and the response body is hex-encoded into a field named `token_der_base64`. On any failure it falls back to local system time with the honest label *"Local timestamp — RFC 3161 unavailable at generation time"* (`timestamp.rs:117-124`); consumers must check `is_rfc3161` to know which they have. In an offline demo this will always be local time.

*Cheapest meaningful improvement:* record the clock's provenance rather than trying to fix it — a field noting whether the host clock was NTP-synchronised, and against what source, at the time of writing. That is honest, it is small, and it is far more useful to a reviewer than an unqualified timestamp.

---

### 6.8 Digital Personal Data Protection Act 2023 (India) — prospective mapping

§58 maps this to Part VI (the Sanitization Engine) as *"directly implements the technical sanitization capability a data fiduciary's obligations would require."*

> ### ⚠️ These are prospective mappings, not current operative obligations
>
> ✅ **Externally verified as of the verification date, 2026-09-01.**
>
> The DPDP Act 2023 is being brought into force in tranches. The Digital Personal Data Protection Rules 2025 were notified on **13 November 2025**, alongside a staggered commencement schedule for the Act itself. Under that schedule:
>
> - Definitions, Data Protection Board provisions and related institutional machinery took effect **immediately on 13 November 2025**.
> - A second tranche (consent-manager registration) commences **12 months** after that date.
> - **Sections 7 to 17 — which include section 8 (obligations of a data fiduciary, including erasure of personal data) and section 12 (the data principal's right to correction and erasure) — commence only on the expiry of 18 months from 13 November 2025** (reported as 12 May 2027), together with sections 3–5, most of section 6, sections 27–34, 36–37 and **section 44(2)**.
>
> **As at 2026-09-01, sections 8 and 12 are therefore not yet in force.** Every mapping in this section is accordingly a **prospective / future-effective mapping**: it records how Vajra's erasure capabilities would relate to those obligations once they commence, and must not be read or cited as evidence of compliance with a currently operative duty. There is presently no DPDP erasure obligation for this software to support.
>
> This is a favourable position for the project, not an awkward one, and should be presented as such: the platform is being built ahead of a known commencement date, which is the right time to build it. What must be avoided is any submission language implying the Act's erasure duties bind today.
>
> **Consequence for the IT Act mapping (§6.6).** Section 44(2) of the DPDP Act is the provision that omits section 43A of the Information Technology Act 2000. Because section 44(2) sits in the same 18-month tranche, **section 43A has not yet been omitted and remains in force as at 2026-09-01.** The §6.6 mappings are therefore live and operative, and are the ones that carry real weight today — which makes the unencrypted-database finding in IT-1 more significant, not less. See the corresponding note in §6.6.

| ID | Prospective requirement (DPDP Act 2023, ss. 8 & 12 — **not in force at 2026-09-01**) | Vajra feature | Implementing file(s) | Status |
|---|---|---|---|---|
| DPDP-1 | Technical capability to erase personal data | Whole-device sanitization | `crates/vajra-erase/` | **Partial** (prospective) |
| DPDP-2 | Targeted erasure of specific data rather than whole media | File/folder secure erasure | `crates/vajra-file-erase/src/file_eraser.rs` | **Partial** (prospective) |
| DPDP-3 | Evidence that erasure occurred | Certificate + five-layer verification + residual scan | `crates/vajra-erase/src/certificate.rs`, `verify/`, `crates/vajra-file-erase/src/scanner.rs` | **Implemented** (prospective) |

The implementation findings below are unchanged — they describe what the code does today, assessed against obligations that will commence later.

#### Evidence and caveats

**DPDP-1 — Partial.** Host-level overwrite is genuinely implemented and executable (NIST-4); controller-native methods are not (NIST-3). For a data fiduciary operating flash media — which in practice is most of them — the platform can currently offer only Clear-level logical overwrite, not Purge.

**DPDP-2 — Partial.**
*Evidence:* `file_eraser.rs` implements a real multi-step pipeline: filesystem-aware extent resolution, multi-pass overwrite of data extents, metadata zeroing, and a five-state residual artifact scan (`scanner.rs:11`, `scan()` at line 43).
*Limitation:* Two steps in the pipeline are hardcoded rather than checked. `file_eraser.rs:126` sets `let journal_scrubbed = true;` under the comment "Step 4: Journal scrubbing" — **no journal scrubbing is performed**; the flag is asserted, not derived. Likewise `file_eraser.rs:130` sets `let free_after_overwrite_verified = true;` under "Step 5: Free-after-overwrite ordering enforcement". Both values then flow into the residual scan (lines 136, 148-149) and into the result record, so a caller reading the result is told journal scrubbing succeeded when it never ran. Related: the crate declares a `vajra-fs-ext4` dependency that is unused. These two lines should either be implemented or the fields removed — reporting an unperformed step as successful is the kind of false assurance §33a warns about, and it is the most misleading single defect found during this review.

**DPDP-3 — Implemented.** The five-layer verification (NIST-5), the five-state residual scan, and the certificate together constitute real evidence of erasure. Subject to the certificate defects in NIST-6 (optional signing, hardcoded timestamp disclaimer) and the hardcoded flags in DPDP-2.

---

### 6.9 Regional overwrite standards referenced in §33a

§33a additionally names **BMB21-2019** (China), **RCMP TSSIT OPS-II** (Canada) and **HMG IS5** (UK) as selectable legacy/regional overwrite patterns. These do not appear in the §58 table.

**Status: Not implemented.** No named pattern table exists for any of them. `OverwritePattern` (`methods/overwrite.rs:16-23`) offers exactly three primitives — `Zeros`, `Ones`, `Random` — which are sufficient building blocks but are not composed into any named regional sequence. No `grep` hit for BMB21, RCMP, TSSIT or IS5 exists anywhere in the workspace.

---

## 7. Blueprint claims not supported by the current code

Consolidated for Syed's integration review. Each item is a place where project documentation asserts something the code does not do.

| # | Claim | Where claimed | Actual state | Severity |
|---|---|---|---|---|
| 1 | Case database is encrypted at rest | §58 (IT Act row); `vajra-case-db/src/lib.rs:3` | `PRAGMA key` issued against plain bundled SQLite; silently ignored. DB is unencrypted. Encryption also optional and called with `None`. | **High** |
| 2 | Controller-native sanitization (ATA/NVMe/TCG) | §35; `methods/hardware.rs` module doc; decision-engine recommendations | All variants except `HostOverwriteSinglePass` return `UnsupportedOperation` on real hardware (`drive.rs:288-294`). Mock only. | **High** |
| 3 | IEEE 2883-2022 / 2883.1-2025 satisfied at §33a, §35 | §58 | Referenced in comments only. No implementation. Raised in significance because SP 800-88 Rev. 2 devolves technique-level guidance toward IEEE 2883 (§6.1). | **High** |
| 4 | NIST Clear/Purge/Destroy framework "used throughout" | §33a, §58 | No enum, type or field. Two string literals. | **Medium** |
| 5 | Journal scrubbing performed during file erasure | `file_eraser.rs:125` comment | `journal_scrubbed = true` hardcoded; step never runs. Reported as successful. | **Medium** |
| 6 | Free-after-overwrite ordering enforced | `file_eraser.rs:128-129` comment | `free_after_overwrite_verified = true` hardcoded. | **Medium** |
| 7 | Reports carry trusted timestamps | §40; certificate output | Certificate hardcodes a "not available" string (`certificate.rs:161`). The audit RFC 3161 client is real but never validates the TSA response and falls back to local time. | **Medium** |
| 8 | Hardware write-blocker identification by VID/PID | `detection.rs` module doc; §24 | Table exists and is tested in isolation but unreachable — both call sites pass `None, None`. No USB descriptor enumeration. | **Medium** |
| 9 | SMART/NVMe health diagnostics | §23; `carve`/CLI health output | Real on Windows. **On Linux, `query_device_health` returns hardcoded `HealthStatus::Good` with empty attributes regardless of the device** (`os/linux/mod.rs:282-300`). | **Medium** |
| 10 | Signed reports provide operator attribution | §40 | `ReportGenerator::new()` mints a fresh, never-persisted Ed25519 key per instance. No keystore. Self-signed certs, no CA. | **Medium** |
| 11 | "External anchoring" of the audit chain | §39–§40 | An anchor is a signed JSON file written to a caller-supplied path. No external service, ledger or WORM enforcement. | **Low** |
| 12 | E01 acquisition output | §19 | E01 read only (via third-party `ewf` crate). No E01 writer; engine hardcoded to RAW. | **Low** |
| 13 | AFF4 support | §19 | Single function returning `UnsupportedFormat`. Explicitly documented as future scope. | **Low** — honestly labelled |
| 14 | HPA/DCO detection | §23; `HpaDcoInfo` type | Type defined; never populated on either platform. | **Low** |
| 15 | Signature-DB extensibility "without recompiling" | §26.1 | Half true. Signatures are data; validators are hardcoded in `ValidatorRegistry::default()` and need a rebuild. | **Low** |
| 16 | Argon2id at 64 MB / 3 iterations / p=1 | `key.rs:28` docstring | Code calls `Argon2::default()`, which does not set those parameters. | **Low** |
| 17 | Retention capability | §58 (CERT-In row) | No retention, TTL, purge or archival mechanism anywhere. The CERT-In Directions of 28 Apr 2022 require a rolling 180-day ICT log retention within Indian jurisdiction; Vajra's append-only design happens not to lose data inside that window, but implements no retention control and no age tracking (§6.7). | **Low** |
| 18 | `carve run --types` supports the listed formats | `vajra-cli/src/main.rs:77` help text | Help text omits `ole2`, added in this branch. Cosmetic. | **Low** |
| 19 | No NIC/NPL time synchronisation | §39–§40; every timestamped record | The CERT-In Directions require ICT clocks synchronised to NIC/NPL NTP or a traceable source. No NTP client, no NIC/NPL reference, no drift detection, and no record of clock provenance exists anywhere in the workspace (§6.7). | **Medium** |

### Recommended before submission

1. **Enable the SQLCipher feature and add an on-disk ciphertext test** (#1). Highest value per unit of effort; converts a false claim into a true one.
2. **Add a `SanitizationCategory` enum and technique→category mapping** (#4). Small, and makes every NIST claim in the project defensible.
3. **Either implement journal scrubbing or delete the two hardcoded flags** (#5, #6). Reporting an unperformed step as successful is the most actively misleading defect found.
4. **Correct §58 and the project summary** to remove the IEEE 2883 claim (#3) and qualify the hardware-sanitization claim (#2).
5. **Gate or label the Linux health path** (#9) so it does not report "Good" for a device it never queried.

6. **Record clock provenance on timestamped records** (#19). Cheaper and more honest than implementing NTP: note whether the host clock was synchronised, and against what.

Items 1–3 are code changes owned by Syed. Item 4 is documentation and is covered by this file. Items 5 and 6 are small honesty fixes.

---

## 8. Sources for externally verified regulatory facts

Three regulatory facts in this document were checked against external sources on 2026-09-01, rather than being taken from the blueprint. They are marked ✅ **externally verified** at the point of use. Everything else about the standards' content remains unverified (§3).

| Fact | Used in | Source |
|---|---|---|
| DPDP Act 2023 phased commencement: ss. 7–17 (incl. 8 and 12) and s. 44(2) commence 18 months after 13 Nov 2025 | §1, §5, §6.6, §6.8 | [AZB & Partners — India's Digital Personal Data Protection Act: Phased Rollout and Key Compliance Milestones](https://www.azbpartners.com/bank/indias-digital-personal-data-protection-act-phased-rollout-and-key-compliance-milestones/); [MeitY / PIB — DPDP Rules 2025 Notified](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf) |
| CERT-In Directions, 28 Apr 2022: rolling 180-day ICT log retention within Indian jurisdiction; NIC/NPL NTP clock synchronisation | §5, §6.7 | [AZB & Partners — CERT-In Directions](https://www.azbpartners.com/bank/cert-in-directions/) |
| SP 800-88 Rev. 2 devolves technology-specific sanitization technique guidance toward standards including IEEE 2883 | §6.1, §6.2, §7 | Consistent with the project blueprint; primary-source verification still required. |

**Caveat.** These were checked against secondary legal commentary and a government notification summary, not against a full reading of the gazetted statutory instruments and the standards themselves. For a submission, the commencement notification and the CERT-In Directions should be read directly. The commencement date for the 18-month tranche is reported as 12 May 2027; this document deliberately states the rule ("expiry of 18 months from 13 November 2025") rather than relying on the computed date.

---

## 9. Maintenance

§58 requires this to be a living document. It should be re-verified whenever a mapped crate changes, and at minimum immediately before submission. The verification method is described in §3; every claim in §6 and §7 cites a file and line so that re-checking is mechanical rather than a fresh investigation.

**Time-sensitive content.** Two things in this document go stale on dates rather than on commits, and must be re-checked if the project is still live then:

- **12 months from 13 November 2025** — the consent-manager tranche of the DPDP Act commences. No effect on these mappings.
- **Expiry of 18 months from 13 November 2025** (reported as 12 May 2027) — DPDP ss. 7–17 (including 8 and 12) and s. 44(2) commence. **On that date §6.8 stops being prospective and becomes operative, and §6.6 ceases to apply** as s. 44(2) omits IT Act s. 43A. Both sections carry notes to this effect.

**Change log**

| Date | Author | Change |
|---|---|---|
| 2026-09-01 | Vaibhavi | Initial verification against the `vaibhavi` branch. 32 mappings across 8 standards; 18 unsupported blueprint claims recorded. |
| 2026-09-01 | Vaibhavi | Regulatory corrections. DPDP mappings relabelled prospective (ss. 7–17 not in force; 18-month commencement from 13 Nov 2025); s. 43A confirmed still operative because s. 44(2) shares that deferral. CERT-In rows restated against the verified 28 Apr 2022 Directions (rolling 180-day retention within Indian jurisdiction; NIC/NPL NTP synchronisation); statuses unchanged (retention Not implemented, time sync Partial). NIST section scoped as a technical-feature mapping, not programme coverage, with Rev. 2's devolution of technique guidance toward IEEE 2883 noted. New §8 records sources. Gap #19 added. No implementation finding changed — no code evidence required it. |
