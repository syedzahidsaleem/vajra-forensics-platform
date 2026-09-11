import React from 'react';
import { useApp } from '../context/AppContext';
import { Shield, Lock, EyeOff, FileText, Database, ArrowLeft, CheckCircle2 } from 'lucide-react';
import { GlassCard } from '../components/ui/vajra-components';

export const PrivacyPolicy: React.FC = () => {
  const { setActiveScreen, mode } = useApp();
  const isForensic = mode === 'forensic';

  return (
    <div data-mode={isForensic ? 'forensic' : 'sanitize'} className="space-y-6 max-w-4xl mx-auto pb-12">
      {/* Header with Back Navigation */}
      <div className="flex items-center justify-between border-b border-[var(--border)]/30 pb-4">
        <div>
          <button
            onClick={() => setActiveScreen('dashboard')}
            className="flex items-center gap-2 text-xs font-mono text-[var(--forensic-text-secondary)] hover:text-[var(--text)] transition-colors mb-2 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Dashboard</span>
          </button>
          <h1 className="text-2xl sm:text-3xl font-industrial font-black tracking-wider uppercase text-[var(--text)]">
            Privacy & Data Sovereignty Policy
          </h1>
          <p className="text-xs font-mono text-[var(--text)]/60 mt-1">
            Canonical Domain: https://vajra-forensics.org • Effective: September 2026 • Version 1.0.0
          </p>
        </div>

        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[11px] font-bold">
          <Shield className="w-4 h-4" />
          <span>AIRGAP CERTIFIED</span>
        </div>
      </div>

      {/* Core Principle Alert */}
      <div className="p-4 rounded-xl bg-[rgba(13,184,211,0.08)] border border-[var(--forensic-accent)]/30 text-xs text-[var(--text)] leading-relaxed space-y-2">
        <div className="flex items-center gap-2 text-[var(--forensic-accent)] font-industrial font-bold uppercase tracking-wider text-sm">
          <EyeOff className="w-4 h-4 shrink-0" />
          <span>Zero-Telemetry & Offline-First Sovereign Guarantee</span>
        </div>
        <p className="text-[var(--text)]/80">
          The Vajra Forensics Platform is architected from the ground up for strict offline air-gapped environments. Vajra does not collect, transmit, store, or process any telemetry, diagnostics, user behaviors, or evidence data on any remote server.
        </p>
      </div>

      {/* Structured Policy Sections */}
      <div className="space-y-5 text-xs text-[var(--text)]/80 leading-relaxed font-sans">
        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <Lock className="w-4 h-4 text-[var(--primary)]" />
            <span>1. Local Evidence Processing & Zero External Egress</span>
          </div>
          <p>
            All physical drive enumeration, block-level bitstream imaging (RAW / DD / E01), MFT and filesystem carving, hex inspection, and NIST SP 800-88 sanitization verification take place exclusively on the local host machine within native process memory.
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>No external network sockets are opened during forensic acquisition or parsing operations.</li>
            <li>No cloud synchronization, remote analytical engines, or third-party web trackers are packaged or executed.</li>
            <li>All cryptographic hashing (SHA-256, BLAKE3, MD5) executes strictly via hardware-accelerated local CPU instructions.</li>
          </ul>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <Database className="w-4 h-4 text-[var(--primary)]" />
            <span>2. Local Cryptographic Keystore & Case Database</span>
          </div>
          <p>
            Evidence logs, custody ledgers, and forensic case records are preserved in an encrypted on-device SQLite database utilizing SQLCipher AES-256 block encryption.
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>Ed25519 digital signature private keys are generated on-device and never leave local physical storage.</li>
            <li>Local audit ledgers are cryptographically linked in a tamper-evident SHA-256 hash chain to verify evidentiary integrity.</li>
            <li>The examiner retains sovereign ownership and authority over all database files, report PDFs, and forensic disk images.</li>
          </ul>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <FileText className="w-4 h-4 text-[var(--primary)]" />
            <span>3. Legal Evidentiary Compliance & Standards</span>
          </div>
          <p>
            Data processing, retention, and verification mechanisms implemented within Vajra comply with legal criteria for forensic admissibility:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border)]/30 space-y-1">
              <span className="font-mono font-bold text-[var(--primary-text)] text-[11px]">Section 65B IEA / Sec 63 BSA 2023</span>
              <p className="text-[10px] text-[var(--text)]/60">
                Automated generation of electronic record integrity certificates with cryptographic hash proofs and system state attestations.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border)]/30 space-y-1">
              <span className="font-mono font-bold text-[var(--primary-text)] text-[11px]">ISO/IEC 27037:2012 Standard</span>
              <p className="text-[10px] text-[var(--text)]/60">
                Guidelines for identification, collection, acquisition, and preservation of digital evidence with strict read-only hardware enforcement.
              </p>
            </div>
          </div>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <CheckCircle2 className="w-4 h-4 text-[var(--primary)]" />
            <span>4. Operator Rights & Data Erasure</span>
          </div>
          <p>
            As an offline desktop and web application, Vajra grants operators complete right of disposal:
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>Closing or tombstoning a case permanently seals the forensic record against accidental modification.</li>
            <li>Deleting a local case database or cache completely and permanently purges all local indexing metadata from the host disk.</li>
            <li>Media sanitized in Sanitization Mode undergoes permanent, irrecoverable physical erasure meeting NIST SP 800-88 Purge/Clear criteria.</li>
          </ul>
        </GlassCard>
      </div>

      {/* Footer Contact & Verification */}
      <div className="pt-4 border-t border-[var(--border)]/30 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-[var(--text)]/50">
        <div>Vajra Forensics Platform: Legal & Compliance Division</div>
        <div>Official Verification: https://vajra-forensics.org</div>
      </div>
    </div>
  );
};
