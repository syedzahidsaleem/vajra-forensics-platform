import React from 'react';
import { useApp } from '../context/AppContext';
import { ShieldAlert, Scale, AlertTriangle, FileCheck, HardDrive, ArrowLeft } from 'lucide-react';
import { GlassCard } from '../components/ui/vajra-components';

export const TermsConditions: React.FC = () => {
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
            Terms & Conditions of Operation
          </h1>
          <p className="text-xs font-mono text-[var(--text)]/60 mt-1">
            Canonical Domain: https://vajra-forensics.org • Legal Agreement • Effective: September 2026
          </p>
        </div>

        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-400 font-mono text-[11px] font-bold">
          <Scale className="w-4 h-4" />
          <span>LEGAL BINDING</span>
        </div>
      </div>

      {/* Critical Destructive Disclaimer */}
      <div className="p-4 rounded-xl bg-[rgba(239,68,68,0.1)] border border-[#EF4444]/40 text-xs text-[var(--text)] leading-relaxed space-y-2">
        <div className="flex items-center gap-2 text-[#EF4444] font-industrial font-bold uppercase tracking-wider text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Notice Regarding Destructive Sanitization Protocols</span>
        </div>
        <p className="text-[var(--text)]/85">
          Operations executed in <strong>Sanitization Mode</strong> invoke controller-native cryptographic erase, block erase, or multi-pass overwrite algorithms that <strong>permanently and irreversibly destroy all data</strong> on target storage media. Passing the mandatory 7-phase confirmation gate constitutes formal operator authorization.
        </p>
      </div>

      {/* Structured Terms Sections */}
      <div className="space-y-5 text-xs text-[var(--text)]/80 leading-relaxed font-sans">
        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <Scale className="w-4 h-4 text-[var(--primary)]" />
            <span>1. Authorized Forensic & Legal Usage</span>
          </div>
          <p>
            The Vajra Forensics Platform is licensed strictly for lawful digital forensic examinations, electronic discovery, authorized law enforcement operations, corporate internal investigations, and verified hardware decommission.
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>The operator affirms they hold lawful authority, legal warrants, or explicit custodian authorization to acquire or sanitize connected storage media.</li>
            <li>Use of Vajra for unauthorized data exfiltration, malicious destruction of evidence, or interception of electronic communications is strictly prohibited and subject to legal prosecution.</li>
          </ul>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <HardDrive className="w-4 h-4 text-[var(--primary)]" />
            <span>2. Read-Only Forensic Invariants & Operator Responsibilities</span>
          </div>
          <p>
            In <strong>Forensic Mode</strong>, Vajra enforces read-only block-source wrappers at the application layer. However, the operator acknowledges:
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>Forensic best practices require physical hardware write-blockers prior to connecting target media to the acquisition host.</li>
            <li>Vajra is not liable for host operating system metadata updates (e.g. automounting or volume indexing) occurring prior to device registration within the platform.</li>
            <li>Evidentiary integrity must be independently substantiated using the generated SHA-256 and BLAKE3 verification hashes.</li>
          </ul>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <ShieldAlert className="w-4 h-4 text-[var(--primary)]" />
            <span>3. Sanitization Gate Sequence & Irrevocability</span>
          </div>
          <p>
            To prevent accidental destruction of production or system disks, Vajra enforces a non-collapsible 7-phase safety gate:
          </p>
          <ul className="list-disc list-inside space-y-1 text-[var(--text)]/70 pl-2">
            <li>Target identity fingerprinting, SMART telemetry verification, and OS boot disk hard-locking.</li>
            <li>Two independent, separated confirmation dialogs and physical drive serial number type-to-confirm validation.</li>
            <li>Upon passing Phase 5, the wiping process cannot be paused or reverted without corrupting the target drive partition table. The operator assumes sole responsibility for data destruction.</li>
          </ul>
        </GlassCard>

        <GlassCard hover={false} className="p-5 space-y-3">
          <div className="flex items-center gap-2.5 text-[var(--text)] font-industrial font-bold text-sm tracking-wide uppercase">
            <FileCheck className="w-4 h-4 text-[var(--primary)]" />
            <span>4. Disclaimer of Warranties & Limitation of Liability</span>
          </div>
          <p>
            Vajra is provided &quot;AS IS&quot; without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
          </p>
          <p className="text-[var(--text)]/70">
            In no event shall the authors, contributors, or copyright holders be liable for any claim, damages, data loss, hardware failure, or business interruption arising from the use or inability to use this software.
          </p>
        </GlassCard>
      </div>

      {/* Footer Contact & Verification */}
      <div className="pt-4 border-t border-[var(--border)]/30 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-[var(--text)]/50">
        <div>Vajra Forensics Platform: Legal Agreement</div>
        <div>Official Portal: https://vajra-forensics.org</div>
      </div>
    </div>
  );
};
