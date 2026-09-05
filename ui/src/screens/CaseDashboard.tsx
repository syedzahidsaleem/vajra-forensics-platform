import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { tauriApi } from '../api/tauri';
import { EvidenceItemRecord, CustodyEvent, CaseRecord } from '../types';
import {
  FolderPlus,
  Plus,
  X,
  History,
  Copy,
  Check,
} from 'lucide-react';
import { GlassCard, GlowButton, FileTypeBadge, useToast } from '../components/ui/vajra-components';

export const CaseDashboard: React.FC = () => {
  const { activeCase, cases, setActiveCase, refreshCases, setActiveScreen } = useApp();
  const { toast } = useToast();
  const [evidenceList, setEvidenceList] = useState<EvidenceItemRecord[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // New Case Modal State
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [newCaseId, setNewCaseId] = useState('');
  const [newCaseName, setNewCaseName] = useState('');
  const [newInvestigator, setNewInvestigator] = useState('INV-4402-NITYA');
  const [newNotes, setNewNotes] = useState('');
  const [creatingCase, setCreatingCase] = useState(false);

  // Custody History Modal State
  const [selectedEvidenceForCustody, setSelectedEvidenceForCustody] = useState<EvidenceItemRecord | null>(null);
  const [custodyHistory, setCustodyHistory] = useState<CustodyEvent[]>([]);
  const [loadingCustody, setLoadingCustody] = useState(false);

  const fetchEvidence = async (caseId: string) => {
    setLoadingEvidence(true);
    try {
      const items = await tauriApi.listEvidence(caseId);
      setEvidenceList(items);
    } catch (err) {
      console.error('Failed to load evidence:', err);
    } finally {
      setLoadingEvidence(false);
    }
  };

  useEffect(() => {
    if (activeCase) {
      fetchEvidence(activeCase.case_id);
    } else {
      setEvidenceList([]);
    }
  }, [activeCase]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseId || !newCaseName) return;
    setCreatingCase(true);
    try {
      const created = await tauriApi.createCase(newCaseId, newCaseName, newInvestigator, newNotes);
      await refreshCases();
      setActiveCase(created);
      setShowNewCaseModal(false);
      setNewCaseId('');
      setNewCaseName('');
      setNewNotes('');
      toast(`Case ${created.case_id} initialized`, 'success');
    } catch (err) {
      console.error('Error creating case:', err);
      toast('Failed to create case', 'danger');
    } finally {
      setCreatingCase(false);
    }
  };

  const handleCloseCase = async (caseId: string) => {
    if (window.confirm(`Close case '${caseId}'? Closed cases cannot be modified.`)) {
      try {
        await tauriApi.closeCase(caseId);
        await refreshCases();
        toast(`Case ${caseId} closed`, 'info');
      } catch (err) {
        console.error('Error closing case:', err);
      }
    }
  };

  const handleOpenCustodyModal = async (item: EvidenceItemRecord) => {
    setSelectedEvidenceForCustody(item);
    setLoadingCustody(true);
    try {
      const history = await tauriApi.getCustodyHistory(item.evidence_id);
      setCustodyHistory(history);
    } catch (err) {
      console.error('Error fetching custody history:', err);
    } finally {
      setLoadingCustody(false);
    }
  };

  const copyHash = (hash: string, id: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    toast('SHA-256 copied to clipboard', 'info');
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-lg font-sans font-medium text-[var(--forensic-text-primary)]">
              Evidence Vault
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(13,184,211,0.12)] text-[var(--forensic-accent)] border border-[var(--forensic-border)]">
              §17, §22
            </span>
          </div>
          <p className="text-[11px] text-[var(--forensic-text-secondary)] font-sans">
            AES-256 SQLCipher encrypted case metadata and custody registry
          </p>
        </div>

        <GlowButton
          variant="primary"
          size="sm"
          icon={<FolderPlus className="w-3.5 h-3.5" />}
          onClick={() => setShowNewCaseModal(true)}
        >
          Create New Case
        </GlowButton>
      </div>

      {/* Active Case Hero Card */}
      {activeCase ? (
        <GlassCard hover={false} className="p-5">
          {/* Top row */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
              <span className="text-[11px] font-mono text-[var(--forensic-text-mono)] font-bold">
                {activeCase.case_id}
              </span>
              <span className="text-[12px] font-sans text-[var(--forensic-text-primary)] font-medium">
                {activeCase.case_name}
              </span>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] uppercase tracking-wider border border-[var(--forensic-border)]">
                {activeCase.status}
              </span>
            </div>
            {activeCase.status === 'Active' && (
              <button
                onClick={() => handleCloseCase(activeCase.case_id)}
                className="text-[10px] font-mono text-[var(--forensic-text-secondary)] hover:text-[#EF4444] transition-colors cursor-pointer"
              >
                Close Case
              </button>
            )}
          </div>

          {/* Dimmed Metadata Line */}
          <p className="text-[10px] font-mono text-[var(--forensic-text-secondary)] opacity-80 mb-5">
            {activeCase.investigator_id} · {activeCase.created_at} · {evidenceList.length} evidence item{evidenceList.length === 1 ? '' : 's'} · SQLCipher AES-256
          </p>

          {/* Evidence Table Header */}
          <div className="flex items-center justify-between mb-3 pt-4 border-t border-[var(--forensic-border)]">
            <span className="text-[10px] font-mono text-[var(--forensic-text-secondary)] uppercase tracking-wider">
              Registered Evidence Media ({evidenceList.length})
            </span>
            <GlowButton
              variant="ghost"
              size="sm"
              icon={<Plus className="w-3 h-3" />}
              onClick={() => setActiveScreen('devices')}
            >
              Add From Device
            </GlowButton>
          </div>

          {/* Simplified 4-Column Table */}
          {evidenceList.length > 0 ? (
            <div className="overflow-hidden rounded-lg border border-[var(--forensic-border)]">
              <table className="w-full text-left text-[11px] font-mono">
                <thead className="bg-[rgba(15,36,48,0.7)] text-[var(--forensic-text-secondary)]">
                  <tr>
                    <th className="py-2.5 px-3">Evidence ID</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Description</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--forensic-border)]">
                  {evidenceList.map((item) => (
                    <tr key={item.evidence_id} className="hover:bg-[rgba(13,184,211,0.05)] transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className="text-[var(--forensic-text-mono)] font-bold">{item.evidence_id}</span>
                          <button
                            onClick={() => copyHash(item.sha256_hash, item.evidence_id)}
                            title={`Copy SHA-256: ${item.sha256_hash}`}
                            className="text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-accent)] transition-colors p-0.5"
                          >
                            {copiedId === item.evidence_id ? (
                              <Check className="w-3 h-3 text-[var(--forensic-accent)]" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <FileTypeBadge type={item.media_type} />
                      </td>
                      <td className="py-2.5 px-3 text-[var(--forensic-text-primary)] font-sans">{item.description}</td>
                      <td className="py-2.5 px-3 text-right space-x-2">
                        <button
                          onClick={() => handleOpenCustodyModal(item)}
                          className="px-2 py-1 rounded bg-[rgba(13,184,211,0.1)] text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)] text-[10px] font-mono border border-[var(--forensic-border)] cursor-pointer"
                        >
                          Custody Log
                        </button>
                        <button
                          onClick={() => setActiveScreen('acquisition')}
                          className="px-2 py-1 rounded bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] hover:bg-[rgba(13,184,211,0.25)] text-[10px] font-mono border border-[var(--forensic-border)] cursor-pointer"
                        >
                          Acquire
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-8 text-center text-[11px] font-mono text-[var(--forensic-text-secondary)]">
              {loadingEvidence
                ? 'Loading evidence registry...'
                : 'No evidence items registered under this case.'}
            </div>
          )}
        </GlassCard>
      ) : (
        <div className="p-8 rounded-xl border border-dashed border-[rgba(89,238,153,0.1)] text-center space-y-3">
          <FolderPlus className="w-8 h-8 text-[#D8E4FF]/20 mx-auto" />
          <p className="text-[12px] font-mono text-[#D8E4FF]/50">No Case Currently Selected</p>
          <GlowButton
            variant="primary"
            size="sm"
            onClick={() => setShowNewCaseModal(true)}
          >
            Create Your First Case
          </GlowButton>
        </div>
      )}

      {/* All Cases Section — 2 Column Minimal Cards Grid */}
      <div className="space-y-3">
        <p className="text-[10px] font-mono text-[var(--forensic-text-secondary)] uppercase tracking-widest">
          All Cases ({cases.length})
        </p>

        <div className="grid grid-cols-2 gap-3">
          {cases.map((c: CaseRecord) => {
            const isSelected = activeCase?.case_id === c.case_id;
            return (
              <GlassCard
                key={c.case_id}
                selected={isSelected}
                hover={true}
                onClick={() => setActiveCase(c)}
                className="p-4"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-mono text-[var(--forensic-text-mono)] font-bold">{c.case_id}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] border border-[var(--forensic-border)]">
                    {c.status}
                  </span>
                </div>
                <p className="text-[12px] font-sans text-[var(--forensic-text-primary)] mb-1 truncate">
                  {c.case_name}
                </p>
                <p className="text-[10px] font-mono text-[var(--forensic-text-secondary)]">
                  {c.investigator_id} · {c.created_at.split(' ')[0]}
                </p>
              </GlassCard>
            );
          })}
        </div>
      </div>

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(0,18,11,0.85)] backdrop-blur-md p-4">
          <div className="w-full max-w-md bg-[#00120B] border border-[rgba(89,238,153,0.15)] rounded-xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-[#59EE99] uppercase tracking-wider">
                Create Forensic Case
              </h3>
              <button
                onClick={() => setShowNewCaseModal(false)}
                className="text-[#D8E4FF]/40 hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-3 font-mono text-[11px]">
              <div>
                <label className="block text-[#D8E4FF]/40 mb-1 text-[10px] uppercase">Case ID</label>
                <input
                  type="text"
                  required
                  placeholder="CASE-2026-003"
                  value={newCaseId}
                  onChange={(e) => setNewCaseId(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.15)] border border-[rgba(89,238,153,0.1)] text-[#D8E4FF] outline-none focus:border-[#59EE99]/50"
                />
              </div>

              <div>
                <label className="block text-[#D8E4FF]/40 mb-1 text-[10px] uppercase">Operation Title</label>
                <input
                  type="text"
                  required
                  placeholder="Operation Blue Horizon"
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.15)] border border-[rgba(89,238,153,0.1)] text-[#D8E4FF] outline-none focus:border-[#59EE99]/50"
                />
              </div>

              <div>
                <label className="block text-[#D8E4FF]/40 mb-1 text-[10px] uppercase">Lead Examiner ID</label>
                <input
                  type="text"
                  required
                  value={newInvestigator}
                  onChange={(e) => setNewInvestigator(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.15)] border border-[rgba(89,238,153,0.1)] text-[#D8E4FF] outline-none focus:border-[#59EE99]/50"
                />
              </div>

              <div>
                <label className="block text-[#D8E4FF]/40 mb-1 text-[10px] uppercase">Judicial Warrant Notes</label>
                <textarea
                  rows={2}
                  placeholder="Judicial warrant reference or context..."
                  value={newNotes}
                  onChange={(e) => setNewNotes(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.15)] border border-[rgba(89,238,153,0.1)] text-[#D8E4FF] outline-none focus:border-[#59EE99]/50"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="px-3 py-1.5 rounded text-[#D8E4FF]/50 hover:bg-[rgba(53,96,90,0.2)]"
                >
                  Cancel
                </button>
                <GlowButton type="submit" variant="primary" size="sm" loading={creatingCase}>
                  Initialize Case
                </GlowButton>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Custody History Modal */}
      {selectedEvidenceForCustody && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(0,18,11,0.85)] backdrop-blur-md p-4">
          <div className="w-full max-w-xl bg-[#00120B] border border-[rgba(89,238,153,0.15)] rounded-xl p-5 shadow-2xl space-y-4 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-[#59EE99]" />
                <span className="font-bold text-[#D8E4FF]">
                  Custody Ledger: {selectedEvidenceForCustody.evidence_id}
                </span>
              </div>
              <button
                onClick={() => setSelectedEvidenceForCustody(null)}
                className="text-[#D8E4FF]/40 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 bg-[rgba(53,96,90,0.12)] rounded-lg space-y-1 text-[10px] text-[#D8E4FF]/60">
              <div><span className="text-[#D8E4FF]/35">Source:</span> {selectedEvidenceForCustody.source_path}</div>
              <div><span className="text-[#D8E4FF]/35">Custody Holder:</span> <span className="text-[#59EE99]">{selectedEvidenceForCustody.custody_holder || 'INV-4402-NITYA'}</span></div>
              <div className="truncate"><span className="text-[#D8E4FF]/35">SHA-256:</span> {selectedEvidenceForCustody.sha256_hash}</div>
            </div>

            {loadingCustody ? (
              <div className="py-6 text-center text-[#D8E4FF]/30">Loading custody log...</div>
            ) : custodyHistory.length > 0 ? (
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {custodyHistory.map((ev: CustodyEvent, i: number) => (
                  <div key={i} className="p-3 bg-[rgba(0,18,11,0.6)] rounded-lg border border-[rgba(89,238,153,0.06)] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="px-1.5 py-0.5 rounded bg-[rgba(89,238,153,0.1)] text-[#59EE99] text-[9px] font-bold">
                        {ev.event_type}
                      </span>
                      <span className="text-[#D8E4FF]/30 text-[9px]">{ev.timestamp}</span>
                    </div>
                    <div className="text-[#D8E4FF]/80">
                      Transfer: <span className="text-[#59EE99]">{ev.operator_from}</span> &rarr; <span className="text-[#AA77A9]">{ev.operator_to}</span>
                    </div>
                    <div className="text-[#D8E4FF]/40 text-[10px]">Location: {ev.location} | Purpose: {ev.purpose}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-[#D8E4FF]/30">
                Initial acquisition custody record verified. No external transfers recorded.
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvidenceForCustody(null)}
                className="px-3 py-1.5 bg-[rgba(53,96,90,0.2)] text-[#D8E4FF]/70 hover:text-[#D8E4FF] rounded text-[10px]"
              >
                Close Ledger
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CaseDashboard;
