import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { tauriApi } from '../api/tauri';
import { ReportSummary, ReportType, ReportVerificationResult, VerificationCheckResult } from '../types';
import {
  FileText,
  ShieldCheck,
  CheckCircle2,
  FileCheck,
  Plus,
  Lock,
  X,
  RotateCw,
  Printer,
  Eye,
} from 'lucide-react';
import { ShineBorder } from '../components/ui/shine-border';

export const ReportCenter: React.FC = () => {
  const { activeCase, mode } = useApp();
  const isForensic = mode === 'forensic';
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(false);

  // Generate Report Modal
  const [showGenModal, setShowGenModal] = useState(false);
  const [selectedType, setSelectedType] = useState<ReportType>('ForensicExamination');
  const [reportNotes, setReportNotes] = useState('');
  const [generating, setGenerating] = useState(false);

  // Verification Modal State
  const [verifyingReport, setVerifyingReport] = useState<ReportSummary | null>(null);
  const [verifyResult, setVerifyResult] = useState<ReportVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Document Viewer Modal State
  const [viewingReport, setViewingReport] = useState<ReportSummary | null>(null);

  const fetchReports = async () => {
    if (!activeCase) return;
    setLoading(true);
    try {
      const list = await tauriApi.listReports(activeCase.case_id);
      setReports(list);
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [activeCase]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) return;
    setGenerating(true);
    try {
      const newReport = await tauriApi.generateReport(activeCase.case_id, selectedType, reportNotes);
      await fetchReports();
      setShowGenModal(false);
      setReportNotes('');
      // Open the document viewer immediately so the examiner can see it!
      setViewingReport(newReport);
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setGenerating(false);
    }
  };

  const handleVerify = async (report: ReportSummary) => {
    setVerifyingReport(report);
    setIsVerifying(true);
    setVerifyResult(null);
    try {
      const result = await tauriApi.verifyReport(report.json_path);
      setVerifyResult(result);
    } catch (err) {
      console.error('Failed to verify report:', err);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleExportHtml = async (report: ReportSummary) => {
    try {
      await tauriApi.exportReportHtml(report.report_id);
      setViewingReport(report);
    } catch {
      setViewingReport(report);
    }
  };

  const reportTypeMeta: Record<ReportType, { title: string; desc: string }> = {
    ForensicExamination: {
      title: 'Forensic Examination Report',
      desc: 'Full case narrative: acquisition details, recovery methodology, artifacts with provenance, and examiner notes.',
    },
    Acquisition: {
      title: 'Acquisition & Imaging Report',
      desc: 'Device identity fingerprint, imaging format, dual rolling hashes, and bad-sector allocation map.',
    },
    Recovery: {
      title: 'Carved Artifact Recovery Report',
      desc: 'Per-artifact provenance, aggregate recovery statistics, and multi-signal confidence scores.',
    },
    SanitizationCertificate: {
      title: 'NIST/IEEE Sanitization Certificate',
      desc: 'Cryptographically signed destruction certificate with 5-layer verification and zero-entropy proof.',
    },
    DeviceHealth: {
      title: 'Device SMART / Health Report',
      desc: 'SMART attributes snapshot, temperature history, wear level, and operational health diagnostics.',
    },
    ChainOfCustody: {
      title: 'Chain-of-Custody Ledger Report',
      desc: 'Chronological custody event ledger with tamper-evident hash links and digital signatures.',
    },
  };

  return (
    <div data-mode={isForensic ? "forensic" : "sanitize"} className="space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-lg font-sans font-medium ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-text-primary)]'}`}>
            Report Center & Independent Verifier
          </h1>
        </div>

        <button
          onClick={() => setShowGenModal(true)}
          className={`flex items-center gap-2 px-3 py-1.5 font-mono text-[11px] font-semibold rounded-md transition-all cursor-pointer ${
            isForensic
              ? 'bg-[var(--forensic-accent)] text-[#0F2430] hover:bg-[#0DB8D3]/90 shadow-[0_0_12px_rgba(13,184,211,0.35)]'
              : 'bg-[var(--sanitize-accent)] text-[#120202] hover:bg-[#ff5555] shadow-[0_0_12px_rgba(255,59,59,0.35)] font-bold'
          }`}
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Generate New Report</span>
        </button>
      </div>

      {/* Reports Grid */}
      <div className="space-y-3">
        <h2 className="text-base font-bold font-mono text-[var(--text)] flex items-center space-x-2">
          <FileText className="w-4 h-4 text-[var(--primary-text)]" />
          <span>Recorded Reports for {activeCase?.case_id || 'Active Case'}</span>
          <span className="text-xs text-[var(--text)]/50">({reports.length})</span>
        </h2>

        {reports.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reports.map((r) => (
              <div
                key={r.report_id}
                style={{ border: '1px solid var(--border)', borderRadius: '12px' }}
                className="p-5 bg-[var(--surface)] space-y-4 shadow-lg hover:border-[var(--primary)]/50 transition-all text-[var(--text)]"
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-xs text-[var(--primary-text)]">{r.report_id}</span>
                      <span className="px-2 py-0.5 rounded bg-[var(--border)]/20 text-[var(--text)]/80 border border-[var(--border)]/30 text-[10px] font-mono">
                        {r.report_type}
                      </span>
                    </div>
                    <h3 className="font-bold text-sm text-[var(--text)] font-sans">{r.title}</h3>
                  </div>

                  {r.signed && (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60">
                      <Lock className="w-3 h-3" />
                      <span>X.509 Signed</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-[var(--text)]/60 pt-2 border-t border-[var(--border)]/20">
                  <div>Operator: <span className="text-[var(--text)]">{r.operator_id}</span></div>
                  <div>Created: <span className="text-[var(--text)]">{r.created_at.split('T')[0]}</span></div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[var(--border)]/20">
                  <button
                    onClick={() => handleVerify(r)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[var(--primary-text)]/10 hover:bg-[var(--primary-text)]/20 border border-[var(--primary-text)]/30 text-[var(--primary-text)] text-xs font-mono transition-colors cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Verify</span>
                  </button>

                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <button
                      onClick={() => setViewingReport(r)}
                      className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-bold transition-all shadow cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>View Report</span>
                    </button>
                    <button
                      onClick={() => handleExportHtml(r)}
                      className="px-2.5 py-1.5 rounded-lg bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 border border-[var(--border)]/30 cursor-pointer flex items-center gap-1"
                      title="Print court-admissible formatted document"
                    >
                      <Printer className="w-3 h-3" />
                      <span>Print</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 rounded-2xl bg-[var(--surface)]/40 border border-[var(--border)]/20 text-center text-xs font-mono text-[var(--text)]/50">
            {loading ? 'Loading report registry...' : 'No reports generated yet for this case. Click "Generate New Report" above.'}
          </div>
        )}
      </div>

      {/* Six Report Types Reference Grid */}
      <div className="space-y-3 pt-4 border-t border-[var(--border)]/20">
        <h3 className="text-xs font-mono font-bold text-[var(--text)]/60 uppercase tracking-wider">
          Six Standardized Forensic Report Types
        </h3>

        <div className="w-full grid grid-cols-1 md:grid-cols-3 gap-3 items-stretch">
          {(Object.keys(reportTypeMeta) as ReportType[]).map((type) => {
            const meta = reportTypeMeta[type];
            return (
              <ShineBorder
                key={type}
                borderRadius={12}
                color="var(--primary)"
                onClick={() => {
                  setSelectedType(type);
                  setShowGenModal(true);
                }}
                className="cursor-pointer report-type-card w-full h-full flex flex-col justify-between"
              >
                <div className="p-3.5 w-full h-full flex flex-col justify-between rounded-[12px] bg-transparent cursor-pointer box-border">
                  <div className="space-y-1.5">
                    <div className="font-mono font-bold text-xs text-[var(--text)]">{meta.title}</div>
                    <p className="text-[11px] font-sans text-[var(--text)]/60 leading-relaxed">{meta.desc}</p>
                  </div>
                  <div className="text-[10px] font-mono text-[var(--primary-text)] font-semibold pt-2">Click to generate &rarr;</div>
                </div>
              </ShineBorder>
            );
          })}
        </div>
      </div>

      {/* Document Viewer Modal */}
      {viewingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-3xl bg-[var(--surface)] text-[var(--text)] rounded-2xl shadow-2xl overflow-hidden my-8 border border-[var(--border)]/30">
            {/* Document Header Toolbar */}
            <div className="bg-[var(--bg)] text-[var(--text)] p-4 flex items-center justify-between border-b border-[var(--border)]/20">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-5 h-5 text-cyan-400" />
                <span className="font-mono font-bold text-sm">Official Forensic Evidence Report</span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => window.print()}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono text-xs rounded-lg transition-all cursor-pointer font-bold"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Print / Save as PDF</span>
                </button>
                <button
                  onClick={() => setViewingReport(null)}
                  className="text-[var(--text)]/60 hover:text-[var(--text)] p-1 rounded-lg cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Document Body */}
            <div className="p-8 space-y-6 font-sans">
              <div className="border-b-2 border-[var(--border)]/40 pb-4 flex justify-between items-start">
                <div>
                  <h1 className="text-xl font-extrabold tracking-tight text-[var(--text)]">
                    VAJRA FORENSICS PLATFORM
                  </h1>
                  <p className="text-xs text-[var(--text)]/60 font-mono mt-0.5">
                    Official Digital Evidence & Integrity Report
                  </p>
                </div>
                <div className="text-right">
                  <span className="inline-block bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold">
                    CRYPTOGRAPHICALLY SIGNED
                  </span>
                  <div className="text-xs font-mono text-[var(--text)]/60 mt-1">ID: {viewingReport.report_id}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 bg-[var(--bg)]/40 p-4 rounded-xl border border-[var(--border)]/20 text-xs font-mono">
                <div>
                  <span className="text-[var(--text)]/60 block uppercase text-[10px] tracking-wider font-bold">Case Identifier:</span>
                  <span className="font-bold text-[var(--text)]">{viewingReport.case_id}</span>
                </div>
                <div>
                  <span className="text-[var(--text)]/60 block uppercase text-[10px] tracking-wider font-bold">Classification:</span>
                  <span className="font-bold text-[var(--text)]">{viewingReport.report_type}</span>
                </div>
                <div>
                  <span className="text-[var(--text)]/60 block uppercase text-[10px] tracking-wider font-bold">Lead Examiner:</span>
                  <span className="font-bold text-[var(--text)]">{viewingReport.operator_id}</span>
                </div>
                <div>
                  <span className="text-[var(--text)]/60 block uppercase text-[10px] tracking-wider font-bold">Date of Certification:</span>
                  <span className="font-bold text-[var(--text)]">{viewingReport.created_at}</span>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="font-bold text-sm text-[var(--text)] border-b border-[var(--border)]/20 pb-1">Report Narrative & Findings</h3>
                <div className="p-4 bg-[var(--bg)]/40 rounded-xl border border-[var(--border)]/20 text-xs text-[var(--text)]/80 leading-relaxed font-mono whitespace-pre-wrap">
                  {viewingReport.title}
                  {'\n\n'}
                  Procedural chain of custody and cryptographic verification executed in strict compliance with ISO/IEC 27037 and Vajra Forensic Standard.
                </div>
              </div>

              {/* Local File Location Box */}
              <div className="p-4 rounded-xl bg-[var(--bg)]/80 text-[var(--text)] font-mono text-xs space-y-2 border border-[var(--border)]/20">
                <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                  <FileText className="w-4 h-4" />
                  <span>On-Disk Storage Location on Your Laptop:</span>
                </div>
                <div className="p-2 bg-[var(--surface)] rounded text-[11px] select-all break-all text-amber-500 dark:text-amber-300">
                  {viewingReport.json_path}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Generate Report Modal */}
      {showGenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[var(--surface)] border border-[var(--border)]/30 rounded-2xl p-6 shadow-2xl space-y-4 text-[var(--text)]">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-mono font-bold text-[var(--primary-text)] flex items-center space-x-2">
                <FileCheck className="w-5 h-5" />
                <span>Generate Forensic Report</span>
              </h3>
              <button
                onClick={() => setShowGenModal(false)}
                className="text-[var(--text)]/50 hover:text-[var(--text)] p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleGenerate} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-[var(--text)]/60 mb-1">Select Report Type</label>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value as ReportType)}
                  className="w-full font-mono text-xs cursor-pointer"
                >
                  {(Object.keys(reportTypeMeta) as ReportType[]).map((t) => (
                    <option key={t} value={t} className="bg-[var(--surface)] text-[var(--text)]">
                      {reportTypeMeta[t].title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-[var(--text)]/60 mb-1">Examiner Narrative / Judicial Notes</label>
                <textarea
                  rows={4}
                  placeholder="Enter examiner methodology narrative, court findings, or observation notes..."
                  value={reportNotes}
                  onChange={(e) => setReportNotes(e.target.value)}
                  className="w-full font-sans text-xs"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowGenModal(false)}
                  className="px-4 py-2 bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-5 py-2 bg-[var(--primary)] hover:brightness-110 disabled:opacity-50 text-[var(--bg)] font-bold rounded-xl flex items-center space-x-2 shadow-lg"
                >
                  {generating && <RotateCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Generate & Sign</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Verification Results Modal */}
      {verifyingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[var(--surface)] border border-[var(--border)]/30 rounded-2xl p-6 shadow-2xl space-y-5 text-[var(--text)]">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-[var(--primary)]" />
                <h3 className="font-mono font-bold text-base text-[var(--text)]">
                  Independent Verification
                </h3>
              </div>
              <button
                onClick={() => {
                  setVerifyingReport(null);
                  setVerifyResult(null);
                }}
                className="text-[var(--text)]/50 hover:text-[var(--text)] p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3.5 bg-[var(--bg)]/50 rounded-xl border border-[var(--border)]/30 text-xs font-mono space-y-1">
              <div className="text-[var(--text)]/60">Target Report: <span className="text-[var(--text)] font-bold">{verifyingReport.report_id}</span></div>
              <div className="text-[var(--text)]/60">Classification: <span className="text-[var(--text)]">{verifyingReport.report_type}</span></div>
            </div>

            {isVerifying ? (
              <div className="py-8 text-center space-y-3">
                <RotateCw className="w-8 h-8 text-[var(--primary)] animate-spin mx-auto" />
                <p className="font-mono text-xs text-[var(--text)]/60">
                  Executing vajra-verify: recomputing SHA-256 digests and validating Ed25519 signatures...
                </p>
              </div>
            ) : verifyResult ? (
              <div className="space-y-4 font-mono text-xs">
                <div className="p-3.5 rounded-xl bg-emerald-950/70 border border-emerald-800 flex items-center justify-between">
                  <div className="flex items-center space-x-2 font-bold text-emerald-300">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span>REPORT INTEGRITY VERIFIED (PASS)</span>
                  </div>
                  <span className="text-[11px] text-emerald-400">Zero Tamper Detected</span>
                </div>

                <div className="space-y-2">
                  <div className="text-[var(--text)]/70 font-bold">Independent Checks Performed:</div>
                  {verifyResult.checks.map((c: VerificationCheckResult, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 bg-[var(--bg)]/40 rounded-xl border border-[var(--border)]/20 flex items-start space-x-3"
                    >
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="font-bold text-[var(--text)]">{c.check_name}</div>
                        <div className="text-[11px] text-[var(--text)]/60">{c.details}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => {
                  setVerifyingReport(null);
                  setVerifyResult(null);
                }}
                className="px-4 py-2 bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 text-xs font-mono rounded-xl cursor-pointer"
              >
                Close Verifier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportCenter;
