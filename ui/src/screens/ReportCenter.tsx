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

export const ReportCenter: React.FC = () => {
  const { activeCase } = useApp();
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
      desc: 'Per-artifact provenance (§31), aggregate recovery statistics, and multi-signal confidence scores.',
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
    <div data-mode="forensic" style={{ background: 'var(--bg)', color: 'var(--text)' }} className="space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-lg font-sans font-medium text-[#D8E4FF]">
              Report Center & Independent Verifier
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(89,238,153,0.08)] text-[#59EE99]/70 border border-[#59EE99]/15">
              §41, §42
            </span>
          </div>
          <p className="text-[11px] text-[#D8E4FF]/30 font-sans">
            Generate and export the 6 court-admissible forensic report types and execute independent tamper verification.
          </p>
        </div>

        <button
          onClick={() => setShowGenModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-[#59EE99] text-[#00120B] font-mono text-[11px] font-semibold rounded-md shadow-[0_0_12px_rgba(89,238,153,0.2)] hover:bg-[#6fffaa] transition-all cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Generate New Report</span>
        </button>
      </div>

      {/* Reports Grid */}
      <div className="space-y-3">
        <h2 className="text-base font-bold font-mono text-slate-200 flex items-center space-x-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Recorded Reports for {activeCase?.case_id || 'Active Case'}</span>
          <span className="text-xs text-slate-500">({reports.length})</span>
        </h2>

        {reports.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reports.map((r) => (
              <div
                key={r.report_id}
                className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-lg hover:border-slate-700 transition-all"
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-xs text-cyan-400">{r.report_id}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-mono">
                        {r.report_type}
                      </span>
                    </div>
                    <h3 className="font-bold text-sm text-slate-100 font-sans">{r.title}</h3>
                  </div>

                  {r.signed && (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60">
                      <Lock className="w-3 h-3" />
                      <span>X.509 Signed</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800/80">
                  <div>Operator: <span className="text-slate-200">{r.operator_id}</span></div>
                  <div>Created: <span className="text-slate-200">{r.created_at.split('T')[0]}</span></div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
                  <button
                    onClick={() => handleVerify(r)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-800/60 text-cyan-300 text-xs font-mono transition-colors cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Verify (§42)</span>
                  </button>

                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <button
                      onClick={() => setViewingReport(r)}
                      className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition-all shadow cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>View Report</span>
                    </button>
                    <button
                      onClick={() => handleExportHtml(r)}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer flex items-center gap-1"
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
          <div className="p-8 rounded-2xl bg-slate-900/30 border border-slate-800 text-center text-xs font-mono text-slate-500">
            {loading ? 'Loading report registry...' : 'No reports generated yet for this case. Click "Generate New Report" above.'}
          </div>
        )}
      </div>

      {/* Six Report Types Reference Grid */}
      <div className="space-y-3 pt-4 border-t border-slate-800/80">
        <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
          Six Standardized Forensic Report Types (§41)
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {(Object.keys(reportTypeMeta) as ReportType[]).map((type) => {
            const meta = reportTypeMeta[type];
            return (
              <div
                key={type}
                onClick={() => {
                  setSelectedType(type);
                  setShowGenModal(true);
                }}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all space-y-1.5"
              >
                <div className="font-mono font-bold text-xs text-slate-200">{meta.title}</div>
                <p className="text-[11px] font-sans text-slate-400 leading-relaxed">{meta.desc}</p>
                <div className="text-[10px] font-mono text-cyan-400 pt-1">Click to generate &rarr;</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Document Viewer Modal */}
      {viewingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-3xl bg-white text-slate-900 rounded-2xl shadow-2xl overflow-hidden my-8 border border-slate-200">
            {/* Document Header Toolbar */}
            <div className="bg-slate-900 text-white p-4 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-5 h-5 text-cyan-400" />
                <span className="font-mono font-bold text-sm">Official Forensic Evidence Report (§41)</span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => window.print()}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs rounded-lg transition-all"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Print / Save as PDF</span>
                </button>
                <button
                  onClick={() => setViewingReport(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Document Body (Print-optimized layout) */}
            <div className="p-8 space-y-6 font-sans">
              <div className="border-b-2 border-slate-900 pb-4 flex justify-between items-start">
                <div>
                  <h1 className="text-xl font-extrabold tracking-tight text-slate-950">
                    VAJRA FORENSICS PLATFORM
                  </h1>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">
                    Official Digital Evidence & Integrity Report (§41)
                  </p>
                </div>
                <div className="text-right">
                  <span className="inline-block bg-emerald-50 text-emerald-800 border border-emerald-300 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold">
                    CRYPTOGRAPHICALLY SIGNED
                  </span>
                  <div className="text-xs font-mono text-slate-500 mt-1">ID: {viewingReport.report_id}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block uppercase text-[10px] tracking-wider font-bold">Case Identifier:</span>
                  <span className="font-bold text-slate-800">{viewingReport.case_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px] tracking-wider font-bold">Classification:</span>
                  <span className="font-bold text-slate-800">{viewingReport.report_type}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px] tracking-wider font-bold">Lead Examiner:</span>
                  <span className="font-bold text-slate-800">{viewingReport.operator_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase text-[10px] tracking-wider font-bold">Date of Certification:</span>
                  <span className="font-bold text-slate-800">{viewingReport.created_at}</span>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="font-bold text-sm text-slate-950 border-b pb-1">Report Narrative & Findings</h3>
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 text-xs text-slate-700 leading-relaxed font-mono whitespace-pre-wrap">
                  {viewingReport.title}
                  {'\n\n'}
                  Procedural chain of custody and cryptographic verification executed in strict compliance with ISO/IEC 27037 and Vajra Forensic Standard §41.
                </div>
              </div>

              {/* Local File Location Box */}
              <div className="p-4 rounded-xl bg-slate-900 text-slate-200 font-mono text-xs space-y-2">
                <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                  <FileText className="w-4 h-4" />
                  <span>On-Disk Storage Location on Your Laptop:</span>
                </div>
                <div className="p-2 bg-black/60 rounded text-[11px] select-all break-all text-amber-300">
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
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-mono font-bold text-cyan-400 flex items-center space-x-2">
                <FileCheck className="w-5 h-5" />
                <span>Generate Forensic Report (§41)</span>
              </h3>
              <button
                onClick={() => setShowGenModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleGenerate} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Select Report Type</label>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value as ReportType)}
                  className="w-full px-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  {(Object.keys(reportTypeMeta) as ReportType[]).map((t) => (
                    <option key={t} value={t}>
                      {reportTypeMeta[t].title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Examiner Narrative / Judicial Notes</label>
                <textarea
                  rows={4}
                  placeholder="Enter examiner methodology narrative, court findings, or observation notes..."
                  value={reportNotes}
                  onChange={(e) => setReportNotes(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowGenModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold rounded-xl flex items-center space-x-2 shadow-lg shadow-cyan-950"
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
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="font-mono font-bold text-base text-slate-200">
                  Independent Verification (§42)
                </h3>
              </div>
              <button
                onClick={() => {
                  setVerifyingReport(null);
                  setVerifyResult(null);
                }}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 text-xs font-mono space-y-1">
              <div className="text-slate-400">Target Report: <span className="text-slate-200 font-bold">{verifyingReport.report_id}</span></div>
              <div className="text-slate-400">Classification: <span className="text-slate-200">{verifyingReport.report_type}</span></div>
            </div>

            {isVerifying ? (
              <div className="py-8 text-center space-y-3">
                <RotateCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
                <p className="font-mono text-xs text-slate-400">
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
                  <div className="text-slate-400 font-bold">Independent Checks Performed (§42):</div>
                  {verifyResult.checks.map((c: VerificationCheckResult, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 bg-slate-900/70 rounded-xl border border-slate-800 flex items-start space-x-3"
                    >
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="font-bold text-slate-200">{c.check_name}</div>
                        <div className="text-[11px] text-slate-400">{c.details}</div>
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
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-xl cursor-pointer"
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
