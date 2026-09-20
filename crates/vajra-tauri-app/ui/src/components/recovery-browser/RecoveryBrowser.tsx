import React, { useState, useEffect, useMemo } from 'react';
import {
  RecoveredArtifact,
  RecoveryTier,
  ConfidenceBreakdown,
  FragmentationDetail,
  WEIGHT_HEADER_FOOTER,
  WEIGHT_STRUCTURAL,
  WEIGHT_METADATA,
  WEIGHT_ENTROPY,
  WEIGHT_FRAGMENTATION,
  WEIGHT_OVERWRITE,
  runRecoveryPipeline,
} from '../../types/vajra';

interface RecoveryBrowserProps {
  sourcePath: string;
}

type SortField =
  | 'id'
  | 'file_type'
  | 'recovery_method'
  | 'confidence_score'
  | 'recovered_bytes'
  | 'filename_guess'
  | 'recovery_limitations';

type SortDirection = 'asc' | 'desc';

// Helper to format bytes into human-readable B, KB, MB, GB
const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

// Helper for file type color badge
const getFileTypeBadgeStyle = (fileType: string): string => {
  switch (fileType.toLowerCase()) {
    case 'jpeg':
    case 'jpg':
      return 'bg-blue-950/80 text-blue-300 border-blue-700/60 shadow-blue-900/20';
    case 'pdf':
      return 'bg-red-950/80 text-red-300 border-red-700/60 shadow-red-900/20';
    case 'png':
      return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60 shadow-emerald-900/20';
    case 'sqlite':
    case 'db':
      return 'bg-amber-950/80 text-amber-300 border-amber-700/60 shadow-amber-900/20';
    case 'zip':
    case 'tar':
    case 'gz':
      return 'bg-purple-950/80 text-purple-300 border-purple-700/60 shadow-purple-900/20';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-600 shadow-slate-900/20';
  }
};

// Helper for tier color badge
const getTierBadgeStyle = (tier: RecoveryTier): { label: string; style: string } => {
  switch (tier) {
    case 'Tier1Metadata':
      return {
        label: 'Tier 1 (Metadata)',
        style: 'bg-cyan-950/90 text-cyan-300 border-cyan-600/60',
      };
    case 'Tier2Signature':
      return {
        label: 'Tier 2 (Signature)',
        style: 'bg-indigo-950/90 text-indigo-300 border-indigo-600/60',
      };
    case 'Tier3Fragmented':
      return {
        label: 'Tier 3 (Fragmented BGC)',
        style: 'bg-fuchsia-950/90 text-fuchsia-300 border-fuchsia-600/60',
      };
  }
};

// Helper for confidence score styling
const getScoreColor = (score: number): { text: string; bg: string; border: string } => {
  if (score >= 0.8) {
    return { text: 'text-emerald-400', bg: 'bg-emerald-500', border: 'border-emerald-500/40' };
  } else if (score >= 0.5) {
    return { text: 'text-amber-400', bg: 'bg-amber-500', border: 'border-amber-500/40' };
  } else {
    return { text: 'text-red-400', bg: 'bg-red-500', border: 'border-red-500/40' };
  }
};

export const RecoveryBrowser: React.FC<RecoveryBrowserProps> = ({ sourcePath }) => {
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<RecoveredArtifact | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters state
  const ALL_TYPES = ['jpeg', 'png', 'pdf', 'sqlite', 'zip', 'unknown'];
  const ALL_TIERS: RecoveryTier[] = ['Tier1Metadata', 'Tier2Signature', 'Tier3Fragmented'];

  const [selectedTypes, setSelectedTypes] = useState<string[]>(ALL_TYPES);
  const [selectedTiers, setSelectedTiers] = useState<RecoveryTier[]>(ALL_TIERS);
  const [minConfidence, setMinConfidence] = useState<number>(0.0);

  // Sorting state (default confidence_score descending)
  const [sortField, setSortField] = useState<SortField>('confidence_score');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Pipeline runner effect
  const fetchArtifacts = async () => {
    if (!sourcePath) return;
    setIsLoading(true);
    setError(null);
    setSelectedArtifact(null);

    try {
      const results = await runRecoveryPipeline(sourcePath, true, true, true);
      setArtifacts(results);
    } catch (err: any) {
      setError(typeof err === 'string' ? err : err?.message || 'Failed to execute recovery pipeline.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchArtifacts();
  }, [sourcePath]);

  // Handle column header click for sorting
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  // Filter & Sort Logic
  const processedArtifacts = useMemo(() => {
    return artifacts
      .filter(art => {
        const typeNorm = art.file_type.toLowerCase();
        const matchesType =
          selectedTypes.includes(typeNorm) ||
          (typeNorm !== 'jpeg' &&
            typeNorm !== 'png' &&
            typeNorm !== 'pdf' &&
            typeNorm !== 'sqlite' &&
            typeNorm !== 'zip' &&
            selectedTypes.includes('unknown'));

        const matchesTier = selectedTiers.includes(art.recovery_method);
        const matchesConf = art.confidence_score >= minConfidence;

        return matchesType && matchesTier && matchesConf;
      })
      .sort((a, b) => {
        let valA: any;
        let valB: any;

        switch (sortField) {
          case 'id':
            valA = a.id;
            valB = b.id;
            break;
          case 'file_type':
            valA = a.file_type;
            valB = b.file_type;
            break;
          case 'recovery_method':
            valA = a.recovery_method;
            valB = b.recovery_method;
            break;
          case 'confidence_score':
            valA = a.confidence_score;
            valB = b.confidence_score;
            break;
          case 'recovered_bytes':
            valA = a.recovered_bytes;
            valB = b.recovered_bytes;
            break;
          case 'filename_guess':
            valA = a.filename_guess || a.original_path || '';
            valB = b.filename_guess || b.original_path || '';
            break;
          case 'recovery_limitations':
            valA = a.recovery_limitations ? 1 : 0;
            valB = b.recovery_limitations ? 1 : 0;
            break;
          default:
            valA = a.confidence_score;
            valB = b.confidence_score;
        }

        if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
        if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
  }, [artifacts, selectedTypes, selectedTiers, minConfidence, sortField, sortDirection]);

  // Toggle type filter
  const toggleType = (t: string) => {
    setSelectedTypes(prev =>
      prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
    );
  };

  // Toggle tier filter
  const toggleTier = (t: RecoveryTier) => {
    setSelectedTiers(prev =>
      prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
    );
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 font-sans p-4 space-y-4 overflow-hidden rounded-xl border border-slate-800 shadow-2xl">
      {/* HEADER & CONTROLS SECTION */}
      <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 backdrop-blur-md flex flex-col space-y-3 shrink-0 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-950/80 border border-cyan-700/50 rounded-lg text-cyan-400">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-bold tracking-wide text-slate-100 flex items-center space-x-2">
                <span>Forensic Recovery Browser</span>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-700/50 font-mono">
                  {processedArtifacts.length} / {artifacts.length} Candidates
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Source: <span className="text-slate-200">{sourcePath || 'No source loaded'}</span>
              </p>
            </div>
          </div>

          <button
            onClick={fetchArtifacts}
            disabled={isLoading}
            className="flex items-center space-x-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 rounded-lg border border-slate-700 transition disabled:opacity-50"
          >
            <svg className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <span>Re-Scan Media</span>
          </button>
        </div>

        {/* FILTERS TOOLBAR */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80 text-xs">
          {/* File Types */}
          <div className="space-y-1">
            <label className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
              File Types
            </label>
            <div className="flex flex-wrap gap-1.5">
              {ALL_TYPES.map(type => {
                const active = selectedTypes.includes(type);
                return (
                  <button
                    key={type}
                    onClick={() => toggleType(type)}
                    className={`px-2 py-0.5 rounded border font-mono uppercase text-[10px] transition ${
                      active
                        ? 'bg-cyan-900/60 text-cyan-200 border-cyan-600/70'
                        : 'bg-slate-950 text-slate-500 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {type}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Recovery Tiers */}
          <div className="space-y-1">
            <label className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
              Recovery Tiers
            </label>
            <div className="flex flex-wrap gap-1.5">
              {ALL_TIERS.map(tier => {
                const active = selectedTiers.includes(tier);
                const info = getTierBadgeStyle(tier);
                return (
                  <button
                    key={tier}
                    onClick={() => toggleTier(tier)}
                    className={`px-2 py-0.5 rounded border text-[10px] font-semibold transition ${
                      active
                        ? info.style
                        : 'bg-slate-950 text-slate-500 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {tier.replace('Tier', 'Tier ')}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Minimum Confidence Slider */}
          <div className="space-y-1 flex flex-col justify-center">
            <div className="flex justify-between items-center text-[10px]">
              <label className="text-slate-400 font-semibold uppercase tracking-wider">
                Min Confidence Threshold
              </label>
              <span className="font-mono text-cyan-400 font-bold">
                {(minConfidence * 100).toFixed(0)}%
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={minConfidence}
              onChange={e => setMinConfidence(parseFloat(e.target.value))}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* SECTION 1 — ARTIFACT GRID (Top 60%) */}
      <div className="flex-1 min-h-[300px] max-h-[60vh] bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col backdrop-blur-md shadow-inner">
        {isLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center space-y-3 p-8">
            <div className="w-10 h-10 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
            <p className="text-sm text-cyan-300 font-mono animate-pulse">
              Running multi-tier recovery pipeline (§25–§31)…
            </p>
          </div>
        ) : error ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 space-y-4">
            <div className="p-3 bg-red-950/80 border border-red-700/60 text-red-400 rounded-full">
              <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="text-center max-w-md">
              <h3 className="text-base font-bold text-red-300">Pipeline Execution Error</h3>
              <p className="text-xs text-slate-400 font-mono mt-1">{error}</p>
            </div>
            <button
              onClick={fetchArtifacts}
              className="px-4 py-2 bg-red-900/60 hover:bg-red-800/80 text-red-200 border border-red-700 text-xs font-semibold rounded-lg transition"
            >
              Retry Recovery
            </button>
          </div>
        ) : processedArtifacts.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-2">
            <svg className="w-12 h-12 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-sm text-slate-400 font-medium">No artifacts recovered — try enabling additional tiers or adjusting filters.</p>
          </div>
        ) : (
          <div className="overflow-y-auto flex-1 custom-scrollbar">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="sticky top-0 bg-slate-950/90 text-slate-400 uppercase tracking-wider text-[10px] font-semibold border-b border-slate-800 backdrop-blur-md z-10">
                <tr>
                  <th
                    onClick={() => handleSort('id')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition"
                  >
                    ID {sortField === 'id' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('file_type')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition"
                  >
                    File Type {sortField === 'file_type' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('recovery_method')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition"
                  >
                    Recovery Tier {sortField === 'recovery_method' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('confidence_score')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition w-44"
                  >
                    Confidence Score {sortField === 'confidence_score' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('recovered_bytes')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition"
                  >
                    Size {sortField === 'recovered_bytes' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('filename_guess')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition"
                  >
                    Filename / Path {sortField === 'filename_guess' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                  <th
                    onClick={() => handleSort('recovery_limitations')}
                    className="py-2.5 px-3 cursor-pointer hover:text-slate-200 transition text-center"
                  >
                    Limitations {sortField === 'recovery_limitations' && (sortDirection === 'asc' ? '▲' : '▼')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {processedArtifacts.map(art => {
                  const isSelected = selectedArtifact?.id === art.id;
                  const tierInfo = getTierBadgeStyle(art.recovery_method);
                  const scoreColors = getScoreColor(art.confidence_score);
                  const filenameDisplay = art.filename_guess || art.original_path || '—';

                  return (
                    <tr
                      key={art.id}
                      onClick={() => setSelectedArtifact(art)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-950/40 border-l-4 border-l-cyan-500 text-slate-100'
                          : 'hover:bg-slate-800/50 text-slate-300'
                      }`}
                    >
                      {/* ID */}
                      <td className="py-2.5 px-3 font-semibold text-cyan-400">
                        #R-{art.id}
                      </td>

                      {/* File Type */}
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getFileTypeBadgeStyle(art.file_type)}`}>
                          {art.file_type}
                        </span>
                      </td>

                      {/* Recovery Tier */}
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${tierInfo.style}`}>
                          {tierInfo.label}
                        </span>
                      </td>

                      {/* Confidence Score */}
                      <td className="py-2.5 px-3">
                        <div className="flex items-center space-x-2">
                          <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                            <div
                              className={`h-full ${scoreColors.bg} transition-all duration-300`}
                              style={{ width: `${Math.min(100, Math.max(0, art.confidence_score * 100))}%` }}
                            />
                          </div>
                          <span className={`text-[11px] font-bold w-12 text-right ${scoreColors.text}`}>
                            {(art.confidence_score * 100).toFixed(1)}%
                          </span>
                        </div>
                      </td>

                      {/* Size */}
                      <td className="py-2.5 px-3 text-slate-300">
                        {formatBytes(art.recovered_bytes)}
                      </td>

                      {/* Filename */}
                      <td className="py-2.5 px-3 truncate max-w-xs text-slate-200 font-sans" title={filenameDisplay}>
                        {filenameDisplay}
                      </td>

                      {/* Limitations */}
                      <td className="py-2.5 px-3 text-center">
                        {art.recovery_limitations ? (
                          <span
                            className="inline-flex items-center justify-center w-5 h-5 bg-amber-950/80 text-amber-400 border border-amber-600/70 rounded-full cursor-help"
                            title={`Limitation: ${art.recovery_limitations}`}
                          >
                            ⚠️
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center justify-center w-5 h-5 bg-emerald-950/80 text-emerald-400 border border-emerald-600/70 rounded-full"
                            title="Complete & verified payload"
                          >
                            ✓
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SECTION 2 — ARTIFACT DETAIL PANEL (Bottom 40%) */}
      {selectedArtifact && (
        <div className="h-[40%] bg-slate-900/90 border border-cyan-800/60 rounded-xl p-4 flex flex-col space-y-3 overflow-y-auto custom-scrollbar backdrop-blur-lg shadow-2xl transition-all animate-fadeIn">
          {/* Detail Header */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-3">
              <span className="text-base font-bold text-cyan-400 font-mono">
                #R-{selectedArtifact.id}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-bold border uppercase ${getFileTypeBadgeStyle(selectedArtifact.file_type)}`}>
                {selectedArtifact.file_type}
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-semibold border ${getTierBadgeStyle(selectedArtifact.recovery_method).style}`}>
                {getTierBadgeStyle(selectedArtifact.recovery_method).label}
              </span>
            </div>

            <button
              onClick={() => setSelectedArtifact(null)}
              className="text-slate-400 hover:text-slate-100 text-xs px-2 py-1 bg-slate-800 rounded border border-slate-700 transition"
            >
              ✕ Close Detail
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs flex-1">
            {/* LEFT COLUMN — PROVENANCE */}
            <div className="space-y-3 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800 flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1 mb-2.5 flex items-center justify-between">
                  <span>Artifact Provenance (§31)</span>
                  <span className="text-[10px] text-slate-500 font-mono">SHA-256 Verified</span>
                </h3>

                <div className="space-y-2 font-mono text-[11px]">
                  {/* Filename & Path */}
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Filename / Path</span>
                    <span className="text-slate-200 font-sans font-medium">
                      {selectedArtifact.filename_guess || selectedArtifact.original_path || '— (Carved candidate)'}
                    </span>
                  </div>

                  {/* LBA Extents */}
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Source LBA Extents</span>
                    <div className="flex flex-wrap gap-1 mt-0.5 max-h-16 overflow-y-auto">
                      {selectedArtifact.source_locations.map(([start, count], idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 bg-slate-900 text-cyan-300 border border-slate-700 rounded text-[10px]"
                        >
                          LBA {start} → {start + count} ({count} blocks)
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Byte Sizes */}
                  <div className="flex justify-between pt-1">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Recovered Bytes</span>
                      <span className="text-slate-200 font-semibold">{formatBytes(selectedArtifact.recovered_bytes)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Expected Total</span>
                      <span className="text-slate-200 font-semibold">
                        {selectedArtifact.expected_total_bytes ? formatBytes(selectedArtifact.expected_total_bytes) : 'Unknown'}
                      </span>
                    </div>
                  </div>

                  {/* SHA-256 Hash */}
                  <div className="pt-1">
                    <span className="text-slate-500 block text-[10px] uppercase">SHA-256 Hash</span>
                    <span
                      className="text-slate-300 font-mono text-[10px] bg-slate-900 px-2 py-1 rounded border border-slate-800 block truncate cursor-help"
                      title={selectedArtifact.content_hash}
                    >
                      {selectedArtifact.content_hash.substring(0, 16)}...
                    </span>
                  </div>
                </div>
              </div>

              {/* Limitations Box */}
              <div className="pt-2">
                {selectedArtifact.recovery_limitations ? (
                  <div className="p-2.5 bg-amber-950/60 border border-amber-600/70 rounded-lg text-amber-200 space-y-1">
                    <div className="flex items-center space-x-1.5 font-bold text-[11px] text-amber-400">
                      <span>⚠️ Recovery Limitations</span>
                    </div>
                    <p className="text-[11px] font-sans leading-relaxed">
                      {selectedArtifact.recovery_limitations}
                    </p>
                  </div>
                ) : (
                  <div className="p-2 bg-emerald-950/60 border border-emerald-600/60 rounded-lg text-emerald-300 flex items-center space-x-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span className="text-[11px] font-semibold font-sans">Complete & verified payload</span>
                  </div>
                )}
              </div>
            </div>

            {/* RIGHT COLUMN — CONFIDENCE BREAKDOWN (§29) */}
            <div className="space-y-3 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800 flex flex-col justify-between overflow-y-auto">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-1 mb-2.5">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    6-Signal Confidence Breakdown (§29)
                  </h3>
                  <span className={`text-xs font-bold font-mono ${getScoreColor(selectedArtifact.confidence_score).text}`}>
                    Score: {(selectedArtifact.confidence_score * 100).toFixed(1)}%
                  </span>
                </div>

                {/* 6 Signal Indicators */}
                <div className="space-y-2 text-[11px]">
                  {[
                    {
                      label: 'Header / Footer Integrity',
                      val: selectedArtifact.confidence_breakdown.header_footer_integrity,
                      weight: WEIGHT_HEADER_FOOTER,
                    },
                    {
                      label: 'Structural Validation',
                      val: selectedArtifact.confidence_breakdown.structural_validity,
                      weight: WEIGHT_STRUCTURAL,
                    },
                    {
                      label: 'Metadata Corroboration',
                      val: selectedArtifact.confidence_breakdown.metadata_cross_reference,
                      weight: WEIGHT_METADATA,
                    },
                    {
                      label: 'Entropy Consistency',
                      val: selectedArtifact.confidence_breakdown.entropy_consistency,
                      weight: WEIGHT_ENTROPY,
                    },
                    {
                      label: 'Fragmentation Quality',
                      val: selectedArtifact.confidence_breakdown.fragmentation_confidence,
                      weight: WEIGHT_FRAGMENTATION,
                    },
                    {
                      label: 'Non-Overwrite Integrity',
                      val: selectedArtifact.confidence_breakdown.overwrite_probability,
                      weight: WEIGHT_OVERWRITE,
                    },
                  ].map((sig, idx) => {
                    const color = getScoreColor(sig.val);
                    return (
                      <div key={idx} className="space-y-0.5">
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="text-slate-300 font-medium">
                            {sig.label} <span className="text-slate-500 font-mono">(× {sig.weight.toFixed(2)})</span>
                          </span>
                          <span className={`font-mono font-bold ${color.text}`}>
                            {(sig.val * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                          <div
                            className={`h-full ${color.bg}`}
                            style={{ width: `${Math.min(100, Math.max(0, sig.val * 100))}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Formula Visualization Box */}
                <div className="mt-3 p-2 bg-slate-900 rounded border border-slate-800 text-[9px] font-mono text-slate-400 space-y-1">
                  <div className="text-slate-500 uppercase tracking-wider text-[8px] font-bold">
                    Weighted Composite Formula (§29)
                  </div>
                  <div className="truncate text-slate-300">
                    ({selectedArtifact.confidence_breakdown.header_footer_integrity.toFixed(2)} × {WEIGHT_HEADER_FOOTER}) + ({selectedArtifact.confidence_breakdown.structural_validity.toFixed(2)} × {WEIGHT_STRUCTURAL}) + ({selectedArtifact.confidence_breakdown.metadata_cross_reference.toFixed(2)} × {WEIGHT_METADATA}) + ({selectedArtifact.confidence_breakdown.entropy_consistency.toFixed(2)} × {WEIGHT_ENTROPY}) + ({selectedArtifact.confidence_breakdown.fragmentation_confidence.toFixed(2)} × {WEIGHT_FRAGMENTATION}) + ({selectedArtifact.confidence_breakdown.overwrite_probability.toFixed(2)} × {WEIGHT_OVERWRITE})
                  </div>
                </div>

                {/* Entropy Explainability Basis */}
                {selectedArtifact.confidence_breakdown.entropy_explainability && (
                  <div className="mt-2 p-2 bg-cyan-950/40 border border-cyan-800/50 rounded flex items-start space-x-2 text-[10px]">
                    <span className="text-cyan-400 font-bold">ℹ️</span>
                    <div>
                      <span className="text-cyan-300 font-bold block">ML Signal Basis</span>
                      <span className="text-slate-300">{selectedArtifact.confidence_breakdown.entropy_explainability}</span>
                    </div>
                  </div>
                )}

                {/* Fragmentation Detail Visualization */}
                {selectedArtifact.fragmentation_detail && (
                  <div className="mt-3 p-2.5 bg-slate-900 border border-fuchsia-800/40 rounded-lg space-y-2">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="font-bold text-fuchsia-300 uppercase tracking-wider">
                        Tier 3 Bifragment Reassembly Details
                      </span>
                      <span className="font-mono text-slate-400">
                        Gap: {selectedArtifact.fragmentation_detail.gap_size_sectors} sectors
                      </span>
                    </div>

                    <div className="text-[10px] font-mono text-slate-300 space-y-0.5">
                      <div>Frag 1: LBA {selectedArtifact.fragmentation_detail.fragment_1[0]} → {selectedArtifact.fragmentation_detail.fragment_1[0] + selectedArtifact.fragmentation_detail.fragment_1[1]}</div>
                      <div>Frag 2: LBA {selectedArtifact.fragmentation_detail.fragment_2[0]} → {selectedArtifact.fragmentation_detail.fragment_2[0] + selectedArtifact.fragmentation_detail.fragment_2[1]}</div>
                    </div>

                    {/* Strip Diagram */}
                    <div className="flex items-center space-x-1 h-5 pt-1">
                      <div
                        className="h-full bg-fuchsia-600/80 border border-fuchsia-400 rounded flex items-center justify-center text-[8px] font-mono font-bold text-white px-1 truncate"
                        style={{ flex: 2 }}
                        title={`Fragment 1: LBA ${selectedArtifact.fragmentation_detail.fragment_1[0]}`}
                      >
                        Frag 1
                      </div>
                      <div
                        className="h-full bg-slate-950 border border-dashed border-amber-500/60 rounded flex items-center justify-center text-[8px] font-mono text-amber-400 px-1 truncate"
                        style={{ flex: 1 }}
                        title={`Intervening Gap: ${selectedArtifact.fragmentation_detail.gap_size_sectors} sectors`}
                      >
                        Gap ({selectedArtifact.fragmentation_detail.gap_size_sectors}s)
                      </div>
                      <div
                        className="h-full bg-indigo-600/80 border border-indigo-400 rounded flex items-center justify-center text-[8px] font-mono font-bold text-white px-1 truncate"
                        style={{ flex: 2 }}
                        title={`Fragment 2: LBA ${selectedArtifact.fragmentation_detail.fragment_2[0]}`}
                      >
                        Frag 2
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RecoveryBrowser;
