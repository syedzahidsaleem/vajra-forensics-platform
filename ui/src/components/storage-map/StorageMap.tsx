import React, { useState, useMemo } from 'react';
import { Layers, Database, Info } from 'lucide-react';

export interface StorageRegion {
  startLba: number;
  endLba: number;
  type: 'allocated' | 'unallocated' | 'bad_sector' | 'fragment' | 'sanitized' | 'wiping' | 'pending';
  label?: string;
  metadata?: Record<string, any>;
}

export interface StorageMapProps {
  sourcePath?: string;
  totalBlocks?: number;
  mode: 'sanitization' | 'forensic';
  sanitizedRanges?: Array<{ startLba: number; endLba: number; pass?: number } | [number, number]>;
  highlightArtifact?: { startLba: number; blockCount: number; name?: string } | null;
  onRegionClick?: (startLba: number, blockCount: number) => void;
  className?: string;
}

export const StorageMap: React.FC<StorageMapProps> = ({
  sourcePath = '\\\\.\\PhysicalDrive0',
  totalBlocks = 1000000,
  mode,
  sanitizedRanges = [],
  highlightArtifact,
  onRegionClick,
  className = '',
}) => {
  const [hoveredBlock, setHoveredBlock] = useState<{
    index: number;
    startLba: number;
    endLba: number;
    status: string;
  } | null>(null);

  const [selectedBlockIndex, setSelectedBlockIndex] = useState<number | null>(null);

  // Normalize sanitizedRanges whether passed as objects or tuples [start, count]
  const normalizedSanitizedRanges = useMemo(() => {
    return sanitizedRanges.map((range) => {
      if (Array.isArray(range)) {
        return { startLba: range[0], endLba: range[0] + range[1] };
      }
      return range;
    });
  }, [sanitizedRanges]);

  // Total resolution segments in the visual map
  const TOTAL_SEGMENTS = 128;
  const blocksPerSegment = Math.max(1, Math.floor(totalBlocks / TOTAL_SEGMENTS));

  // Determine state of each segment
  const segments = useMemo(() => {
    return Array.from({ length: TOTAL_SEGMENTS }, (_, i) => {
      const startLba = i * blocksPerSegment;
      const endLba = (i + 1) * blocksPerSegment - 1;

      if (mode === 'sanitization') {
        const isSanitized = normalizedSanitizedRanges.some(
          (r) => r.startLba <= endLba && r.endLba >= startLba
        );
        const isCurrentlyWiping =
          normalizedSanitizedRanges.length > 0 &&
          i === Math.min(TOTAL_SEGMENTS - 1, Math.floor((normalizedSanitizedRanges[normalizedSanitizedRanges.length - 1]?.endLba || 0) / blocksPerSegment));

        let status = 'pending';
        let colorClass = 'bg-amber-950/40 border-amber-800/30 hover:border-amber-500';

        if (isSanitized) {
          status = 'sanitized';
          colorClass = 'bg-emerald-600 border-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.3)]';
        } else if (isCurrentlyWiping) {
          status = 'wiping';
          colorClass = 'bg-amber-500 animate-pulse border-amber-300 shadow-[0_0_10px_rgba(245,158,11,0.5)]';
        }

        return { index: i, startLba, endLba, status, colorClass };
      } else {
        // Forensic Mode
        const isHighlighted =
          highlightArtifact &&
          highlightArtifact.startLba <= endLba &&
          highlightArtifact.startLba + highlightArtifact.blockCount >= startLba;

        // Deterministic synthetic distribution for demonstration when analyzing raw drives
        const isBadSector = i === 14 || i === 82;
        const isAllocated = (i >= 0 && i < 40) || (i >= 60 && i < 90);

        let status = isAllocated ? 'allocated' : 'unallocated';
        let colorClass = isAllocated
          ? 'bg-[rgba(13,184,211,0.35)] border-[rgba(13,184,211,0.5)] hover:border-[#0DB8D3]'
          : 'bg-[rgba(15,36,48,0.7)] border-[rgba(13,184,211,0.15)] hover:border-[rgba(13,184,211,0.4)]';

        if (isBadSector) {
          status = 'bad_sector';
          colorClass = 'bg-rose-600 border-rose-400 animate-pulse';
        } else if (isHighlighted) {
          status = 'artifact';
          colorClass = 'bg-[#0DB8D3] border-[#C9E8F5] shadow-[0_0_10px_rgba(13,184,211,0.6)] ring-2 ring-[#0DB8D3]';
        }

        return { index: i, startLba, endLba, status, colorClass };
      }
    });
  }, [TOTAL_SEGMENTS, blocksPerSegment, mode, normalizedSanitizedRanges, highlightArtifact, totalBlocks]);

  const handleCellClick = (startLba: number, endLba: number, index: number) => {
    setSelectedBlockIndex(index);
    if (onRegionClick) {
      onRegionClick(startLba, endLba - startLba + 1);
    }
  };

  const isSanitizing = mode === 'sanitization';

  return (
    <div
      className={`rounded-xl border p-4 transition-all duration-200 ${
        isSanitizing
          ? 'bg-zinc-950/80 border-amber-900/40 shadow-lg shadow-amber-950/20'
          : 'glass shadow-lg'
      } ${className}`}
    >
      {/* Header & Meta */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <Layers className={`w-4 h-4 ${isSanitizing ? 'text-amber-500' : 'text-[#0DB8D3]'}`} />
          <span className={`text-xs font-semibold uppercase tracking-wider ${isSanitizing ? 'text-slate-300' : 'text-[var(--forensic-text-primary)]'}`}>
            LBA Block Allocation & Sector Map (§32)
          </span>
          <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${isSanitizing ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-[rgba(13,184,211,0.1)] text-[var(--forensic-text-mono)] border-[var(--forensic-border)]'}`}>
            {sourcePath}
          </span>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[11px] font-medium text-slate-400">
          {isSanitizing ? (
            <>
              <div className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-600 border border-emerald-400 inline-block" />
                <span>Sanitized / Zero-Entropy</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 animate-pulse border border-amber-300 inline-block" />
                <span>Active Overwrite</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-950/40 border border-amber-800/40 inline-block" />
                <span>Pending Sweep</span>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center gap-1 text-[var(--forensic-text-secondary)]">
                <span className="w-2.5 h-2.5 rounded-sm bg-[rgba(13,184,211,0.4)] border border-[#0DB8D3] inline-block" />
                <span>Allocated</span>
              </div>
              <div className="flex items-center gap-1 text-[var(--forensic-text-secondary)]">
                <span className="w-2.5 h-2.5 rounded-sm bg-[rgba(15,36,48,0.7)] border border-[rgba(13,184,211,0.2)] inline-block" />
                <span>Unallocated Slack</span>
              </div>
              <div className="flex items-center gap-1 text-[var(--forensic-text-secondary)]">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-600 border border-rose-400 inline-block" />
                <span>Bad Sector</span>
              </div>
              <div className="flex items-center gap-1 text-[var(--forensic-text-secondary)]">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#0DB8D3] border border-[#C9E8F5] inline-block" />
                <span>Target Artifact</span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Grid Canvas */}
      <div className="grid grid-cols-16 sm:grid-cols-32 gap-1 p-2 rounded-lg bg-black/40 border border-slate-800/80 mb-2">
        {segments.map((seg) => (
          <button
            key={seg.index}
            type="button"
            onClick={() => handleCellClick(seg.startLba, seg.endLba, seg.index)}
            onMouseEnter={() =>
              setHoveredBlock({
                index: seg.index,
                startLba: seg.startLba,
                endLba: seg.endLba,
                status: seg.status,
              })
            }
            onMouseLeave={() => setHoveredBlock(null)}
            className={`h-4.5 rounded-[2px] border transition-all duration-100 cursor-pointer ${
              seg.colorClass
            } ${selectedBlockIndex === seg.index ? 'ring-2 ring-white scale-110 z-10' : ''}`}
            title={`LBA ${seg.startLba.toLocaleString()} - ${seg.endLba.toLocaleString()} (${seg.status})`}
          />
        ))}
      </div>

      {/* Interactive Telemetry Tooltip / Footer */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1">
        <div className="flex items-center gap-2">
          <Database className="w-3.5 h-3.5 text-slate-500" />
          <span>LBA Range: 0 .. {totalBlocks.toLocaleString()}</span>
        </div>

        {hoveredBlock ? (
          <div className="flex items-center gap-2 text-slate-200">
            <Info className="w-3 h-3 text-cyan-400" />
            <span>
              Segment #{hoveredBlock.index}: LBA [{hoveredBlock.startLba.toLocaleString()} ..{' '}
              {hoveredBlock.endLba.toLocaleString()}]
            </span>
            <span className="capitalize px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-amber-300 font-sans border border-slate-700">
              {hoveredBlock.status.replace('_', ' ')}
            </span>
          </div>
        ) : (
          <span className="text-slate-500 italic">Hover or click block to inspect sector provenance</span>
        )}
      </div>
    </div>
  );
};

export default StorageMap;
