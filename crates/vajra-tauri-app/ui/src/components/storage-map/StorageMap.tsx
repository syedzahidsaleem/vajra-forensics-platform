import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  StorageMapData,
  RecoveredArtifact,
  getStorageMap,
} from '../../types/vajra';

export interface StorageMapProps {
  sourcePath: string;
  mode: 'forensic' | 'sanitization';
  // During sanitization, caller streams sanitized_ranges updates in
  sanitizedRanges?: [number, number][]; // (start_lba, block_count)[]
  // Optional: highlight specific artifact's LBAs (from Recovery Browser)
  highlightArtifact?: RecoveredArtifact | null;
  onRegionClick?: (startLba: number, blockCount: number) => void;
}

interface SegmentItem {
  id: string;
  startLba: number;
  blockCount: number;
  type: 'allocated' | 'unallocated' | 'bad_sector' | 'recovered' | 'sanitized';
  label: string;
  color: string;
  zIndex: number;
  isOverlay?: boolean;
}

interface SegmentState {
  startLba: number;
  blockCount: number;
  type: string;
  leftPercent: number;
  widthPercent: number;
  clickXPercent?: number;
}

// Helper functions (exported as required)
export const lbaToPercent = (lba: number, totalBlocks: number): number => {
  if (totalBlocks <= 0) return 0;
  return (lba / totalBlocks) * 100;
};

export const rangeToWidthPercent = (
  blockCount: number,
  totalBlocks: number
): number => {
  if (totalBlocks <= 0) return 0;
  return (blockCount / totalBlocks) * 100;
};

export const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

export const computeRegionStats = (
  ranges: [number, number][] = [],
  blockSize: number
): { rangeCount: number; totalSectors: number; totalBytes: number } => {
  const rangeCount = ranges.length;
  const totalSectors = ranges.reduce((acc, [_, count]) => acc + count, 0);
  const totalBytes = totalSectors * blockSize;
  return { rangeCount, totalSectors, totalBytes };
};

export default function StorageMap({
  sourcePath,
  mode,
  sanitizedRanges = [],
  highlightArtifact = null,
  onRegionClick,
}: StorageMapProps) {
  const [storageMap, setStorageMap] = useState<StorageMapData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedSegment, setSelectedSegment] = useState<SegmentState | null>(
    null
  );
  const [hoveredSegment, setHoveredSegment] = useState<SegmentState | null>(
    null
  );

  const barRef = useRef<HTMLDivElement>(null);

  // Fetch StorageMapData on mount & sourcePath change
  const fetchMapData = async () => {
    setIsLoading(true);
    setError(null);
    setSelectedSegment(null);
    setHoveredSegment(null);

    try {
      const data = await getStorageMap(sourcePath);
      setStorageMap(data);
    } catch (err: any) {
      console.error('Failed to load storage map:', err);
      setError(
        typeof err === 'string'
          ? err
          : err?.message || 'Failed to retrieve storage map data'
      );
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (sourcePath) {
      fetchMapData();
    }
  }, [sourcePath]);

  // Calculate sanitization progress statistics
  const sanitizationStats = useMemo(() => {
    if (!storageMap || mode !== 'sanitization') return null;

    const blockSize = storageMap.block_size;
    const allocatedStats = computeRegionStats(
      storageMap.allocated_ranges,
      blockSize
    );
    const sanitizedStats = computeRegionStats(sanitizedRanges, blockSize);

    // Target is allocated blocks if available, else total drive blocks
    const targetSectors =
      allocatedStats.totalSectors > 0
        ? allocatedStats.totalSectors
        : storageMap.total_blocks;

    const percent =
      targetSectors > 0
        ? Math.min(
            100,
            Math.round(
              (sanitizedStats.totalSectors / targetSectors) * 100 * 10
            ) / 10
          )
        : 0;

    const isComplete =
      targetSectors > 0 && sanitizedStats.totalSectors >= targetSectors;

    return {
      sanitizedSectors: sanitizedStats.totalSectors,
      sanitizedBytes: sanitizedStats.totalBytes,
      targetSectors,
      percent,
      isComplete,
    };
  }, [storageMap, mode, sanitizedRanges]);

  // Compute table statistics
  const stats = useMemo(() => {
    if (!storageMap) return null;
    const bs = storageMap.block_size;
    return {
      allocated: computeRegionStats(storageMap.allocated_ranges, bs),
      unallocated: computeRegionStats(storageMap.unallocated_ranges, bs),
      badSectors: computeRegionStats(storageMap.bad_sector_ranges, bs),
      recovered: computeRegionStats(
        storageMap.recovered_fragment_ranges,
        bs
      ),
      sanitized: computeRegionStats(sanitizedRanges, bs),
    };
  }, [storageMap, sanitizedRanges]);

  // Artifact Highlight ranges
  const highlightRanges = useMemo<[number, number][]>(() => {
    if (!highlightArtifact) return [];
    if (
      highlightArtifact.source_locations &&
      highlightArtifact.source_locations.length > 0
    ) {
      return highlightArtifact.source_locations;
    }
    if (highlightArtifact.fragmentation_detail) {
      return [
        highlightArtifact.fragmentation_detail.fragment_1,
        highlightArtifact.fragmentation_detail.fragment_2,
      ];
    }
    return [];
  }, [highlightArtifact]);

  // Handle segment click
  const handleSegmentClick = (
    e: React.MouseEvent<HTMLDivElement>,
    startLba: number,
    blockCount: number,
    typeLabel: string
  ) => {
    e.stopPropagation();

    const totalBlocks = storageMap?.total_blocks || 1;
    const leftPct = lbaToPercent(startLba, totalBlocks);
    const widthPct = rangeToWidthPercent(blockCount, totalBlocks);

    let clickXPercent = leftPct + widthPct / 2;
    if (barRef.current) {
      const rect = barRef.current.getBoundingClientRect();
      if (rect.width > 0) {
        clickXPercent = ((e.clientX - rect.left) / rect.width) * 100;
      }
    }

    const newSeg: SegmentState = {
      startLba,
      blockCount,
      type: typeLabel,
      leftPercent: leftPct,
      widthPercent: widthPct,
      clickXPercent: Math.max(5, Math.min(95, clickXPercent)),
    };

    setSelectedSegment(newSeg);

    if (onRegionClick) {
      onRegionClick(startLba, blockCount);
    }
  };

  // Handle segment hover
  const handleSegmentHover = (
    e: React.MouseEvent<HTMLDivElement>,
    startLba: number,
    blockCount: number,
    typeLabel: string
  ) => {
    const totalBlocks = storageMap?.total_blocks || 1;
    const leftPct = lbaToPercent(startLba, totalBlocks);
    const widthPct = rangeToWidthPercent(blockCount, totalBlocks);

    let hoverXPercent = leftPct + widthPct / 2;
    if (barRef.current) {
      const rect = barRef.current.getBoundingClientRect();
      if (rect.width > 0) {
        hoverXPercent = ((e.clientX - rect.left) / rect.width) * 100;
      }
    }

    setHoveredSegment({
      startLba,
      blockCount,
      type: typeLabel,
      leftPercent: leftPct,
      widthPercent: widthPct,
      clickXPercent: Math.max(5, Math.min(95, hoverXPercent)),
    });
  };

  return (
    <div
      className="w-full font-sans text-sm text-[#D8E4FF] bg-[#00120B] p-5 rounded-xl shadow-2xl border border-[#35605A]/40 select-none transition-all"
      style={
        {
          '--onyx': '#00120B',
          '--dark-slate': '#35605A',
          '--light-green': '#59EE99',
          '--amethyst-smoke': '#AA77A9',
          '--lavender': '#D8E4FF',
        } as React.CSSProperties
      }
      onClick={() => setSelectedSegment(null)}
    >
      {/* ──────────────────────────────────────── */}
      {/* SECTION 1 — Header bar                   */}
      {/* ──────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 mb-5 border-b border-[#35605A]/50">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-wider text-[#D8E4FF]/60 bg-[#35605A]/40 px-2 py-0.5 rounded border border-[#35605A]/60">
              Source Drive
            </span>
            <h2
              className="font-mono text-base font-semibold text-[#D8E4FF] truncate max-w-md"
              title={sourcePath}
            >
              {sourcePath}
            </h2>
          </div>

          <div className="flex items-center gap-4 text-xs text-[#D8E4FF]/80 mt-1">
            <span>
              Total Capacity:{' '}
              <strong className="text-[#D8E4FF] font-mono">
                {storageMap
                  ? formatBytes(storageMap.total_blocks * storageMap.block_size)
                  : '—'}
              </strong>
            </span>
            <span className="text-[#35605A]">•</span>
            <span>
              Block Size:{' '}
              <strong className="text-[#D8E4FF] font-mono">
                {storageMap ? `${storageMap.block_size} B sectors` : '—'}
              </strong>
            </span>
            {storageMap && (
              <>
                <span className="text-[#35605A]">•</span>
                <span>
                  Total Sectors:{' '}
                  <strong className="text-[#D8E4FF] font-mono">
                    {storageMap.total_blocks.toLocaleString()}
                  </strong>
                </span>
              </>
            )}
          </div>
        </div>

        {/* Mode Badge & Sanitization Progress */}
        <div className="flex items-center gap-3 self-start md:self-auto">
          {mode === 'sanitization' && sanitizationStats && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#59EE99]/10 border border-[#59EE99]/30">
              <div className="w-2 h-2 rounded-full bg-[#59EE99] animate-ping" />
              <span className="font-mono text-xs font-bold text-[#59EE99]">
                {sanitizationStats.percent}% SANITIZED
              </span>
            </div>
          )}

          {/* §15 Mode-separation badge requirement:
              FORENSIC MODE in --light-green (#59EE99)
              SANITIZATION MODE in bold RED (#EF4444) strictly separated for safety */}
          {mode === 'forensic' ? (
            <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-md bg-[#59EE99]/15 border border-[#59EE99]/50 text-[#59EE99] shadow-[0_0_12px_rgba(89,238,153,0.15)] font-bold text-xs tracking-wider uppercase">
              <svg
                className="w-3.5 h-3.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              <span>FORENSIC MODE</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-md bg-[#EF4444]/20 border-2 border-[#EF4444] text-[#EF4444] shadow-[0_0_15px_rgba(239,68,68,0.35)] font-extrabold text-xs tracking-wider uppercase animate-pulse">
              <svg
                className="w-4 h-4 text-[#EF4444]"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2.5}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
              <span>SANITIZATION MODE</span>
            </div>
          )}
        </div>
      </div>

      {/* Sanitization Complete Banner (§5) */}
      {mode === 'sanitization' && sanitizationStats?.isComplete && (
        <div className="mb-5 p-3.5 rounded-lg bg-[#59EE99]/15 border-2 border-[#59EE99] flex items-center justify-between shadow-[0_0_20px_rgba(89,238,153,0.25)]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-[#59EE99] text-[#00120B] flex items-center justify-center font-bold text-lg">
              ✓
            </div>
            <div>
              <h4 className="font-bold text-[#59EE99] text-sm uppercase tracking-wide">
                Sanitization Complete
              </h4>
              <p className="text-xs text-[#D8E4FF]/90">
                100% of target allocated sectors have been wiped & verified.
              </p>
            </div>
          </div>
          <span className="font-mono text-xs font-bold px-3 py-1 bg-[#59EE99] text-[#00120B] rounded uppercase tracking-wider">
            Verified Safe
          </span>
        </div>
      )}

      {/* Loading Skeleton */}
      {isLoading && (
        <div className="space-y-4 py-4">
          <div className="w-full h-[48px] bg-[#35605A] rounded-[4px] animate-pulse relative overflow-hidden">
          </div>
          <div className="flex justify-between text-xs font-mono text-[#D8E4FF]/40">
            <span>0 LBA</span>
            <span>25%</span>
            <span>50%</span>
            <span>75%</span>
            <span>100%</span>
          </div>
          <p className="text-center text-xs text-[#D8E4FF]/60 italic py-2">
            Loading storage block layout...
          </p>
        </div>
      )}

      {/* Error state */}
      {!isLoading && error && (
        <div className="my-4 p-4 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/40 flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <svg
              className="w-5 h-5 text-[#EF4444] shrink-0"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span className="text-xs text-[#D8E4FF] font-mono">{error}</span>
          </div>
          <button
            onClick={fetchMapData}
            className="px-3.5 py-1.5 bg-[#35605A] hover:bg-[#35605A]/80 text-[#D8E4FF] font-semibold text-xs rounded border border-[#D8E4FF]/20 transition-all shrink-0 cursor-pointer"
          >
            Retry Loading
          </button>
        </div>
      )}

      {/* ──────────────────────────────────────── */}
      {/* SECTION 2 — LBA Range Map (Visualization)*/}
      {/* ──────────────────────────────────────── */}
      {!isLoading && storageMap && (
        <div className="space-y-3 mb-6 relative">
          <div className="flex justify-between items-center text-xs text-[#D8E4FF]/70">
            <span className="font-semibold uppercase tracking-wider text-[#D8E4FF]">
              LBA Range Space Map
            </span>
            <span className="font-mono text-[11px]">
              LBA 0 → {(storageMap.total_blocks - 1).toLocaleString()}
            </span>
          </div>

          {/* Main Horizontal Bar (Height 48px, rounded 4px, background #35605A) */}
          <div
            ref={barRef}
            className="w-full h-[48px] rounded-[4px] bg-[#35605A] relative overflow-hidden shadow-inner border border-[#35605A]/80 group"
          >
            {/* Base Layer: Allocated Ranges (#35605A) */}
            {storageMap.allocated_ranges.map(([start, count], idx) => {
              const leftPct = lbaToPercent(start, storageMap.total_blocks);
              const widthPct = rangeToWidthPercent(
                count,
                storageMap.total_blocks
              );
              const isSelected =
                selectedSegment?.startLba === start &&
                selectedSegment?.type === 'Allocated';

              return (
                <div
                  key={`alloc-${idx}`}
                  className={`absolute top-0 bottom-0 bg-[#35605A] cursor-pointer transition-all duration-150 hover:brightness-125 hover:z-20 ${
                    isSelected ? 'ring-2 ring-white z-30' : ''
                  }`}
                  style={{
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    minWidth: '3px',
                  }}
                  onClick={(e) =>
                    handleSegmentClick(e, start, count, 'Allocated')
                  }
                  onMouseEnter={(e) =>
                    handleSegmentHover(e, start, count, 'Allocated')
                  }
                  onMouseLeave={() => setHoveredSegment(null)}
                />
              );
            })}

            {/* Base Layer: Unallocated Ranges (#D8E4FF at 20% opacity) */}
            {storageMap.unallocated_ranges.map(([start, count], idx) => {
              const leftPct = lbaToPercent(start, storageMap.total_blocks);
              const widthPct = rangeToWidthPercent(
                count,
                storageMap.total_blocks
              );
              const isSelected =
                selectedSegment?.startLba === start &&
                selectedSegment?.type === 'Unallocated';

              return (
                <div
                  key={`unalloc-${idx}`}
                  className={`absolute top-0 bottom-0 cursor-pointer transition-all duration-150 hover:brightness-125 hover:z-20 ${
                    isSelected ? 'ring-2 ring-white z-30' : ''
                  }`}
                  style={{
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    minWidth: '3px',
                    backgroundColor: 'rgba(216, 228, 255, 0.2)',
                  }}
                  onClick={(e) =>
                    handleSegmentClick(e, start, count, 'Unallocated')
                  }
                  onMouseEnter={(e) =>
                    handleSegmentHover(e, start, count, 'Unallocated')
                  }
                  onMouseLeave={() => setHoveredSegment(null)}
                />
              );
            })}

            {/* Layer: Recovered Fragment Ranges (#AA77A9 - Amethyst Smoke) */}
            {storageMap.recovered_fragment_ranges.map(([start, count], idx) => {
              const leftPct = lbaToPercent(start, storageMap.total_blocks);
              const widthPct = rangeToWidthPercent(
                count,
                storageMap.total_blocks
              );
              const isSelected =
                selectedSegment?.startLba === start &&
                selectedSegment?.type === 'Recovered';

              return (
                <div
                  key={`rec-${idx}`}
                  className={`absolute top-0 bottom-0 bg-[#AA77A9] cursor-pointer transition-all duration-150 hover:brightness-125 z-10 hover:z-20 ${
                    isSelected ? 'ring-2 ring-white z-30' : ''
                  }`}
                  style={{
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    minWidth: '3px',
                  }}
                  onClick={(e) =>
                    handleSegmentClick(e, start, count, 'Recovered')
                  }
                  onMouseEnter={(e) =>
                    handleSegmentHover(e, start, count, 'Recovered')
                  }
                  onMouseLeave={() => setHoveredSegment(null)}
                />
              );
            })}

            {/* Layer: Bad Sector Ranges (#EF4444 - Red) */}
            {storageMap.bad_sector_ranges.map(([start, count], idx) => {
              const leftPct = lbaToPercent(start, storageMap.total_blocks);
              const widthPct = rangeToWidthPercent(
                count,
                storageMap.total_blocks
              );
              const isSelected =
                selectedSegment?.startLba === start &&
                selectedSegment?.type === 'Bad Sector';

              return (
                <div
                  key={`bad-${idx}`}
                  className={`absolute top-0 bottom-0 bg-[#EF4444] cursor-pointer transition-all duration-150 hover:brightness-125 z-10 hover:z-20 ${
                    isSelected ? 'ring-2 ring-white z-30' : ''
                  }`}
                  style={{
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    minWidth: '3px',
                  }}
                  onClick={(e) =>
                    handleSegmentClick(e, start, count, 'Bad Sector')
                  }
                  onMouseEnter={(e) =>
                    handleSegmentHover(e, start, count, 'Bad Sector')
                  }
                  onMouseLeave={() => setHoveredSegment(null)}
                />
              );
            })}

            {/* Layer: Sanitized Ranges (#59EE99 - Light Green, 400ms transition) */}
            {mode === 'sanitization' &&
              sanitizedRanges.map(([start, count], idx) => {
                const leftPct = lbaToPercent(start, storageMap.total_blocks);
                const widthPct = rangeToWidthPercent(
                  count,
                  storageMap.total_blocks
                );
                const isSelected =
                  selectedSegment?.startLba === start &&
                  selectedSegment?.type === 'Sanitized';

                return (
                  <div
                    key={`san-${idx}`}
                    className={`absolute top-0 bottom-0 bg-[#59EE99] cursor-pointer transition-all duration-300 ease-in-out hover:brightness-125 z-10 hover:z-20 ${
                      isSelected ? 'ring-2 ring-white z-30' : ''
                    }`}
                    style={{
                      left: `${leftPct}%`,
                      width: `${widthPct}%`,
                      minWidth: '3px',
                    }}
                    onClick={(e) =>
                      handleSegmentClick(e, start, count, 'Sanitized')
                    }
                    onMouseEnter={(e) =>
                      handleSegmentHover(e, start, count, 'Sanitized')
                    }
                    onMouseLeave={() => setHoveredSegment(null)}
                  />
                );
              })}

            {/* Layer: Highlight Artifact LBAs (Pulsing #59EE99 Outline) */}
            {highlightRanges.map(([start, count], idx) => {
              const leftPct = lbaToPercent(start, storageMap.total_blocks);
              const widthPct = rangeToWidthPercent(
                count,
                storageMap.total_blocks
              );

              return (
                <div
                  key={`hl-${idx}`}
                  className="absolute top-0 bottom-0 border-2 border-[#59EE99] shadow-[0_0_10px_#59EE99] animate-pulse z-20 pointer-events-none rounded-[2px]"
                  style={{
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    minWidth: '4px',
                  }}
                />
              );
            })}

            {/* Interactive Detail Popover Above Click Point (§4) */}
            {selectedSegment && (
              <div
                className="absolute z-40 bg-[#00120B] text-[#D8E4FF] p-3 rounded-lg border border-[#59EE99]/50 shadow-[0_0_20px_rgba(0,0,0,0.8)] text-xs font-sans min-w-[220px]"
                style={{
                  left: `${selectedSegment.clickXPercent}%`,
                  top: '50%',
                  transform: 'translate(-50%, -50%)',
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex items-center justify-between border-b border-[#35605A] pb-1.5 mb-2">
                  <span className="font-bold text-[#59EE99] uppercase tracking-wider text-[11px]">
                    {selectedSegment.type} Region
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedSegment(null);
                    }}
                    className="text-[#D8E4FF]/60 hover:text-white font-bold px-1 text-sm cursor-pointer"
                  >
                    ×
                  </button>
                </div>
                <div className="space-y-1 font-mono text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-[#D8E4FF]/60">Start LBA:</span>
                    <span className="font-bold">
                      {selectedSegment.startLba.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#D8E4FF]/60">End LBA:</span>
                    <span className="font-bold">
                      {(
                        selectedSegment.startLba +
                        selectedSegment.blockCount -
                        1
                      ).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#D8E4FF]/60">Sectors:</span>
                    <span className="font-bold">
                      {selectedSegment.blockCount.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#D8E4FF]/60">Size:</span>
                    <span className="font-bold text-[#59EE99]">
                      {formatBytes(
                        selectedSegment.blockCount * storageMap.block_size
                      )}
                    </span>
                  </div>
                  <div className="flex justify-between pt-1 border-t border-[#35605A]/40">
                    <span className="text-[#D8E4FF]/60">% of Drive:</span>
                    <span className="font-bold">
                      {(
                        (selectedSegment.blockCount /
                          storageMap.total_blocks) *
                        100
                      ).toFixed(2)}
                      %
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Hover Tooltip */}
          {hoveredSegment && !selectedSegment && (
            <div
              className="pointer-events-none absolute z-30 -top-12 bg-[#00120B]/95 text-[#D8E4FF] px-2.5 py-1.5 rounded border border-[#35605A] shadow-lg text-[11px] font-mono flex items-center gap-2 whitespace-nowrap"
              style={{
                left: `${hoveredSegment.clickXPercent}%`,
                transform: 'translateX(-50%)',
              }}
            >
              <span className="w-2 h-2 rounded-full bg-[#59EE99]" />
              <span>
                <strong>{hoveredSegment.type}:</strong> LBA{' '}
                {hoveredSegment.startLba.toLocaleString()} →{' '}
                {(
                  hoveredSegment.startLba +
                  hoveredSegment.blockCount -
                  1
                ).toLocaleString()}{' '}
                (
                {formatBytes(
                  hoveredSegment.blockCount * storageMap.block_size
                )}
                )
              </span>
            </div>
          )}

          {/* LBA Ruler with tick marks at 0%, 25%, 50%, 75%, 100% */}
          <div className="relative w-full pt-1">
            <div className="flex justify-between w-full font-mono text-[11px] text-[#D8E4FF]">
              <div className="flex flex-col items-start">
                <div className="h-2 w-px bg-[#D8E4FF]/40 mb-1" />
                <span>0 LBA</span>
              </div>
              <div className="flex flex-col items-center">
                <div className="h-2 w-px bg-[#D8E4FF]/40 mb-1" />
                <span>
                  {Math.round(
                    storageMap.total_blocks * 0.25
                  ).toLocaleString()}{' '}
                  (25%)
                </span>
              </div>
              <div className="flex flex-col items-center">
                <div className="h-2 w-px bg-[#D8E4FF]/40 mb-1" />
                <span>
                  {Math.round(
                    storageMap.total_blocks * 0.5
                  ).toLocaleString()}{' '}
                  (50%)
                </span>
              </div>
              <div className="flex flex-col items-center">
                <div className="h-2 w-px bg-[#D8E4FF]/40 mb-1" />
                <span>
                  {Math.round(
                    storageMap.total_blocks * 0.75
                  ).toLocaleString()}{' '}
                  (75%)
                </span>
              </div>
              <div className="flex flex-col items-end">
                <div className="h-2 w-px bg-[#D8E4FF]/40 mb-1" />
                <span>
                  {storageMap.total_blocks.toLocaleString()} (100%)
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ──────────────────────────────────────── */}
      {/* SECTION 3 — Region legend + stats table  */}
      {/* ──────────────────────────────────────── */}
      {!isLoading && storageMap && stats && (
        <div className="space-y-4 pt-4 border-t border-[#35605A]/40">
          {/* Horizontal Legend Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-sm bg-[#35605A] border border-[#D8E4FF]/20" />
                <span className="text-[#D8E4FF]">Allocated</span>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className="w-3 h-3 rounded-sm border border-[#D8E4FF]/40"
                  style={{ backgroundColor: 'rgba(216, 228, 255, 0.2)' }}
                />
                <span className="text-[#D8E4FF]">Unallocated</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-sm bg-[#EF4444]" />
                <span className="text-[#D8E4FF]">Bad Sectors</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-sm bg-[#AA77A9]" />
                <span className="text-[#D8E4FF]">Recovered</span>
              </div>
              {mode === 'sanitization' && (
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-sm bg-[#59EE99]" />
                  <span className="text-[#D8E4FF]">Sanitized</span>
                </div>
              )}
              {highlightArtifact && (
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-sm border-2 border-[#59EE99] animate-pulse bg-transparent" />
                  <span className="text-[#59EE99] font-medium">
                    Artifact Target
                  </span>
                </div>
              )}
            </div>

            <div className="text-[11px] text-[#D8E4FF]/60 font-mono">
              Total Space: {formatBytes(storageMap.total_blocks * storageMap.block_size)}
            </div>
          </div>

          {/* Compact Stats Table (4 columns, no borders — spacing only) */}
          <div className="overflow-x-auto bg-[#35605A]/20 rounded-lg p-3 border border-[#35605A]/30">
            <table className="w-full text-left text-xs border-collapse font-sans">
              <thead>
                <tr className="text-[#D8E4FF]/60 text-[11px] uppercase tracking-wider border-b border-[#35605A]/40 pb-2">
                  <th className="py-2 px-3 font-semibold">Region</th>
                  <th className="py-2 px-3 font-semibold">LBA Ranges</th>
                  <th className="py-2 px-3 font-semibold text-right">
                    Total Sectors
                  </th>
                  <th className="py-2 px-3 font-semibold text-right">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#35605A]/20 font-mono text-[12px]">
                {/* Allocated */}
                <tr className="hover:bg-[#35605A]/30 transition-colors">
                  <td className="py-2 px-3 font-sans font-medium text-[#D8E4FF] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#35605A]" />
                    Allocated
                  </td>
                  <td className="py-2 px-3 text-[#D8E4FF]/90">
                    {stats.allocated.rangeCount} {stats.allocated.rangeCount === 1 ? 'range' : 'ranges'}
                  </td>
                  <td className="py-2 px-3 text-right text-[#D8E4FF]/90">
                    {stats.allocated.totalSectors.toLocaleString()}
                  </td>
                  <td className="py-2 px-3 text-right font-bold text-[#D8E4FF]">
                    {formatBytes(stats.allocated.totalBytes)}
                  </td>
                </tr>

                {/* Unallocated */}
                <tr className="hover:bg-[#35605A]/30 transition-colors">
                  <td className="py-2 px-3 font-sans font-medium text-[#D8E4FF] flex items-center gap-2">
                    <span
                      className="w-2 h-2 rounded-full border border-[#D8E4FF]/60"
                      style={{ backgroundColor: 'rgba(216, 228, 255, 0.2)' }}
                    />
                    Unallocated
                  </td>
                  <td className="py-2 px-3 text-[#D8E4FF]/90">
                    {stats.unallocated.rangeCount} {stats.unallocated.rangeCount === 1 ? 'range' : 'ranges'}
                  </td>
                  <td className="py-2 px-3 text-right text-[#D8E4FF]/90">
                    {stats.unallocated.totalSectors.toLocaleString()}
                  </td>
                  <td className="py-2 px-3 text-right font-bold text-[#D8E4FF]">
                    {formatBytes(stats.unallocated.totalBytes)}
                  </td>
                </tr>

                {/* Bad Sectors */}
                <tr className="hover:bg-[#35605A]/30 transition-colors">
                  <td className="py-2 px-3 font-sans font-medium text-[#EF4444] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#EF4444]" />
                    Bad Sectors
                  </td>
                  <td className="py-2 px-3 text-[#D8E4FF]/90">
                    {stats.badSectors.rangeCount} {stats.badSectors.rangeCount === 1 ? 'range' : 'ranges'}
                  </td>
                  <td className="py-2 px-3 text-right text-[#D8E4FF]/90">
                    {stats.badSectors.totalSectors.toLocaleString()}
                  </td>
                  <td className="py-2 px-3 text-right font-bold text-[#EF4444]">
                    {formatBytes(stats.badSectors.totalBytes)}
                  </td>
                </tr>

                {/* Recovered */}
                <tr className="hover:bg-[#35605A]/30 transition-colors">
                  <td className="py-2 px-3 font-sans font-medium text-[#AA77A9] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#AA77A9]" />
                    Recovered
                  </td>
                  <td className="py-2 px-3 text-[#D8E4FF]/90">
                    {stats.recovered.rangeCount} {stats.recovered.rangeCount === 1 ? 'range' : 'ranges'}
                  </td>
                  <td className="py-2 px-3 text-right text-[#D8E4FF]/90">
                    {stats.recovered.totalSectors.toLocaleString()}
                  </td>
                  <td className="py-2 px-3 text-right font-bold text-[#AA77A9]">
                    {formatBytes(stats.recovered.totalBytes)}
                  </td>
                </tr>

                {/* Sanitized (sanitization mode only) */}
                {mode === 'sanitization' && (
                  <tr className="hover:bg-[#35605A]/30 transition-colors bg-[#59EE99]/5">
                    <td className="py-2 px-3 font-sans font-medium text-[#59EE99] flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-[#59EE99]" />
                      Sanitized
                    </td>
                    <td className="py-2 px-3 text-[#59EE99]">
                      {stats.sanitized.rangeCount} {stats.sanitized.rangeCount === 1 ? 'range' : 'ranges'}
                    </td>
                    <td className="py-2 px-3 text-right text-[#59EE99]">
                      {stats.sanitized.totalSectors.toLocaleString()}
                    </td>
                    <td className="py-2 px-3 text-right font-bold text-[#59EE99]">
                      {formatBytes(stats.sanitized.totalBytes)}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
