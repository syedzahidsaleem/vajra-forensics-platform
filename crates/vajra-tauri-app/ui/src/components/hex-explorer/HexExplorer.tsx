import React, { useState, useEffect, useMemo, useRef } from 'react';
import { RecoveredArtifact, readRawSectors } from '../../types/vajra';

interface HexExplorerProps {
  artifact: RecoveredArtifact;
  sourcePath: string;
}

export type FragmentType = 'fragment1' | 'fragment2' | 'gap' | 'unrelated';

export interface HexCell {
  value: number;
  fragment: FragmentType;
  absLba: number;
  lbaOffset: number;
  absoluteIndex: number;
}

export interface FormattedRow {
  offset: string;
  hexCells: HexCell[];
  ascii: string;
}

const SECTOR_SIZE = 512;
const BLOCKS_PER_PAGE = 4;

/**
 * Classifies an LBA into fragment1, fragment2, gap, or unrelated based on artifact provenance (§32).
 */
export const lbaToFragment = (lba: number, artifact: RecoveredArtifact): FragmentType => {
  const frag = artifact.fragmentation_detail;

  if (frag) {
    const f1Start = frag.fragment_1[0];
    const f1End = f1Start + frag.fragment_1[1];
    const f2Start = frag.fragment_2[0];
    const f2End = f2Start + frag.fragment_2[1];

    if (lba >= f1Start && lba < f1End) {
      return 'fragment1';
    }
    if (lba >= f2Start && lba < f2End) {
      return 'fragment2';
    }
    if (lba >= f1End && lba < f2Start) {
      return 'gap';
    }
  }

  // Fallback / Contiguous checking against source_locations
  for (const [start, count] of artifact.source_locations) {
    if (lba >= start && lba < start + count) {
      return 'fragment1';
    }
  }

  return 'unrelated';
};

/**
 * Converts a byte value into printable ASCII (0x20–0x7E) or middle dot "·".
 */
export const byteToAscii = (b: number): string => {
  if (b >= 0x20 && b <= 0x7e) {
    return String.fromCharCode(b);
  }
  return '·';
};

/**
 * Formats a slice of bytes into hex cells, offset string, and ascii line.
 */
export const formatHexRow = (
  bytes: number[],
  baseLba: number,
  rowOffset: number,
  bytesPerRow: number,
  artifact: RecoveredArtifact
): FormattedRow => {
  const hexCells: HexCell[] = [];
  let asciiStr = '';

  const hexOffsetStr = rowOffset.toString(16).padStart(8, '0').toUpperCase();

  for (let i = 0; i < bytesPerRow; i++) {
    const absIdx = rowOffset + i;
    if (absIdx < bytes.length) {
      const val = bytes[absIdx];
      const sectorIndex = Math.floor(absIdx / SECTOR_SIZE);
      const absLba = baseLba + sectorIndex;
      const lbaOffset = absIdx % SECTOR_SIZE;
      const frag = lbaToFragment(absLba, artifact);

      hexCells.push({
        value: val,
        fragment: frag,
        absLba,
        lbaOffset,
        absoluteIndex: absIdx,
      });

      asciiStr += byteToAscii(val);
    }
  }

  return {
    offset: hexOffsetStr,
    hexCells,
    ascii: asciiStr,
  };
};

export const HexExplorer: React.FC<HexExplorerProps> = ({ artifact, sourcePath }) => {
  const initialLba = useMemo(() => {
    if (artifact.source_locations && artifact.source_locations.length > 0) {
      return artifact.source_locations[0][0];
    }
    return 0;
  }, [artifact]);

  const [currentLba, setCurrentLba] = useState<number>(initialLba);
  const [jumpInput, setJumpInput] = useState<string>(initialLba.toString());
  const [rawSectorData, setRawSectorData] = useState<number[] | null>(null);
  const [bytesPerRow, setBytesPerRow] = useState<8 | 16 | 32>(16);
  const [hoveredCell, setHoveredCell] = useState<HexCell | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Sync initial LBA when artifact changes
  useEffect(() => {
    setCurrentLba(initialLba);
    setJumpInput(initialLba.toString());
  }, [artifact, initialLba]);

  // Debounced raw sector loader
  useEffect(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    setIsLoading(true);
    setError(null);

    debounceTimerRef.current = setTimeout(async () => {
      try {
        const data = await readRawSectors(sourcePath, currentLba, BLOCKS_PER_PAGE);
        setRawSectorData(data);
      } catch (err: any) {
        setError(typeof err === 'string' ? err : err?.message || 'Failed to read raw sector data.');
      } finally {
        setIsLoading(false);
      }
    }, 150);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [currentLba, sourcePath]);

  // Overall bounds calculation for LBA range map
  const rangeBounds = useMemo(() => {
    let minLba = Infinity;
    let maxLba = -Infinity;

    if (artifact.fragmentation_detail) {
      const f = artifact.fragmentation_detail;
      minLba = Math.min(f.fragment_1[0], f.fragment_2[0]);
      maxLba = Math.max(f.fragment_1[0] + f.fragment_1[1], f.fragment_2[0] + f.fragment_2[1]);
    } else {
      for (const [start, count] of artifact.source_locations) {
        if (start < minLba) minLba = start;
        if (start + count > maxLba) maxLba = start + count;
      }
    }

    if (minLba === Infinity) minLba = currentLba;
    if (maxLba === -Infinity) maxLba = currentLba + BLOCKS_PER_PAGE;
    if (minLba === maxLba) maxLba = minLba + BLOCKS_PER_PAGE;

    return { minLba, maxLba, totalSpan: maxLba - minLba };
  }, [artifact, currentLba]);

  // Total blocks display approximation
  const totalBlocksDisplay = Math.max(rangeBounds.maxLba, currentLba + BLOCKS_PER_PAGE);

  // Handle Sector Navigation
  const handlePrev = () => {
    setCurrentLba(prev => Math.max(0, prev - BLOCKS_PER_PAGE));
  };

  const handleNext = () => {
    setCurrentLba(prev => prev + BLOCKS_PER_PAGE);
  };

  const handleJumpSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(jumpInput, 10);
    if (!isNaN(parsed) && parsed >= 0) {
      setCurrentLba(parsed);
    }
  };

  // Convert LBA percentage for Range Map
  const getPercent = (lba: number) => {
    const raw = ((lba - rangeBounds.minLba) / rangeBounds.totalSpan) * 100;
    return Math.min(100, Math.max(0, raw));
  };

  // Hex rows generation
  const formattedRows: FormattedRow[] = useMemo(() => {
    if (!rawSectorData) return [];
    const rows: FormattedRow[] = [];
    for (let offset = 0; offset < rawSectorData.length; offset += bytesPerRow) {
      rows.push(formatHexRow(rawSectorData, currentLba, offset, bytesPerRow, artifact));
    }
    return rows;
  }, [rawSectorData, currentLba, bytesPerRow, artifact]);

  // Fragment styling helper for cells
  const getCellBg = (frag: FragmentType, isHovered: boolean): string => {
    let base = 'hover:ring-1 hover:ring-cyan-400 cursor-crosshair ';
    switch (frag) {
      case 'fragment1':
        base += isHovered ? 'bg-blue-600 text-white font-bold' : 'bg-blue-950/80 text-blue-300 border-blue-800/60';
        break;
      case 'fragment2':
        base += isHovered ? 'bg-purple-600 text-white font-bold' : 'bg-purple-950/80 text-purple-300 border-purple-800/60';
        break;
      case 'gap':
        base += isHovered ? 'bg-red-700 text-white font-bold' : 'bg-red-950/90 text-red-300 border-red-800/70 stripe-bg';
        break;
      case 'unrelated':
      default:
        base += isHovered ? 'bg-slate-700 text-slate-100' : 'text-slate-400 border-slate-800/50';
    }
    return base;
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 font-sans p-4 space-y-4 rounded-xl border border-slate-800 shadow-2xl overflow-hidden">
      {/* ───────────────────────────────────────────── */}
      {/* PANEL 1 — SECTOR NAVIGATION BAR (Fixed Top)  */}
      {/* ───────────────────────────────────────────── */}
      <div className="bg-slate-900/90 p-3.5 rounded-xl border border-slate-800 backdrop-blur-md flex flex-wrap items-center justify-between gap-3 shrink-0 shadow-lg">
        {/* Info label */}
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-950/80 border border-indigo-700/50 rounded-lg text-indigo-400">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
          </div>
          <div>
            <div className="text-xs font-bold text-slate-200 font-mono">
              Viewing LBA <span className="text-cyan-400">{currentLba}</span> —{' '}
              <span className="text-cyan-400">{currentLba + BLOCKS_PER_PAGE - 1}</span> of{' '}
              <span className="text-slate-400">{totalBlocksDisplay}</span> total
            </div>
            <div className="text-[10px] text-slate-400 font-mono">
              Artifact: <span className="text-cyan-300 font-semibold">#R-{artifact.id} ({artifact.file_type.toUpperCase()})</span>
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center space-x-4 text-xs">
          {/* Step Prev/Next */}
          <div className="flex items-center space-x-1.5">
            <button
              onClick={handlePrev}
              disabled={currentLba === 0}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 font-mono rounded border border-slate-700 transition"
              title="Previous 4 Sectors"
            >
              ◀ Prev
            </button>
            <button
              onClick={handleNext}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono rounded border border-slate-700 transition"
              title="Next 4 Sectors"
            >
              Next ▶
            </button>
          </div>

          {/* Jump-to-LBA Input */}
          <form onSubmit={handleJumpSubmit} className="flex items-center space-x-1.5">
            <span className="text-[10px] text-slate-400 font-mono">LBA:</span>
            <input
              type="number"
              min="0"
              value={jumpInput}
              onChange={e => setJumpInput(e.target.value)}
              className="w-24 px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-100 text-xs font-mono focus:outline-none focus:border-cyan-500"
              placeholder="Jump LBA"
            />
            <button
              type="submit"
              className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 font-bold font-mono rounded border border-cyan-700 transition"
            >
              Go
            </button>
          </form>

          {/* Bytes Per Row Selector */}
          <div className="flex items-center space-x-1 font-mono">
            <span className="text-[10px] text-slate-400 mr-1">Bytes/Row:</span>
            {[8, 16, 32].map(b => (
              <button
                key={b}
                onClick={() => setBytesPerRow(b as 8 | 16 | 32)}
                className={`px-2 py-0.5 rounded text-[11px] border transition ${
                  bytesPerRow === b
                    ? 'bg-cyan-900/80 text-cyan-200 border-cyan-600 font-bold'
                    : 'bg-slate-950 text-slate-500 border-slate-800 hover:border-slate-700'
                }`}
              >
                {b}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ───────────────────────────────────────────── */}
      {/* PANEL 2 — LBA RANGE MAP (Elite Feature)       */}
      {/* ───────────────────────────────────────────── */}
      <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 backdrop-blur-md flex flex-col space-y-3 shrink-0 shadow-lg">
        <div className="flex justify-between items-center text-xs">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
              Physical LBA Provenance Map (§32)
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              Range: LBA {rangeBounds.minLba} → {rangeBounds.maxLba}
            </span>
          </div>
          {artifact.fragmentation_detail ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-fuchsia-950 text-fuchsia-300 border border-fuchsia-700/60 font-mono">
              Tier 3 Reassembled (BGC Gap Carving)
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-mono">
              Contiguous Extent
            </span>
          )}
        </div>

        {/* The Map Bar Strip Container */}
        <div className="relative w-full h-8 bg-slate-950 rounded-lg border border-slate-800 overflow-hidden cursor-pointer select-none">
          {/* Fragment & Gap Segments */}
          {artifact.fragmentation_detail ? (
            <>
              {/* Fragment 1 */}
              <div
                onClick={() => setCurrentLba(artifact.fragmentation_detail!.fragment_1[0])}
                className="absolute top-0 bottom-0 bg-blue-500/80 hover:bg-blue-500 transition-colors flex items-center justify-center text-[9px] font-bold text-white font-mono"
                style={{
                  left: `${getPercent(artifact.fragmentation_detail.fragment_1[0])}%`,
                  width: `${Math.max(1, getPercent(artifact.fragmentation_detail.fragment_1[0] + artifact.fragmentation_detail.fragment_1[1]) - getPercent(artifact.fragmentation_detail.fragment_1[0]))}%`,
                }}
                title={`Fragment 1: LBA ${artifact.fragmentation_detail.fragment_1[0]} → ${artifact.fragmentation_detail.fragment_1[0] + artifact.fragmentation_detail.fragment_1[1]}`}
              >
                Frag 1
              </div>

              {/* Gap Region */}
              <div
                onClick={() => setCurrentLba(artifact.fragmentation_detail!.fragment_1[0] + artifact.fragmentation_detail!.fragment_1[1])}
                className="absolute top-0 bottom-0 bg-gradient-to-r from-red-950 via-red-900 to-red-950 border-x border-red-600/60 flex items-center justify-center text-[9px] font-bold text-red-300 font-mono overflow-hidden"
                style={{
                  left: `${getPercent(artifact.fragmentation_detail.fragment_1[0] + artifact.fragmentation_detail.fragment_1[1])}%`,
                  width: `${Math.max(1, getPercent(artifact.fragmentation_detail.fragment_2[0]) - getPercent(artifact.fragmentation_detail.fragment_1[0] + artifact.fragmentation_detail.fragment_1[1]))}%`,
                  backgroundImage:
                    'repeating-linear-gradient(45deg, rgba(220, 38, 38, 0.4), rgba(220, 38, 38, 0.4) 10px, rgba(0, 0, 0, 0.6) 10px, rgba(0, 0, 0, 0.6) 20px)',
                }}
                title={`GAP: ${artifact.fragmentation_detail.gap_size_sectors} sectors`}
              >
                GAP ({artifact.fragmentation_detail.gap_size_sectors}s)
              </div>

              {/* Fragment 2 */}
              <div
                onClick={() => setCurrentLba(artifact.fragmentation_detail!.fragment_2[0])}
                className="absolute top-0 bottom-0 bg-purple-600/80 hover:bg-purple-600 transition-colors flex items-center justify-center text-[9px] font-bold text-white font-mono"
                style={{
                  left: `${getPercent(artifact.fragmentation_detail.fragment_2[0])}%`,
                  width: `${Math.max(1, getPercent(artifact.fragmentation_detail.fragment_2[0] + artifact.fragmentation_detail.fragment_2[1]) - getPercent(artifact.fragmentation_detail.fragment_2[0]))}%`,
                }}
                title={`Fragment 2: LBA ${artifact.fragmentation_detail.fragment_2[0]} → ${artifact.fragmentation_detail.fragment_2[0] + artifact.fragmentation_detail.fragment_2[1]}`}
              >
                Frag 2
              </div>
            </>
          ) : (
            // Contiguous Extent Bar
            artifact.source_locations.map(([start, count], i) => (
              <div
                key={i}
                onClick={() => setCurrentLba(start)}
                className="absolute top-0 bottom-0 bg-blue-500/80 hover:bg-blue-500 transition-colors flex items-center justify-center text-[9px] font-bold text-white font-mono"
                style={{
                  left: `${getPercent(start)}%`,
                  width: `${Math.max(1, getPercent(start + count) - getPercent(start))}%`,
                }}
                title={`Contiguous Extent: LBA ${start} → ${start + count}`}
              >
                Contiguous Payload
              </div>
            ))
          )}

          {/* Current View Indicator Overlay */}
          <div
            className="absolute top-0 bottom-0 border-2 border-cyan-400 bg-cyan-400/20 shadow-lg pointer-events-none transition-all duration-150 z-10"
            style={{
              left: `${getPercent(currentLba)}%`,
              width: `${Math.max(0.8, getPercent(currentLba + BLOCKS_PER_PAGE) - getPercent(currentLba))}%`,
            }}
          />
        </div>

        {/* Boundary Labels & Legend */}
        <div className="flex flex-wrap items-center justify-between text-[10px] font-mono text-slate-400 pt-1">
          {/* LBA Boundaries */}
          {artifact.fragmentation_detail ? (
            <div className="flex items-center space-x-4 text-slate-300">
              <span>F1 Start: <strong className="text-blue-400">{artifact.fragmentation_detail.fragment_1[0]}</strong></span>
              <span>F1 End: <strong className="text-blue-400">{artifact.fragmentation_detail.fragment_1[0] + artifact.fragmentation_detail.fragment_1[1]}</strong></span>
              <span>F2 Start: <strong className="text-purple-400">{artifact.fragmentation_detail.fragment_2[0]}</strong></span>
              <span>F2 End: <strong className="text-purple-400">{artifact.fragmentation_detail.fragment_2[0] + artifact.fragmentation_detail.fragment_2[1]}</strong></span>
            </div>
          ) : (
            <div className="flex items-center space-x-4 text-slate-300">
              <span>Start LBA: <strong className="text-blue-400">{rangeBounds.minLba}</strong></span>
              <span>End LBA: <strong className="text-blue-400">{rangeBounds.maxLba}</strong></span>
            </div>
          )}

          {/* Map Legend */}
          <div className="flex items-center space-x-3">
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span>
              <span>Fragment 1</span>
            </span>
            {artifact.fragmentation_detail && (
              <>
                <span className="flex items-center space-x-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-600 inline-block"></span>
                  <span>Intervening Gap</span>
                </span>
                <span className="flex items-center space-x-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block"></span>
                  <span>Fragment 2</span>
                </span>
              </>
            )}
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 border border-cyan-400 bg-cyan-400/30 inline-block"></span>
              <span className="text-cyan-300">Active Window</span>
            </span>
          </div>
        </div>
      </div>

      {/* ───────────────────────────────────────────── */}
      {/* PANEL 3 — HEX VIEW                            */}
      {/* ───────────────────────────────────────────── */}
      <div className="flex-1 bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col min-h-[300px] overflow-hidden backdrop-blur-md shadow-inner relative">
        {/* Hex Area Header */}
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs">
          <div className="font-mono text-slate-300 flex items-center space-x-2">
            <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">Raw Sector Data Grid</span>
            <span className="text-[10px] text-slate-500">
              (512 B/sector × {BLOCKS_PER_PAGE} = {BLOCKS_PER_PAGE * SECTOR_SIZE} bytes per page)
            </span>
          </div>

          {/* Hover Tooltip Box Bar */}
          {hoveredCell ? (
            <div className="flex items-center space-x-3 bg-slate-950 px-3 py-1 rounded border border-cyan-700/60 text-[11px] font-mono text-cyan-300">
              <span>
                Val: <strong>0x{hoveredCell.value.toString(16).padStart(2, '0').toUpperCase()}</strong> ({hoveredCell.value}) [
                {hoveredCell.value.toString(2).padStart(8, '0')}]
              </span>
              <span>•</span>
              <span>
                LBA <strong>{hoveredCell.absLba}</strong> (Offset: +{hoveredCell.lbaOffset}B)
              </span>
              <span>•</span>
              <span
                className={`font-bold uppercase ${
                  hoveredCell.fragment === 'fragment1'
                    ? 'text-blue-400'
                    : hoveredCell.fragment === 'fragment2'
                    ? 'text-purple-400'
                    : hoveredCell.fragment === 'gap'
                    ? 'text-red-400'
                    : 'text-slate-400'
                }`}
              >
                Region: {hoveredCell.fragment}
              </span>
            </div>
          ) : (
            <span className="text-[11px] font-mono text-slate-500 italic">Hover over any byte to inspect metadata</span>
          )}
        </div>

        {/* Loading Overlay / Error / Hex Grid */}
        {isLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center space-y-2 p-8">
            <div className="w-8 h-8 border-3 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
            <p className="text-xs text-cyan-300 font-mono animate-pulse">
              Loading sectors LBA {currentLba}–{currentLba + BLOCKS_PER_PAGE - 1}…
            </p>
          </div>
        ) : error ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-2">
            <p className="text-xs text-red-400 font-mono">Error loading sector bytes: {error}</p>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto custom-scrollbar font-mono text-xs select-none">
            <div className="space-y-1">
              {/* Header Row */}
              <div className="flex items-center text-slate-500 font-bold text-[10px] pb-1 border-b border-slate-800/60">
                <div className="w-24 text-slate-600">OFFSET</div>
                <div className="flex-1 flex justify-start space-x-2">
                  <span>HEX BYTES ({bytesPerRow} B/ROW)</span>
                </div>
                <div className="w-40 text-left pl-4">ASCII</div>
              </div>

              {/* Rows */}
              {formattedRows.map((row, rowIdx) => (
                <div key={rowIdx} className="flex items-center hover:bg-slate-800/30 py-0.5 px-1 rounded transition-colors">
                  {/* Offset Column */}
                  <div className="w-24 text-cyan-500 font-bold select-all tracking-wider text-[11px]">
                    {row.offset}
                  </div>

                  {/* Hex Bytes Column */}
                  <div className="flex-1 flex items-center flex-wrap gap-1">
                    {row.hexCells.map((cell, cellIdx) => {
                      const isHovered = hoveredCell?.absoluteIndex === cell.absoluteIndex;
                      const showGapSpacer = cellIdx > 0 && cellIdx % 8 === 0;

                      return (
                        <React.Fragment key={cellIdx}>
                          {showGapSpacer && <div className="w-3"></div>}
                          <span
                            onMouseEnter={() => setHoveredCell(cell)}
                            onMouseLeave={() => setHoveredCell(null)}
                            className={`px-1 rounded border text-[11px] transition font-mono ${getCellBg(
                              cell.fragment,
                              isHovered
                            )}`}
                          >
                            {cell.value.toString(16).padStart(2, '0').toUpperCase()}
                          </span>
                        </React.Fragment>
                      );
                    })}
                  </div>

                  {/* ASCII Column */}
                  <div className="w-40 pl-4 text-slate-300 font-mono tracking-widest bg-slate-950/40 py-0.5 rounded border border-slate-800/60 truncate">
                    {row.ascii}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default HexExplorer;
