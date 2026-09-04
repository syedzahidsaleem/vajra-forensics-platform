import React, { useState, useMemo, useEffect } from 'react';
import {
  Binary,
  ArrowLeft,
  ArrowRight,
  Search,
  Layers,
  Sparkles,
  Copy,
  Check,
} from 'lucide-react';
import StorageMap from '../components/storage-map/StorageMap';
import { useApp } from '../context/AppContext';

export const HexExplorer: React.FC = () => {
  const { selectedDevice, targetHexLba, setTargetHexLba } = useApp();
  const [currentLba, setCurrentLba] = useState<number>(targetHexLba || 2048);
  const [inputLba, setInputLba] = useState<string>(String(targetHexLba || 2048));
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (targetHexLba !== currentLba) {
      setCurrentLba(targetHexLba);
      setInputLba(String(targetHexLba));
    }
  }, [targetHexLba]);

  const handleJumpLba = (e: React.FormEvent) => {
    e.preventDefault();
    const lba = parseInt(inputLba, 10);
    if (!isNaN(lba) && lba >= 0) {
      setCurrentLba(lba);
      setTargetHexLba(lba);
    }
  };

  // Generate deterministic 512-byte sector data based on LBA offset
  const sectorBytes = useMemo(() => {
    const bytes = new Uint8Array(512);

    // If LBA is 2048 (sample PDF header)
    if (currentLba === 2048) {
      const pdfHeader = '%PDF-1.7\r\n%\xE2\xE3\xCF\xD3\r\n1 0 obj\r\n<<\r\n/Type /Catalog\r\n/Pages 2 0 R\r\n>>\r\nendobj\r\n';
      for (let i = 0; i < pdfHeader.length; i++) {
        bytes[i] = pdfHeader.charCodeAt(i);
      }
      for (let i = pdfHeader.length; i < 512; i++) {
        bytes[i] = (i * 37 + currentLba) % 256;
      }
    } else if (currentLba === 65400) {
      // JPEG header
      bytes[0] = 0xff;
      bytes[1] = 0xd8;
      bytes[2] = 0xff;
      bytes[3] = 0xe0;
      bytes[4] = 0x00;
      bytes[5] = 0x10;
      bytes[6] = 0x4a; // J
      bytes[7] = 0x46; // F
      bytes[8] = 0x49; // I
      bytes[9] = 0x46; // F
      for (let i = 10; i < 512; i++) {
        bytes[i] = (i * 13 + 97) % 256;
      }
    } else {
      // Synthetic pseudo-disk sector pattern
      for (let i = 0; i < 512; i++) {
        bytes[i] = (i ^ (currentLba & 0xff)) % 256;
      }
    }
    return bytes;
  }, [currentLba]);

  // Group into 16-byte rows
  const rows = useMemo(() => {
    const r = [];
    for (let i = 0; i < sectorBytes.length; i += 16) {
      const rowBytes = sectorBytes.slice(i, i + 16);
      r.push({
        offset: i,
        bytes: rowBytes,
      });
    }
    return r;
  }, [sectorBytes]);

  const selectedByteVal = selectedByteOffset !== null ? sectorBytes[selectedByteOffset] : null;

  const handleCopyHex = () => {
    const hexStr = Array.from(sectorBytes)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    navigator.clipboard.writeText(hexStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div data-mode="forensic" style={{ background: 'var(--bg)', color: 'var(--text)' }} className="space-y-6">
      {/* Header & Title */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-lg font-sans font-medium text-[var(--text)]">
              Hex Data & Raw Sector Explorer
            </h1>
          </div>
          <p className="text-[11px] text-[var(--text)]/50 font-sans">
            Raw byte inspection, sector boundary mapping, fragment provenance overlay, and colored block storage visualization.
          </p>
        </div>

        {/* LBA Navigation Bar */}
        <form onSubmit={handleJumpLba} className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const next = Math.max(0, currentLba - 1);
              setCurrentLba(next);
              setInputLba(String(next));
              setTargetHexLba(next);
            }}
            disabled={currentLba <= 0}
            className="p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)]/30 text-[var(--text)]/80 hover:border-[var(--border)]/60 disabled:opacity-40"
            title="Previous Sector"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>

          <div className="relative flex items-center">
            <span className="absolute left-3 text-xs font-mono text-[var(--primary)] font-bold">LBA:</span>
            <input
              type="text"
              value={inputLba}
              onChange={(e) => setInputLba(e.target.value)}
              className="pl-12 pr-3 py-1.5 w-32 rounded-lg bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] font-mono text-xs font-bold focus:outline-none focus:border-[var(--primary)]"
            />
          </div>

          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono text-xs font-bold flex items-center gap-1.5 shadow-md"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Jump</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const next = currentLba + 1;
              setCurrentLba(next);
              setInputLba(String(next));
              setTargetHexLba(next);
            }}
            className="p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)]/30 text-[var(--text)]/80 hover:border-[var(--border)]/60"
            title="Next Sector"
          >
            <ArrowRight className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={handleCopyHex}
            className="p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)]/30 text-[var(--text)]/80 hover:text-[var(--text)]"
            title="Copy Raw Hex Dump"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
        </form>
      </div>

      {/* Synchronized Storage Map */}
      <StorageMap
        sourcePath={selectedDevice?.path || '\\\\.\\PhysicalDrive0'}
        mode="forensic"
        highlightArtifact={{ startLba: currentLba, blockCount: 1, name: `Sector LBA ${currentLba}` }}
        onRegionClick={(start) => {
          setCurrentLba(start);
          setInputLba(String(start));
          setTargetHexLba(start);
        }}
      />

      {/* Fragment Provenance Overlay Legend */}
      <div className="p-4 rounded-xl bg-[var(--surface)] border border-[var(--border)]/30 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex items-center gap-2 text-[var(--text)]/80">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span className="font-bold">Bifragment Reconstruction Provenance Overlay:</span>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-emerald-500/30 border border-emerald-400" />
            <span className="text-emerald-400">Fragment 1 [LBA 2048..2247]</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-amber-500/30 border border-amber-400" />
            <span className="text-amber-400">Gap Region [100 Sectors]</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-cyan-500/30 border border-cyan-400" />
            <span className="text-cyan-400">Fragment 2 [LBA 2348..2547]</span>
          </div>
        </div>
      </div>

      {/* Hex Dump & Byte Inspector Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* 16-Byte Hex Virtualized Table */}
        <div className="xl:col-span-3 rounded-xl border border-[var(--border)]/30 bg-[var(--surface)] p-4 font-mono text-xs overflow-x-auto">
          {/* Header Row */}
          <div className="grid grid-cols-24 gap-1 text-[11px] text-[var(--text)]/50 pb-2 border-b border-[var(--border)]/20 font-bold select-none">
            <div className="col-span-3 text-[var(--primary)]">Offset (h)</div>
            <div className="col-span-13 grid grid-cols-16 gap-1 text-center">
              {Array.from({ length: 16 }, (_, i) => (
                <span key={i}>{i.toString(16).toUpperCase().padStart(2, '0')}</span>
              ))}
            </div>
            <div className="col-span-8 text-center text-[var(--text)]/60">Decoded Text</div>
          </div>

          {/* Data Rows */}
          <div className="divide-y divide-[var(--border)]/10 pt-1">
            {rows.map((row) => (
              <div key={row.offset} className="grid grid-cols-24 gap-1 py-1 items-center hover:bg-[var(--primary)]/5">
                {/* Offset */}
                <div className="col-span-3 text-[var(--text)]/40 select-none">
                  {row.offset.toString(16).padStart(8, '0').toUpperCase()}
                </div>

                {/* 16 Hex Bytes */}
                <div className="col-span-13 grid grid-cols-16 gap-1 text-center">
                  {Array.from(row.bytes).map((b, idx) => {
                    const byteGlobalOffset = row.offset + idx;
                    const isSelected = selectedByteOffset === byteGlobalOffset;
                    const isNull = b === 0;
                    const isAscii = b >= 32 && b <= 126;

                    return (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => setSelectedByteOffset(byteGlobalOffset)}
                        className={`py-0.5 rounded transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-[var(--primary)] text-[var(--bg)] font-bold ring-2 ring-[var(--primary)]/50'
                            : isNull
                            ? 'text-[var(--text)]/30 hover:bg-[var(--border)]/20 hover:text-[var(--text)]/70'
                            : isAscii
                            ? 'text-cyan-500 dark:text-cyan-300 hover:bg-[var(--border)]/20'
                            : 'text-amber-500 dark:text-amber-300 hover:bg-[var(--border)]/20'
                        }`}
                      >
                        {b.toString(16).padStart(2, '0').toUpperCase()}
                      </button>
                    );
                  })}
                </div>

                {/* ASCII Column */}
                <div className="col-span-8 pl-4 text-[var(--text)]/80 tracking-wider">
                  {Array.from(row.bytes).map((b, idx) => {
                    const char = b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
                    const byteGlobalOffset = row.offset + idx;
                    const isSelected = selectedByteOffset === byteGlobalOffset;
                    return (
                      <span
                        key={idx}
                        onClick={() => setSelectedByteOffset(byteGlobalOffset)}
                        className={`cursor-pointer inline-block ${
                          isSelected ? 'bg-[var(--primary)] text-[var(--bg)] font-bold px-0.5 rounded' : 'hover:text-[var(--primary)]'
                        }`}
                      >
                        {char}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Byte Inspector Side Panel */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-[var(--surface)] border border-[var(--border)]/30 space-y-4 font-mono text-xs">
            <div className="flex items-center gap-2 text-[var(--primary)] font-bold pb-2 border-b border-[var(--border)]/20">
              <Binary className="w-4 h-4" />
              <span>Byte Inspector & Types</span>
            </div>

            {selectedByteOffset !== null && selectedByteVal !== null ? (
              <div className="space-y-2.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-[var(--text)]/60">Selected Offset:</span>
                  <span className="text-[var(--text)] font-bold">
                    0x{selectedByteOffset.toString(16).toUpperCase()} ({selectedByteOffset})
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-[var(--text)]/60">Hex Value:</span>
                  <span className="text-[var(--primary)] font-bold">
                    0x{selectedByteVal.toString(16).toUpperCase().padStart(2, '0')}
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-[var(--text)]/60">Unsigned 8-bit:</span>
                  <span className="text-[var(--text)]">{selectedByteVal}</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-[var(--text)]/60">Binary:</span>
                  <span className="text-amber-500 dark:text-amber-300 font-bold">{selectedByteVal.toString(2).padStart(8, '0')}</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-[var(--text)]/60">ASCII Character:</span>
                  <span className="text-emerald-500 dark:text-emerald-400 font-bold">
                    {selectedByteVal >= 32 && selectedByteVal <= 126
                      ? `'${String.fromCharCode(selectedByteVal)}'`
                      : 'Non-Printable'}
                  </span>
                </div>

                <div className="pt-2 border-t border-[var(--border)]/20">
                  <span className="text-[var(--text)]/60 block mb-1">Little-Endian 16-bit:</span>
                  <span className="text-[var(--text)]/90">
                    {selectedByteOffset + 1 < sectorBytes.length
                      ? sectorBytes[selectedByteOffset] | (sectorBytes[selectedByteOffset + 1] << 8)
                      : 'N/A'}
                  </span>
                </div>

                <div>
                  <span className="text-[var(--text)]/60 block mb-1">Little-Endian 32-bit:</span>
                  <span className="text-[var(--text)]/90">
                    {selectedByteOffset + 3 < sectorBytes.length
                      ? (sectorBytes[selectedByteOffset] |
                          (sectorBytes[selectedByteOffset + 1] << 8) |
                          (sectorBytes[selectedByteOffset + 2] << 16) |
                          (sectorBytes[selectedByteOffset + 3] << 24)) >>>
                        0
                      : 'N/A'}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-[var(--text)]/40 italic">Click any byte in the hex grid to inspect structure</div>
            )}
          </div>

          <div className="p-4 rounded-xl bg-[var(--surface)]/60 border border-[var(--border)]/30 text-[11px] font-sans text-[var(--text)]/60 leading-relaxed">
            <div className="flex items-center gap-1.5 font-bold text-[var(--text)]/90 font-mono mb-1">
              <Sparkles className="w-3.5 h-3.5 text-[var(--primary)]" />
              <span>Forensic Significance</span>
            </div>
            Raw disk sector viewing operates strictly under <code className="text-[var(--primary)] font-mono">ReadOnlyBlockSource</code> type invariants.
          </div>
        </div>
      </div>
    </div>
  );
};

export default HexExplorer;
