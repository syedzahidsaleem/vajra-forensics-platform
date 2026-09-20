import React, { useState, useEffect } from 'react';
import StorageMap from './components/storage-map/StorageMap';
import RecoveryBrowser from './components/recovery-browser/RecoveryBrowser';
import HexExplorer from './components/hex-explorer/HexExplorer';
import { RecoveredArtifact } from './types/vajra';

export default function App() {
  const [activeTab, setActiveTab] = useState<'storage' | 'recovery' | 'hex'>('storage');
  const [mode, setMode] = useState<'forensic' | 'sanitization'>('forensic');
  const [sourcePath, setSourcePath] = useState<string>('/dev/nvme0n1');

  // Sanitization live stream simulation
  const [sanitizedRanges, setSanitizedRanges] = useState<[number, number][]>([]);
  const [isSanitizing, setIsSanitizing] = useState<boolean>(false);

  // Highlighted artifact simulation
  const [highlightArtifact, setHighlightArtifact] = useState<RecoveredArtifact | null>(null);

  // Selected range for Hex Explorer
  const [selectedHexLba, setSelectedHexLba] = useState<{ startLba: number; count: number } | null>(null);

  // Simulate streaming sanitization ranges
  useEffect(() => {
    let timer: any = null;
    if (mode === 'sanitization' && isSanitizing) {
      setSanitizedRanges([]);
      let step = 0;
      const totalSteps = 10;
      const stepBlockCount = Math.floor(1048570 / totalSteps);

      timer = setInterval(() => {
        step++;
        const currentCount = step * stepBlockCount;
        setSanitizedRanges([
          [0, currentCount],
          [209715, Math.floor(currentCount * 0.3)],
          [629145, Math.floor(currentCount * 0.4)],
        ]);

        if (step >= totalSteps) {
          setSanitizedRanges([
            [0, 104857],
            [209715, 314572],
            [629145, 419430],
            [1258291, 524288],
          ]);
          setIsSanitizing(false);
          clearInterval(timer);
        }
      }, 600);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [mode, isSanitizing]);

  const handleArtifactHighlightToggle = () => {
    if (highlightArtifact) {
      setHighlightArtifact(null);
    } else {
      setHighlightArtifact({
        id: 102,
        recovery_method: 'Tier3Fragmented',
        source_locations: [
          [700000, 4096],
          [1350000, 12288],
        ],
        original_path: '/Photos/Evidence.jpg',
        filename_guess: 'Evidence_Fragmented.jpg',
        file_type: 'JPEG',
        confidence_score: 0.82,
        confidence_breakdown: {
          header_footer_integrity: 0.95,
          structural_validity: 0.8,
          metadata_cross_reference: 0.7,
          entropy_consistency: 0.85,
          entropy_explainability: 'JPEG stream entropy matched',
          fragmentation_confidence: 0.75,
          overwrite_probability: 0.05,
        },
        fragmentation_detail: {
          gap_size_sectors: 645904,
          fragment_1: [700000, 4096],
          fragment_2: [1350000, 12288],
        },
        recovered_bytes: 8388608,
        expected_total_bytes: 8388608,
        content_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        recovery_limitations: 'Fragmented file',
      });
    }
  };

  const handleRegionClick = (startLba: number, blockCount: number) => {
    setSelectedHexLba({ startLba, count: blockCount });
  };

  return (
    <div className="min-h-screen bg-[#00120B] text-[#D8E4FF] p-6 flex flex-col gap-6">
      {/* Top Application Header */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#35605A]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#59EE99] text-[#00120B] font-black text-xl flex items-center justify-center shadow-[0_0_15px_rgba(89,238,153,0.4)]">
            V
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              Vajra Forensics Platform
              <span className="text-xs px-2 py-0.5 rounded bg-[#35605A] text-[#59EE99] font-mono">
                v2.4-PROD
              </span>
            </h1>
            <p className="text-xs text-[#D8E4FF]/70">
              Hardware-Accelerated Digital Forensics & Multi-Pass Sanitization Engine
            </p>
          </div>
        </div>

        {/* Global Controls & Mode Switcher */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center bg-[#00120B] border border-[#35605A] rounded-lg p-1">
            <button
              onClick={() => {
                setMode('forensic');
                setIsSanitizing(false);
              }}
              className={`px-3 py-1.5 rounded text-xs font-bold transition-all cursor-pointer ${
                mode === 'forensic'
                  ? 'bg-[#59EE99] text-[#00120B] shadow-[0_0_10px_rgba(89,238,153,0.3)]'
                  : 'text-[#D8E4FF]/70 hover:text-white'
              }`}
            >
              FORENSIC
            </button>
            <button
              onClick={() => setMode('sanitization')}
              className={`px-3 py-1.5 rounded text-xs font-bold transition-all cursor-pointer ${
                mode === 'sanitization'
                  ? 'bg-[#EF4444] text-white shadow-[0_0_10px_rgba(239,68,68,0.4)]'
                  : 'text-[#D8E4FF]/70 hover:text-white'
              }`}
            >
              SANITIZATION
            </button>
          </div>

          <select
            value={sourcePath}
            onChange={(e) => setSourcePath(e.target.value)}
            className="bg-[#35605A]/40 border border-[#35605A] text-xs text-[#D8E4FF] font-mono px-3 py-1.5 rounded-lg focus:outline-none focus:border-[#59EE99]"
          >
            <option value="/dev/nvme0n1">Drive: /dev/nvme0n1 (1.0 TB NVMe SSD)</option>
            <option value="/dev/sdb">Drive: /dev/sdb (500 GB SATA HDD)</option>
            <option value="/evidence/case_8892.raw">Image: /evidence/case_8892.raw</option>
          </select>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-[#35605A]/50 pb-2">
        <button
          onClick={() => setActiveTab('storage')}
          className={`px-4 py-2 rounded-lg font-medium text-xs transition-all cursor-pointer ${
            activeTab === 'storage'
              ? 'bg-[#35605A] text-[#59EE99] border border-[#59EE99]/40 font-semibold shadow'
              : 'text-[#D8E4FF]/70 hover:bg-[#35605A]/30 hover:text-white'
          }`}
        >
          Storage Block Map (Component 2c)
        </button>
        <button
          onClick={() => setActiveTab('recovery')}
          className={`px-4 py-2 rounded-lg font-medium text-xs transition-all cursor-pointer ${
            activeTab === 'recovery'
              ? 'bg-[#35605A] text-[#59EE99] border border-[#59EE99]/40 font-semibold shadow'
              : 'text-[#D8E4FF]/70 hover:bg-[#35605A]/30 hover:text-white'
          }`}
        >
          Recovery Browser
        </button>
        <button
          onClick={() => setActiveTab('hex')}
          className={`px-4 py-2 rounded-lg font-medium text-xs transition-all cursor-pointer ${
            activeTab === 'hex'
              ? 'bg-[#35605A] text-[#59EE99] border border-[#59EE99]/40 font-semibold shadow'
              : 'text-[#D8E4FF]/70 hover:bg-[#35605A]/30 hover:text-white'
          }`}
        >
          Hex Explorer
        </button>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col gap-6">
        {activeTab === 'storage' && (
          <div className="space-y-6">
            {/* Interactive Control Panel for Storage Map */}
            <div className="bg-[#35605A]/20 border border-[#35605A]/60 p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
              <div className="space-y-1">
                <h3 className="font-bold text-sm text-[#59EE99]">Storage Map Demonstration Controls</h3>
                <p className="text-xs text-[#D8E4FF]/70">
                  Simulate streaming sanitization passes or highlight recovered file artifacts across LBA space.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                {mode === 'sanitization' && (
                  <button
                    onClick={() => setIsSanitizing(true)}
                    disabled={isSanitizing}
                    className="px-3.5 py-1.5 bg-[#59EE99] hover:bg-[#59EE99]/90 disabled:opacity-50 text-[#00120B] font-bold text-xs rounded-lg transition-all cursor-pointer shadow-[0_0_10px_rgba(89,238,153,0.3)]"
                  >
                    {isSanitizing ? 'Wiping Sectors...' : 'Stream Sanitization Pass'}
                  </button>
                )}

                <button
                  onClick={handleArtifactHighlightToggle}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all border cursor-pointer ${
                    highlightArtifact
                      ? 'bg-[#AA77A9] text-white border-[#AA77A9]'
                      : 'bg-[#35605A] text-[#D8E4FF] border-[#35605A] hover:border-[#59EE99]'
                  }`}
                >
                  {highlightArtifact ? 'Clear Artifact Highlight' : 'Highlight Artifact LBAs'}
                </button>
              </div>
            </div>

            {/* StorageMap Component */}
            <StorageMap
              sourcePath={sourcePath}
              mode={mode}
              sanitizedRanges={sanitizedRanges}
              highlightArtifact={highlightArtifact}
              onRegionClick={handleRegionClick}
            />

            {selectedHexLba && (
              <div className="p-4 bg-[#35605A]/30 border border-[#59EE99]/40 rounded-xl text-xs flex items-center justify-between">
                <div>
                  <span className="font-bold text-[#59EE99]">Region Selected: </span>
                  <span className="font-mono">
                    LBA {selectedHexLba.startLba.toLocaleString()} →{' '}
                    {(selectedHexLba.startLba + selectedHexLba.count - 1).toLocaleString()} ({selectedHexLba.count.toLocaleString()} sectors)
                  </span>
                </div>
                <button
                  onClick={() => setActiveTab('hex')}
                  className="px-3 py-1 bg-[#59EE99] text-[#00120B] font-bold rounded hover:opacity-90 transition cursor-pointer"
                >
                  Open in Hex Explorer →
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'recovery' && (
          <RecoveryBrowser sourcePath={sourcePath} />
        )}

        {activeTab === 'hex' && (
          <HexExplorer sourcePath={sourcePath} initialLba={selectedHexLba?.startLba || 0} />
        )}
      </main>

      <footer className="text-center text-xs text-[#D8E4FF]/40 pt-4 border-t border-[#35605A]/30 font-mono">
        Vajra Digital Forensics Platform — Component 2c Storage Visualization Engine
      </footer>
    </div>
  );
}
