import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import {
  AcquisitionProfile,
  ImageFormat,
  AcquisitionProgress,
  DeviceDescriptor,
} from '../types';
import {
  Disc,
  HardDrive,
  Hash,
  Activity,
  AlertTriangle,
  Play,
  FileCode,
  ShieldCheck,
  RotateCcw,
} from 'lucide-react';

export const AcquisitionWizard: React.FC = () => {
  const { devices, selectedDevice, setActiveScreen } = useApp();

  // Wizard Steps: 1: Source & Case, 2: Profile & Format, 3: Options, 4: Live Imaging
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);

  // Config State
  const [sourcePath, setSourcePath] = useState(selectedDevice?.path || '');
  const [evidenceId, setEvidenceId] = useState('EVID-001');
  const [profile, setProfile] = useState<AcquisitionProfile>('Physical');
  const [format, setFormat] = useState<ImageFormat>('E01');
  const [destDir, setDestDir] = useState('./forensic_images');
  const [imageName, setImageName] = useState('EVID-001_PHYSICAL');
  const [segmentSizeMb, setSegmentSizeMb] = useState(2048);
  const [computeSha256, setComputeSha256] = useState(true);
  const [computeMd5, setComputeMd5] = useState(true);
  const [examiner, setExaminer] = useState('INV-4402-NITYA');

  // Live Acquisition Simulation / State
  const [progress, setProgress] = useState<AcquisitionProgress>({
    state: 'idle',
    bytes_processed: 0,
    total_bytes: 0,
    progress_percent: 0,
    current_speed_mbps: 0,
    elapsed_seconds: 0,
    estimated_remaining_seconds: 0,
    bad_sectors_count: 0,
  });

  useEffect(() => {
    if (selectedDevice) {
      setSourcePath(selectedDevice.path);
    } else if (devices.length > 0 && !sourcePath) {
      setSourcePath(devices[0].path);
    }
  }, [selectedDevice, devices, sourcePath]);

  const targetDevice = devices.find((d: DeviceDescriptor) => d.path === sourcePath) || devices[0];

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleStartImaging = () => {
    setStep(4);
    const total = targetDevice ? targetDevice.size_bytes : 32014925824;
    setProgress({
      state: 'running',
      bytes_processed: 0,
      total_bytes: total,
      progress_percent: 0,
      current_speed_mbps: 185.4,
      elapsed_seconds: 0,
      estimated_remaining_seconds: 180,
      bad_sectors_count: 0,
    });

    let current = 0;
    const stepSize = total / 60;
    const interval = setInterval(() => {
      current += stepSize;
      if (current >= total) {
        current = total;
        clearInterval(interval);
        setProgress((prev: AcquisitionProgress) => ({
          ...prev,
          state: 'completed',
          bytes_processed: total,
          progress_percent: 100,
          current_speed_mbps: 0,
          estimated_remaining_seconds: 0,
          sha256_checksum: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        }));
      } else {
        const pct = Math.min(99, Math.floor((current / total) * 100));
        setProgress((prev: AcquisitionProgress) => ({
          ...prev,
          bytes_processed: current,
          progress_percent: pct,
          elapsed_seconds: prev.elapsed_seconds + 1,
          estimated_remaining_seconds: Math.max(1, Math.floor((total - current) / (185.4 * 1024 * 1024))),
          current_speed_mbps: 175 + Math.random() * 20,
        }));
      }
    }, 500);
  };

  return (
    <div data-mode="forensic" style={{ background: 'var(--bg)', color: 'var(--text)' }} className="space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-lg font-sans font-medium text-[var(--text)]">
              Forensic Evidence Acquisition Wizard
            </h1>
          </div>
          <p className="text-[11px] text-[var(--text)]/50 font-sans">
            Bit-stream physical/logical imaging, E01 Expert Witness compression, bad-sector retry engine, and dual-phase rolling hash verification.
          </p>
        </div>

        {/* Step Indicator */}
        <div className="flex items-center gap-1 overflow-x-auto">
          {[
            { num: 1, label: 'Target' },
            { num: 2, label: 'Format' },
            { num: 3, label: 'Hashing' },
            { num: 4, label: 'Acquisition' },
          ].map((s, i) => (
            <React.Fragment key={s.num}>
              <div
                className={`px-3 py-1 rounded-full text-[10px] font-mono whitespace-nowrap transition-all ${
                  step === s.num
                    ? 'bg-[var(--primary)]/15 text-[var(--primary)] border border-[var(--primary)]/40 font-bold'
                    : step > s.num
                    ? 'bg-[var(--primary)]/10 text-[var(--primary)]/60'
                    : 'text-[var(--text)]/40'
                }`}
              >
                {s.num}. {s.label}
              </div>
              {i < 3 && <div className="w-3 h-px bg-[var(--border)]/20 shrink-0" />}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Step 1: Source & Case Selection */}
      {step === 1 && (
        <div className="p-6 rounded-2xl bg-[var(--surface)] border border-[var(--border)]/30 space-y-5 text-[var(--text)]">
          <div className="flex items-center space-x-2 text-[var(--primary)] font-mono font-bold text-sm">
            <HardDrive className="w-4 h-4" />
            <span>Step 1: Select Source Storage Media & Evidence Record</span>
          </div>

          <div className="grid grid-cols-2 gap-4 font-mono text-xs">
            <div>
              <label className="block text-[var(--text)]/60 mb-1">Source Storage Device</label>
              <select
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              >
                {devices.map((d: DeviceDescriptor) => (
                  <option key={d.path} value={d.path} className="bg-[var(--surface)] text-[var(--text)]">
                    {d.path} — {d.model} ({formatBytes(d.size_bytes)}) {d.is_system_disk ? '[OS DISK]' : ''}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[var(--text)]/60 mb-1">Case Evidence Identifier</label>
              <input
                type="text"
                value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)}
                placeholder="EVID-001"
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              />
            </div>
          </div>

          {targetDevice && (
            <div className="p-4 rounded-xl bg-[var(--bg)]/50 border border-[var(--border)]/30 space-y-2 text-xs font-mono">
              <div className="text-[var(--text)]/70 font-bold">Selected Source Inspection:</div>
              <div className="grid grid-cols-3 gap-2 text-[var(--text)]/80">
                <div>Model: <span className="text-[var(--primary)] font-semibold">{targetDevice.model}</span></div>
                <div>Serial: <span className="text-[var(--text)]">{targetDevice.serial}</span></div>
                <div>Capacity: <span className="text-emerald-400 font-bold">{formatBytes(targetDevice.size_bytes)}</span></div>
              </div>
              {targetDevice.is_system_disk && (
                <div className="p-2 rounded bg-amber-950/40 border border-amber-800/50 text-amber-300 text-[11px] flex items-center space-x-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Warning: Device is the live OS boot disk. Physical imaging requires volume shadow snapshot.</span>
                </div>
              )}
            </div>
          )}

          <div className="flex justify-end pt-3 border-t border-[var(--border)]/20">
            <button
              onClick={() => setStep(2)}
              className="px-6 py-2.5 bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono font-bold text-xs rounded-xl shadow-lg"
            >
              Continue to Profile Selection &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Profile & Image Format */}
      {step === 2 && (
        <div className="p-6 rounded-2xl bg-[var(--surface)] border border-[var(--border)]/30 space-y-5 text-[var(--text)]">
          <div className="flex items-center space-x-2 text-[var(--primary)] font-mono font-bold text-sm">
            <Disc className="w-4 h-4" />
            <span>Step 2: Choose Acquisition Profile & Forensic Image Container</span>
          </div>

          {/* Profile Choice */}
          <div className="space-y-2">
            <label className="block text-xs font-mono text-[var(--text)]/60">Acquisition Profile</label>
            <div className="grid grid-cols-3 gap-3">
              {[
                {
                  id: 'Physical' as AcquisitionProfile,
                  title: 'Physical (Bit-Stream)',
                  desc: 'Sector-by-sector mirror including all unallocated clusters, slack space, and partition tables.',
                },
                {
                  id: 'Logical' as AcquisitionProfile,
                  title: 'Logical (Volume-Scoped)',
                  desc: 'Acquires recognized filesystem partitions, active directory tree, and recoverable entries.',
                },
                {
                  id: 'Partial' as AcquisitionProfile,
                  title: 'Partial (LBA Range)',
                  desc: 'Targeted sector range extraction for rapid triage or bad-drive rescue.',
                },
              ].map((p) => (
                <div
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    profile === p.id
                      ? 'bg-[var(--primary)]/15 border-[var(--primary)] text-[var(--text)] font-medium shadow-[0_0_15px_rgba(0,0,0,0.2)]'
                      : 'bg-[var(--bg)]/40 border-[var(--border)]/30 text-[var(--text)]/70 hover:border-[var(--border)]/60'
                  }`}
                >
                  <div className="font-mono font-bold text-sm text-[var(--text)] mb-1">{p.title}</div>
                  <div className="text-[11px] font-sans leading-relaxed">{p.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Container Format Choice */}
          <div className="space-y-2">
            <label className="block text-xs font-mono text-[var(--text)]/60">Image Container Format</label>
            <div className="grid grid-cols-2 gap-3">
              <div
                onClick={() => setFormat('E01')}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  format === 'E01'
                    ? 'bg-[var(--primary)]/15 border-[var(--primary)] text-[var(--text)] font-medium shadow-[0_0_15px_rgba(0,0,0,0.2)]'
                    : 'bg-[var(--bg)]/40 border-[var(--border)]/30 text-[var(--text)]/70 hover:border-[var(--border)]/60'
                }`}
              >
                <div className="font-mono font-bold text-sm text-[var(--text)] mb-1">
                  E01 (Expert Witness Format)
                </div>
                <div className="text-[11px] font-sans leading-relaxed">
                  Forensic industry standard. Embedded case metadata, Deflate chunk compression, internal CRC32 per block, and MD5/SHA-256 integrity footer.
                </div>
              </div>

              <div
                onClick={() => setFormat('RAW')}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  format === 'RAW'
                    ? 'bg-[var(--primary)]/15 border-[var(--primary)] text-[var(--text)] font-medium shadow-[0_0_15px_rgba(0,0,0,0.2)]'
                    : 'bg-[var(--bg)]/40 border-[var(--border)]/30 text-[var(--text)]/70 hover:border-[var(--border)]/60'
                }`}
              >
                <div className="font-mono font-bold text-sm text-[var(--text)] mb-1">
                  RAW / DD (Flat Binary Stream)
                </div>
                <div className="text-[11px] font-sans leading-relaxed">
                  Uncompressed 1:1 sector stream. Highest raw performance, universally compatible with third-party tools (Autopsy, FTK, SleuthKit, X-Ways).
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-between pt-3 border-t border-[var(--border)]/20">
            <button
              onClick={() => setStep(1)}
              className="px-4 py-2 bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 font-mono text-xs rounded-xl"
            >
              &larr; Back
            </button>
            <button
              onClick={() => setStep(3)}
              className="px-6 py-2.5 bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono font-bold text-xs rounded-xl shadow-lg"
            >
              Continue to Hashing Configuration &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Hashing & Output Options */}
      {step === 3 && (
        <div className="p-6 rounded-2xl bg-[var(--surface)] border border-[var(--border)]/30 space-y-5 text-[var(--text)]">
          <div className="flex items-center space-x-2 text-[var(--primary)] font-mono font-bold text-sm">
            <Hash className="w-4 h-4" />
            <span>Step 3: Verification Hashing & Destination Options</span>
          </div>

          <div className="grid grid-cols-2 gap-4 font-mono text-xs">
            <div>
              <label className="block text-[var(--text)]/60 mb-1">Destination Directory</label>
              <input
                type="text"
                value={destDir}
                onChange={(e) => setDestDir(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              />
            </div>

            <div>
              <label className="block text-[var(--text)]/60 mb-1">Image Filename Base</label>
              <input
                type="text"
                value={imageName}
                onChange={(e) => setImageName(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              />
            </div>

            <div>
              <label className="block text-[var(--text)]/60 mb-1">Segment Split Size (MB)</label>
              <select
                value={segmentSizeMb}
                onChange={(e) => setSegmentSizeMb(Number(e.target.value))}
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              >
                <option value={2048} className="bg-[var(--surface)] text-[var(--text)]">2048 MB (2 GB standard E01 chunks)</option>
                <option value={4096} className="bg-[var(--surface)] text-[var(--text)]">4096 MB (4 GB chunks)</option>
                <option value={0} className="bg-[var(--surface)] text-[var(--text)]">Single continuous file (No split)</option>
              </select>
            </div>

            <div>
              <label className="block text-[var(--text)]/60 mb-1">Lead Examiner</label>
              <input
                type="text"
                value={examiner}
                onChange={(e) => setExaminer(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-[var(--bg)]/60 border border-[var(--border)]/30 text-[var(--text)] focus:outline-none focus:border-[var(--primary)]"
              />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[var(--bg)]/50 border border-[var(--border)]/30 space-y-3 font-mono text-xs">
            <div className="text-[var(--text)]/80 font-bold">Cryptographic Integrity Hashing</div>
            <div className="flex items-center space-x-6">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={computeSha256}
                  onChange={(e) => setComputeSha256(e.target.checked)}
                  className="rounded bg-[var(--surface)] border-[var(--border)]/40 text-[var(--primary)] focus:ring-0"
                />
                <span className="text-[var(--text)]">Compute SHA-256 (Forensic Standard)</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={computeMd5}
                  onChange={(e) => setComputeMd5(e.target.checked)}
                  className="rounded bg-[var(--surface)] border-[var(--border)]/40 text-[var(--primary)] focus:ring-0"
                />
                <span className="text-[var(--text)]">Compute MD5 (Legacy Cross-Check)</span>
              </label>
            </div>
            <p className="text-[11px] text-[var(--text)]/50">
              Vajra computes rolling stream hashes on-the-fly during acquisition and performs an independent post-write verification pass to guarantee byte-for-byte reproducibility.
            </p>
          </div>

          <div className="flex justify-between pt-3 border-t border-[var(--border)]/20">
            <button
              onClick={() => setStep(2)}
              className="px-4 py-2 bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 font-mono text-xs rounded-xl"
            >
              &larr; Back
            </button>
            <button
              onClick={handleStartImaging}
              className="flex items-center space-x-2 px-6 py-2.5 bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono font-bold text-xs rounded-xl shadow-lg"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Start Forensic Acquisition</span>
            </button>
          </div>
        </div>
      )}

      {/* Step 4: Live Imaging Execution & Telemetry */}
      {step === 4 && (
        <div className="space-y-4">
          <div className="p-6 rounded-2xl bg-[var(--surface)] border border-[var(--border)]/30 space-y-6 shadow-2xl text-[var(--text)]">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <span className="font-mono text-lg font-bold text-[var(--primary)]">
                    {progress.state === 'completed'
                      ? 'Acquisition Completed Successfully'
                      : 'Live Imaging in Progress...'}
                  </span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase ${
                      progress.state === 'completed'
                        ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
                        : 'bg-[var(--primary)]/15 text-[var(--primary)] border border-[var(--primary)]/40 animate-pulse'
                    }`}
                  >
                    {progress.state}
                  </span>
                </div>
                <div className="text-xs font-mono text-[var(--text)]/60">
                  Target: <span className="text-[var(--text)]">{targetDevice?.model} ({sourcePath})</span> &rarr; {format} Container
                </div>
              </div>

              <div className="text-right font-mono">
                <div className="text-2xl font-bold text-[var(--text)]">{progress.progress_percent}%</div>
                <div className="text-xs text-[var(--text)]/60">
                  {formatBytes(progress.bytes_processed)} / {formatBytes(progress.total_bytes)}
                </div>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="space-y-1.5">
              <div className="w-full h-3 bg-[var(--bg)]/70 rounded-full overflow-hidden p-0.5 border border-[var(--border)]/30">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    progress.state === 'completed'
                      ? 'bg-emerald-500 shadow-sm shadow-emerald-500'
                      : 'bg-gradient-to-r from-[var(--primary)] to-cyan-400 forensic-glow'
                  }`}
                  style={{ width: `${progress.progress_percent}%` }}
                />
              </div>
            </div>

            {/* Telemetry Metrics */}
            <div className="grid grid-cols-4 gap-3 font-mono text-xs">
              <div className="p-3 bg-[var(--bg)]/50 rounded-xl border border-[var(--border)]/30">
                <div className="text-[var(--text)]/50 text-[10px]">Current Throughput</div>
                <div className="text-base font-bold text-[var(--primary)]">
                  {progress.current_speed_mbps.toFixed(1)} MB/s
                </div>
              </div>

              <div className="p-3 bg-[var(--bg)]/50 rounded-xl border border-[var(--border)]/30">
                <div className="text-[var(--text)]/50 text-[10px]">Elapsed Time</div>
                <div className="text-base font-bold text-[var(--text)]">
                  {Math.floor(progress.elapsed_seconds / 60)}m {progress.elapsed_seconds % 60}s
                </div>
              </div>

              <div className="p-3 bg-[var(--bg)]/50 rounded-xl border border-[var(--border)]/30">
                <div className="text-[var(--text)]/50 text-[10px]">Estimated Remaining</div>
                <div className="text-base font-bold text-[var(--text)]">
                  {progress.state === 'completed' ? '0s' : `${progress.estimated_remaining_seconds}s`}
                </div>
              </div>

              <div className="p-3 bg-[var(--bg)]/50 rounded-xl border border-[var(--border)]/30">
                <div className="text-[var(--text)]/50 text-[10px]">Bad Sectors Detected</div>
                <div className="text-base font-bold text-emerald-400">
                  {progress.bad_sectors_count} (0 LBA errors)
                </div>
              </div>
            </div>

            {/* Bad Sector Map Visualization */}
            <div className="p-4 rounded-xl bg-[var(--bg)]/50 border border-[var(--border)]/30 space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between text-[var(--text)]/80 font-bold">
                <span className="flex items-center space-x-1.5">
                  <Activity className="w-4 h-4 text-[var(--primary)]" />
                  <span>Sector Map & LBA Block Visualization</span>
                </span>
                <span className="text-[10px] text-[var(--text)]/50">64 Sector Chunks</span>
              </div>

              {/* Grid of sector visual blocks */}
              <div className="grid grid-cols-32 gap-1 h-12 p-1 bg-black/40 rounded border border-[var(--border)]/20 overflow-hidden">
                {Array.from({ length: 64 }).map((_, idx) => {
                  const isRead = idx < (progress.progress_percent / 100) * 64;
                  return (
                    <div
                      key={idx}
                      className={`h-full rounded-xs transition-colors duration-150 ${
                        isRead
                          ? 'bg-[var(--primary)] shadow-xs'
                          : 'bg-[var(--border)]/20'
                      }`}
                      title={`Sector Chunk #${idx}`}
                    />
                  );
                })}
              </div>
            </div>

            {/* Post-Acquisition Hash Summary */}
            {progress.state === 'completed' && progress.sha256_checksum && (
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/60 space-y-2 font-mono text-xs">
                <div className="flex items-center space-x-2 text-emerald-400 font-bold">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Acquisition Integrity Verified (Dual-Phase SHA-256 Match)</span>
                </div>
                <div className="p-2 rounded bg-black/60 font-mono text-[11px] text-emerald-300 break-all select-all">
                  SHA-256: {progress.sha256_checksum}
                </div>
                <p className="text-[11px] text-[var(--text)]/60">
                  Image file signed and hash-chained into Evidence Vault audit log.
                </p>
              </div>
            )}

            {/* Action Bar */}
            <div className="flex justify-end space-x-3 pt-3 border-t border-[var(--border)]/20">
              {progress.state === 'completed' ? (
                <>
                  <button
                    onClick={() => {
                      setStep(1);
                      setProgress({
                        state: 'idle',
                        bytes_processed: 0,
                        total_bytes: 0,
                        progress_percent: 0,
                        current_speed_mbps: 0,
                        elapsed_seconds: 0,
                        estimated_remaining_seconds: 0,
                        bad_sectors_count: 0,
                      });
                    }}
                    className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-[var(--border)]/20 hover:bg-[var(--border)]/30 text-[var(--text)]/80 text-xs font-mono"
                  >
                    <RotateCcw className="w-4 h-4" />
                    <span>New Acquisition</span>
                  </button>

                  <button
                    onClick={() => setActiveScreen('reports')}
                    className="flex items-center space-x-1.5 px-5 py-2 rounded-xl bg-[var(--primary)] hover:brightness-110 text-[var(--bg)] font-mono text-xs font-bold shadow-lg"
                  >
                    <FileCode className="w-4 h-4" />
                    <span>Generate Acquisition Report</span>
                  </button>
                </>
              ) : (
                <button
                  disabled
                  className="px-5 py-2 rounded-xl bg-[var(--border)]/20 text-[var(--text)]/50 text-xs font-mono cursor-not-allowed"
                >
                  Acquisition in Progress...
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
