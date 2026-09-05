import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { tauriApi } from '../api/tauri';
import { DeviceDescriptor, DeviceFingerprint, SmartHealthSnapshot } from '../types';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Disc,
  Flame,
  Plus,
  RefreshCw,
  X,
  AlertOctagon,
  CheckCircle,
  Thermometer,
  Cpu,
} from 'lucide-react';
import { GlowButton, FileTypeBadge, useToast } from '../components/ui/vajra-components';
import { formatDevicePath } from '../lib/utils';

export const DeviceSelection: React.FC = () => {
  const { devices, refreshDevices, mode, activeCase, setSelectedDevice, setActiveScreen } = useApp();
  const { toast } = useToast();
  const isForensic = mode === 'forensic';

  // Selected device for modal inspection
  const [inspectingDevice, setInspectingDevice] = useState<DeviceDescriptor | null>(null);
  const [fingerprint, setFingerprint] = useState<DeviceFingerprint | null>(null);
  const [health, setHealth] = useState<SmartHealthSnapshot | null>(null);
  const [loadingModal, setLoadingModal] = useState(false);

  // Evidence Registration State
  const [registeringDevice, setRegisteringDevice] = useState<DeviceDescriptor | null>(null);
  const [evidenceDesc, setEvidenceDesc] = useState('');
  const [registeringSuccess, setRegisteringSuccess] = useState(false);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleInspectDevice = async (device: DeviceDescriptor) => {
    setInspectingDevice(device);
    setLoadingModal(true);
    try {
      const [fp, hl] = await Promise.all([
        tauriApi.getDeviceFingerprint(device.path),
        tauriApi.getDeviceHealth(device.path),
      ]);
      setFingerprint(fp);
      setHealth(hl);
    } catch (err) {
      console.error('Error fetching device diagnostics:', err);
    } finally {
      setLoadingModal(false);
    }
  };

  const handleRegisterEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registeringDevice || !activeCase) return;
    try {
      await tauriApi.addEvidence(activeCase.case_id, registeringDevice.path, evidenceDesc || registeringDevice.model);
      setRegisteringSuccess(true);
      toast('Device registered in case vault', 'success');
      setTimeout(() => {
        setRegisteringDevice(null);
        setRegisteringSuccess(false);
        setEvidenceDesc('');
        setActiveScreen('dashboard');
      }, 1200);
    } catch (err) {
      console.error('Error registering evidence:', err);
    }
  };

  const handleProceedToAcquisition = (device: DeviceDescriptor) => {
    setSelectedDevice(device);
    setActiveScreen('acquisition');
  };

  const handleProceedToSanitization = (device: DeviceDescriptor) => {
    setSelectedDevice(device);
    setActiveScreen('sanitization');
  };

  return (
    <div data-mode={isForensic ? "forensic" : "sanitize"} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-lg font-sans font-medium ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-text-primary)]'}`}>
            {isForensic ? 'Storage Device Enumeration' : 'Sanitization Target Selection'}
          </h1>
        </div>

        <GlowButton
          variant="ghost"
          size="sm"
          icon={<RefreshCw className="w-3.5 h-3.5" />}
          onClick={() => {
            refreshDevices();
            toast('Devices re-scanned', 'info');
          }}
        >
          Re-scan
        </GlowButton>
      </div>

      {/* Device List — Horizontal Bars */}
      <div className="flex flex-col gap-4 w-full">
        {devices.map((device: DeviceDescriptor) => {
          const isSystem = device.is_system_disk;
          const isWriteBlocked = device.is_write_blocked;
          const devInfo = formatDevicePath(device.path);

          return (
            <div
              key={device.path}
              style={{ border: '1px solid var(--border)', borderRadius: '16px' }}
              className="w-full p-5 sm:p-6 bg-[var(--surface)] text-[var(--text)] rounded-2xl shadow-sm transition-all duration-200 hover:border-[var(--primary)]/40 flex flex-col xl:flex-row xl:items-center justify-between gap-5"
            >
              {/* Left: Drive Info + Capacity */}
              <div className="flex items-center gap-5 sm:gap-6 shrink-0 min-w-0">
                {/* Identity & Hardware Specs */}
                <div className="space-y-1.5 min-w-[240px] sm:min-w-[280px]">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className={`font-mono text-sm font-bold tracking-tight ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-accent)]'}`}>
                      {devInfo.primary}
                    </span>
                    <span className="font-mono text-xs text-[var(--text)]/50">
                      {devInfo.raw}
                    </span>
                    <FileTypeBadge type={device.media_type} />
                    {device.bus_type && (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${isForensic ? 'bg-[rgba(13,184,211,0.12)] text-[var(--forensic-text-secondary)] border border-[var(--forensic-border)]/40' : 'bg-[rgba(255,59,59,0.12)] text-[var(--sanitize-text-secondary)] border border-[var(--sanitize-border)]/40'}`}>
                        {device.bus_type}
                      </span>
                    )}
                  </div>
                  <div className="flex items-baseline gap-2.5 flex-wrap">
                    <h3 className={`font-medium text-sm font-sans ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-text-primary)]'}`}>
                      {device.model}
                    </h3>
                    <span className={`text-xs font-mono ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[var(--sanitize-text-secondary)]'}`}>
                      S/N: <span className={isForensic ? 'text-[var(--forensic-text-mono)] font-semibold' : 'text-[var(--sanitize-text-mono)] font-semibold'}>{device.serial}</span>
                    </span>
                  </div>
                </div>

                {/* Capacity & Sector Geometry Stat Block */}
                <div className="pl-5 border-l border-[var(--border)]/30 shrink-0 font-mono">
                  <div className={`text-base sm:text-lg font-bold ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-text-primary)]'}`}>
                    {formatBytes(device.size_bytes)}
                  </div>
                  <div className={`text-[11px] ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[var(--sanitize-text-secondary)]'}`}>
                    Sector: {device.block_size} B
                  </div>
                </div>
              </div>

              {/* Right: Badges & Buttons */}
              <div className="flex items-center justify-between xl:justify-end gap-4 sm:gap-6 flex-wrap xl:flex-nowrap pt-3 xl:pt-0 border-t border-[var(--border)]/20 xl:border-t-0">
                {/* Safety & Access Badges */}
                <div className="flex items-center gap-2 text-xs font-mono shrink-0">
                  {isSystem ? (
                    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[rgba(239,68,68,0.1)] border border-[#EF4444]/30 text-[#EF4444] whitespace-nowrap shadow-sm">
                      <AlertOctagon className="w-3.5 h-3.5 flex-shrink-0" />
                      <span className="font-semibold text-[11px]">OS BOOT DISK (LOCKED §24)</span>
                    </div>
                  ) : (
                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border whitespace-nowrap shadow-sm ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(255,59,59,0.08)] border-[var(--sanitize-border)] text-[var(--sanitize-accent)]'}`}>
                      <CheckCircle className="w-3.5 h-3.5 flex-shrink-0" />
                      <span className="text-[11px]">Secondary Target Disk</span>
                    </div>
                  )}

                  {isWriteBlocked ? (
                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border whitespace-nowrap shadow-sm ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(255,59,59,0.08)] border-[var(--sanitize-border)] text-[var(--sanitize-accent)]'}`}>
                      <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />
                      <span className="text-[11px]">Write-Blocker Active</span>
                    </div>
                  ) : (
                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border whitespace-nowrap shadow-sm ${isForensic ? 'bg-[rgba(15,36,48,0.6)] border-[var(--forensic-border)] text-[var(--forensic-text-secondary)]' : 'bg-[rgba(30,4,6,0.6)] border-[var(--sanitize-border)] text-[var(--sanitize-text-secondary)]'}`}>
                      <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0 text-amber-400" />
                      <span className="text-[11px]">Direct Device Access</span>
                    </div>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2.5 shrink-0">
                  <GlowButton
                    variant="ghost"
                    size="sm"
                    icon={<Activity className="w-3.5 h-3.5" />}
                    onClick={() => handleInspectDevice(device)}
                  >
                    Inspect & Health
                  </GlowButton>

                  {isForensic ? (
                    <>
                      {activeCase && (
                        <GlowButton
                          variant="ghost"
                          size="sm"
                          icon={<Plus className="w-3.5 h-3.5" />}
                          onClick={() => setRegisteringDevice(device)}
                        >
                          Vault Evidence
                        </GlowButton>
                      )}
                      <GlowButton
                        variant="primary"
                        size="sm"
                        icon={<Disc className="w-3.5 h-3.5" />}
                        onClick={() => handleProceedToAcquisition(device)}
                      >
                        Acquire Image
                      </GlowButton>
                    </>
                  ) : (
                    <GlowButton
                      disabled={isSystem}
                      variant="danger"
                      size="sm"
                      icon={<Flame className="w-3.5 h-3.5" />}
                      onClick={() => handleProceedToSanitization(device)}
                    >
                      Sanitize Device
                    </GlowButton>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Inspect & Health Modal */}
      {inspectingDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-xl bg-[var(--surface)] border border-[var(--border)]/30 rounded-xl p-5 shadow-2xl space-y-4 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[var(--primary-text)]" />
                <span className="font-bold text-[var(--text)]">
                  Diagnostics: {inspectingDevice.model}
                </span>
              </div>
              <button
                onClick={() => setInspectingDevice(null)}
                className="text-[var(--text)]/50 hover:text-[var(--text)]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {loadingModal ? (
              <div className="py-8 text-center text-[var(--text)]/50">Reading drive SMART & fingerprint...</div>
            ) : (
              <div className="space-y-3">
                {/* Fingerprint Card */}
                {fingerprint && (
                  <div className="p-3 bg-[var(--bg)]/50 rounded-lg space-y-1">
                    <p className="label-muted">Hardware Identity Fingerprint</p>
                    <div className="text-[10px] text-[var(--text)]/70 truncate">
                      SHA-256 Digest: <span className="text-[var(--primary-text)] font-semibold">{fingerprint.sha256_hash}</span>
                    </div>
                  </div>
                )}

                {/* Health Snapshot */}
                {health && (
                  <div className="p-3 bg-[var(--bg)]/50 rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="label-muted">SMART / NVMe Health Telemetry</p>
                      <span className="px-1.5 py-0.5 rounded bg-[var(--primary-text)]/10 text-[var(--primary-text)] text-[9px] font-bold">
                        {health.overall_health}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-[10px] text-[var(--text)]/70">
                      <div className="flex items-center gap-1">
                        <Thermometer className="w-3 h-3 text-[var(--primary-text)]" />
                        <span>Temp: {health.temperature_celsius}°C</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Cpu className="w-3 h-3 text-[var(--primary-text)]" />
                        <span>Power Hours: {health.power_on_hours}h</span>
                      </div>
                      <div>
                        <span>Reallocated: {health.reallocated_sectors}</span>
                      </div>
                    </div>

                    <p className="text-[10px] text-[var(--text)]/60 font-sans leading-relaxed pt-1 border-t border-[var(--border)]/20">
                      {health.recommendation}
                    </p>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectingDevice(null)}
                className="px-3 py-1.5 bg-[var(--border)]/20 text-[var(--text)]/80 hover:text-[var(--text)] rounded text-[10px]"
              >
                Close Diagnostics
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Vault Evidence Modal */}
      {registeringDevice && activeCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-[var(--surface)] border border-[var(--border)]/30 rounded-xl p-5 shadow-2xl space-y-4 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[var(--primary-text)]">Register Evidence Media</span>
              <button
                onClick={() => setRegisteringDevice(null)}
                className="text-[var(--text)]/50 hover:text-[var(--text)]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {registeringSuccess ? (
              <div className="py-6 text-center text-[var(--primary-text)] space-y-1">
                <CheckCircle className="w-6 h-6 mx-auto" />
                <p>Registered to Case {activeCase.case_id}!</p>
              </div>
            ) : (
              <form onSubmit={handleRegisterEvidence} className="space-y-3">
                <div>
                  <label className="label-muted block mb-1">Target Case</label>
                  <input
                    type="text"
                    disabled
                    value={`${activeCase.case_id} (${activeCase.case_name})`}
                    className="w-full font-mono text-xs opacity-60 cursor-not-allowed"
                  />
                </div>

                <div>
                  <label className="label-muted block mb-1">Device Path</label>
                  <input
                    type="text"
                    disabled
                    value={`${formatDevicePath(registeringDevice.path).primary} (${registeringDevice.path}) — ${registeringDevice.model}`}
                    className="w-full font-mono text-xs opacity-60 cursor-not-allowed"
                  />
                </div>

                <div>
                  <label className="label-muted block mb-1">Evidence Description & Notes</label>
                  <textarea
                    rows={2}
                    placeholder="Seized USB drive from suspect workstation..."
                    value={evidenceDesc}
                    onChange={(e) => setEvidenceDesc(e.target.value)}
                    className="w-full font-mono text-xs"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setRegisteringDevice(null)}
                    className="px-3 py-1.5 rounded text-[var(--text)]/60 hover:bg-[var(--border)]/20"
                  >
                    Cancel
                  </button>
                  <GlowButton type="submit" variant="primary" size="sm">
                    Register Evidence
                  </GlowButton>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default DeviceSelection;
