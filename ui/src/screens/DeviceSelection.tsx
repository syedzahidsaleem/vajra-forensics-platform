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
    <div data-mode={isForensic ? "forensic" : "sanitize"} style={{ background: 'var(--bg)', color: 'var(--text)' }} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-lg font-sans font-medium ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
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
      <div className="flex flex-col gap-3 w-full">
        {devices.map((device: DeviceDescriptor) => {
          const isSystem = device.is_system_disk;
          const isWriteBlocked = device.is_write_blocked;
          const devInfo = formatDevicePath(device.path);

          return (
            <div
              key={device.path}
              style={{ border: '1px solid var(--border)', borderRadius: '12px' }}
              className="p-3.5 px-5 bg-[var(--surface)] text-[var(--text)] rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm w-full"
            >
              {/* Left: Drive Info + Capacity */}
              <div className="flex items-center gap-4 min-w-0 flex-1">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`font-mono text-xs font-bold ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#59EE99]'}`}>
                      {devInfo.primary}
                    </span>
                    <span className="font-mono text-[10px] text-[var(--text)]/50">
                      {devInfo.raw}
                    </span>
                    <FileTypeBadge type={device.media_type} />
                    {device.bus_type && (
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono ${isForensic ? 'bg-[rgba(13,184,211,0.1)] text-[var(--forensic-text-secondary)]' : 'bg-[rgba(53,96,90,0.15)] text-[#D8E4FF]/40'}`}>
                        {device.bus_type}
                      </span>
                    )}
                  </div>
                  <div className="flex items-baseline gap-2.5 flex-wrap">
                    <h3 className={`font-medium text-sm font-sans ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
                      {device.model}
                    </h3>
                    <span className={`text-[10px] font-mono ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[#D8E4FF]/35'}`}>
                      S/N: <span className={isForensic ? 'text-[var(--forensic-text-mono)]' : 'text-[#D8E4FF]/70'}>{device.serial}</span>
                    </span>
                  </div>
                </div>

                <div className="pl-3 border-l border-[var(--border)]/20 shrink-0">
                  <div className={`text-sm font-mono font-bold ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
                    {formatBytes(device.size_bytes)}
                  </div>
                  <div className={`text-[9px] font-mono ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[#D8E4FF]/30'}`}>
                    Sector: {device.block_size} B
                  </div>
                </div>
              </div>

              {/* Middle: Safety Badges */}
              <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono shrink-0">
                {isSystem ? (
                  <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[rgba(239,68,68,0.08)] border border-[#EF4444]/20 text-[#EF4444] whitespace-nowrap">
                    <AlertOctagon className="w-3 h-3 flex-shrink-0" />
                    <span>OS BOOT DISK (LOCKED §24)</span>
                  </div>
                ) : (
                  <div className={`flex items-center gap-1.5 px-2 py-1 rounded border whitespace-nowrap ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(89,238,153,0.08)] border-[#59EE99]/20 text-[#59EE99]'}`}>
                    <CheckCircle className="w-3 h-3 flex-shrink-0" />
                    <span>Secondary Target Disk</span>
                  </div>
                )}

                {isWriteBlocked ? (
                  <div className={`flex items-center gap-1.5 px-2 py-1 rounded border whitespace-nowrap ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(89,238,153,0.08)] border-[#59EE99]/20 text-[#59EE99]'}`}>
                    <ShieldCheck className="w-3 h-3 flex-shrink-0" />
                    <span>Write-Blocker Active</span>
                  </div>
                ) : (
                  <div className={`flex items-center gap-1.5 px-2 py-1 rounded border whitespace-nowrap ${isForensic ? 'bg-[rgba(15,36,48,0.5)] border-[var(--forensic-border)] text-[var(--forensic-text-secondary)]' : 'bg-[rgba(53,96,90,0.15)] border-[rgba(89,238,153,0.06)] text-[#D8E4FF]/40'}`}>
                    <ShieldAlert className="w-3 h-3 flex-shrink-0 text-amber-400" />
                    <span>Direct Device Access</span>
                  </div>
                )}
              </div>

              {/* Right: Action Buttons */}
              <div className="flex items-center gap-2 shrink-0 self-end lg:self-center">
                <GlowButton
                  variant="ghost"
                  size="sm"
                  icon={<Activity className="w-3 h-3" />}
                  onClick={() => handleInspectDevice(device)}
                >
                  Inspect & Health
                </GlowButton>

                <div className="flex items-center gap-2">
                  {isForensic ? (
                    <>
                      {activeCase && (
                        <GlowButton
                          variant="ghost"
                          size="sm"
                          icon={<Plus className="w-3 h-3" />}
                          onClick={() => setRegisteringDevice(device)}
                        >
                          Vault Evidence
                        </GlowButton>
                      )}
                      <GlowButton
                        variant="primary"
                        size="sm"
                        icon={<Disc className="w-3 h-3" />}
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
                      icon={<Flame className="w-3 h-3" />}
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
