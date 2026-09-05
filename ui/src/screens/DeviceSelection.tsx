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
import { GlassCard, GlowButton, FileTypeBadge, useToast } from '../components/ui/vajra-components';

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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className={`text-lg font-sans font-medium ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
              {isForensic ? 'Storage Device Enumeration' : 'Sanitization Target Selection'}
            </h1>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                isForensic
                  ? 'bg-[rgba(13,184,211,0.12)] text-[var(--forensic-accent)] border border-[var(--forensic-border)]'
                  : 'bg-[rgba(89,238,153,0.08)] text-[#59EE99]/70 border border-[#59EE99]/15'
              }`}
            >
              §23, §24
            </span>
          </div>
          <p className={`text-[11px] font-sans ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[#D8E4FF]/30'}`}>
            {isForensic
              ? 'Real-time hardware enumeration, SMART/NVMe telemetry, write-blocker detection, and SHA-256 fingerprinting.'
              : 'Target disk verification and strict OS-disk hard refusal (§24) prior to sanitization gate.'}
          </p>
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

      {/* Device Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {devices.map((device: DeviceDescriptor) => {
          const isSystem = device.is_system_disk;
          const isWriteBlocked = device.is_write_blocked;

          return (
            <GlassCard
              key={device.path}
              hover={true}
              danger={!isForensic && isSystem}
              className="p-5 space-y-4"
            >
              {/* Drive Top Row */}
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`font-mono text-[11px] font-bold ${isForensic ? 'text-[var(--forensic-text-mono)]' : 'text-[#59EE99]'}`}>
                      {device.path}
                    </span>
                    <FileTypeBadge type={device.media_type} />
                    {device.bus_type && (
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono ${isForensic ? 'bg-[rgba(13,184,211,0.1)] text-[var(--forensic-text-secondary)]' : 'bg-[rgba(53,96,90,0.15)] text-[#D8E4FF]/40'}`}>
                        {device.bus_type}
                      </span>
                    )}
                  </div>
                  <h3 className={`font-medium text-sm font-sans ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
                    {device.model}
                  </h3>
                  <div className={`text-[10px] font-mono ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[#D8E4FF]/35'}`}>
                    S/N: <span className={isForensic ? 'text-[var(--forensic-text-mono)]' : 'text-[#D8E4FF]/70'}>{device.serial}</span>
                  </div>
                </div>

                <div className="text-right">
                  <div className={`text-sm font-mono font-bold ${isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[#D8E4FF]'}`}>
                    {formatBytes(device.size_bytes)}
                  </div>
                  <div className={`text-[9px] font-mono ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[#D8E4FF]/30'}`}>
                    Sector: {device.block_size} B
                  </div>
                </div>
              </div>

              {/* Safety Badges */}
              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[rgba(13,184,211,0.15)] text-[10px] font-mono">
                {isSystem ? (
                  <div className="flex items-center gap-1.5 p-1.5 rounded bg-[rgba(239,68,68,0.08)] border border-[#EF4444]/20 text-[#EF4444]">
                    <AlertOctagon className="w-3 h-3 flex-shrink-0" />
                    <span>OS BOOT DISK (LOCKED §24)</span>
                  </div>
                ) : (
                  <div className={`flex items-center gap-1.5 p-1.5 rounded border ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(89,238,153,0.08)] border-[#59EE99]/20 text-[#59EE99]'}`}>
                    <CheckCircle className="w-3 h-3 flex-shrink-0" />
                    <span>Secondary Target Disk</span>
                  </div>
                )}

                {isWriteBlocked ? (
                  <div className={`flex items-center gap-1.5 p-1.5 rounded border ${isForensic ? 'bg-[rgba(13,184,211,0.12)] border-[var(--forensic-border)] text-[var(--forensic-accent)]' : 'bg-[rgba(89,238,153,0.08)] border-[#59EE99]/20 text-[#59EE99]'}`}>
                    <ShieldCheck className="w-3 h-3 flex-shrink-0" />
                    <span>Write-Blocker Active</span>
                  </div>
                ) : (
                  <div className={`flex items-center gap-1.5 p-1.5 rounded border ${isForensic ? 'bg-[rgba(15,36,48,0.5)] border-[var(--forensic-border)] text-[var(--forensic-text-secondary)]' : 'bg-[rgba(53,96,90,0.15)] border-[rgba(89,238,153,0.06)] text-[#D8E4FF]/40'}`}>
                    <ShieldAlert className="w-3 h-3 flex-shrink-0 text-amber-400" />
                    <span>Direct Device Access</span>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-2 border-t border-[rgba(89,238,153,0.06)]">
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
            </GlassCard>
          );
        })}
      </div>

      {/* Inspect & Health Modal */}
      {inspectingDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(0,18,11,0.85)] backdrop-blur-md p-4">
          <div className="w-full max-w-xl bg-[#00120B] border border-[rgba(89,238,153,0.15)] rounded-xl p-5 shadow-2xl space-y-4 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#59EE99]" />
                <span className="font-bold text-[#D8E4FF]">
                  Diagnostics: {inspectingDevice.model}
                </span>
              </div>
              <button
                onClick={() => setInspectingDevice(null)}
                className="text-[#D8E4FF]/40 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {loadingModal ? (
              <div className="py-8 text-center text-[#D8E4FF]/30">Reading drive SMART & fingerprint...</div>
            ) : (
              <div className="space-y-3">
                {/* Fingerprint Card */}
                {fingerprint && (
                  <div className="p-3 bg-[rgba(53,96,90,0.12)] rounded-lg space-y-1">
                    <p className="label-muted">Hardware Identity Fingerprint (§23)</p>
                    <div className="text-[10px] text-[#D8E4FF]/60 truncate">
                      SHA-256 Digest: <span className="text-[#59EE99]">{fingerprint.sha256_hash}</span>
                    </div>
                  </div>
                )}

                {/* Health Snapshot */}
                {health && (
                  <div className="p-3 bg-[rgba(53,96,90,0.12)] rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="label-muted">SMART / NVMe Health Telemetry</p>
                      <span className="px-1.5 py-0.5 rounded bg-[rgba(89,238,153,0.1)] text-[#59EE99] text-[9px] font-bold">
                        {health.overall_health}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-[10px] text-[#D8E4FF]/60">
                      <div className="flex items-center gap-1">
                        <Thermometer className="w-3 h-3 text-[#59EE99]" />
                        <span>Temp: {health.temperature_celsius}°C</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Cpu className="w-3 h-3 text-[#59EE99]" />
                        <span>Power Hours: {health.power_on_hours}h</span>
                      </div>
                      <div>
                        <span>Reallocated: {health.reallocated_sectors}</span>
                      </div>
                    </div>

                    <p className="text-[10px] text-[#D8E4FF]/40 font-sans leading-relaxed pt-1 border-t border-[rgba(89,238,153,0.06)]">
                      {health.recommendation}
                    </p>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectingDevice(null)}
                className="px-3 py-1.5 bg-[rgba(53,96,90,0.2)] text-[#D8E4FF]/70 hover:text-[#D8E4FF] rounded text-[10px]"
              >
                Close Diagnostics
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Vault Evidence Modal */}
      {registeringDevice && activeCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(0,18,11,0.85)] backdrop-blur-md p-4">
          <div className="w-full max-w-md bg-[#00120B] border border-[rgba(89,238,153,0.15)] rounded-xl p-5 shadow-2xl space-y-4 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#59EE99]">Register Evidence Media</span>
              <button
                onClick={() => setRegisteringDevice(null)}
                className="text-[#D8E4FF]/40 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {registeringSuccess ? (
              <div className="py-6 text-center text-[#59EE99] space-y-1">
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
                    className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.1)] border border-[rgba(89,238,153,0.06)] text-[#D8E4FF]/50"
                  />
                </div>

                <div>
                  <label className="label-muted block mb-1">Device Path</label>
                  <input
                    type="text"
                    disabled
                    value={`${registeringDevice.path} — ${registeringDevice.model}`}
                    className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.1)] border border-[rgba(89,238,153,0.06)] text-[#D8E4FF]/50"
                  />
                </div>

                <div>
                  <label className="label-muted block mb-1">Evidence Description & Notes</label>
                  <textarea
                    rows={2}
                    placeholder="Seized USB drive from suspect workstation..."
                    value={evidenceDesc}
                    onChange={(e) => setEvidenceDesc(e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-[rgba(53,96,90,0.15)] border border-[rgba(89,238,153,0.1)] text-[#D8E4FF] outline-none focus:border-[#59EE99]/50"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setRegisteringDevice(null)}
                    className="px-3 py-1.5 rounded text-[#D8E4FF]/50 hover:bg-[rgba(53,96,90,0.2)]"
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
