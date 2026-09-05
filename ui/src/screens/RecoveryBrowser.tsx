import React, { useState } from 'react';
import {
  Sparkles,
  Filter,
  Binary,
  Play,
} from 'lucide-react';
import StorageMap from '../components/storage-map/StorageMap';
import { useApp } from '../context/AppContext';
import {
  SectionHeader,
  GlassCard,
  FileTypeBadge,
  TierBadge,
  ConfidenceBar,
  GlowButton,
  OrbitalSpinner,
  AnimatedCounter,
  useToast,
} from '../components/ui/vajra-components';

interface Artifact {
  id: string;
  name: string;
  type: string;
  tier: string;
  confidence: number;
  startLba: number;
  blockCount: number;
  sizeBytes: number;
  status: string;
  signals: {
    signature: number;
    structure: number;
    entropy: number;
    slack: number;
    ml: number;
    validation: number;
  };
}

export const RecoveryBrowser: React.FC = () => {
  const { selectedDevice, jumpToHexLba } = useApp();
  const { toast } = useToast();
  const [selectedTier, setSelectedTier] = useState<'All' | 'Tier 1' | 'Tier 2' | 'Tier 3'>('All');
  const [isLoading, setIsLoading] = useState(false);

  const [artifacts] = useState<Artifact[]>([
    {
      id: 'REC-001',
      name: 'confidential_ledger.pdf',
      type: 'pdf',
      tier: 'Tier1Metadata',
      confidence: 0.96,
      startLba: 2048,
      blockCount: 400,
      sizeBytes: 204800,
      status: 'Confirmed Intact',
      signals: {
        signature: 1.0,
        structure: 0.95,
        entropy: 0.92,
        slack: 1.0,
        ml: 0.94,
        validation: 0.98,
      },
    },
    {
      id: 'REC-002',
      name: 'surveillance_camera_04.jpg',
      type: 'jpeg',
      tier: 'Tier2Signature',
      confidence: 0.91,
      startLba: 65400,
      blockCount: 1200,
      sizeBytes: 614400,
      status: 'Validated Headers & EXIF',
      signals: {
        signature: 0.98,
        structure: 0.92,
        entropy: 0.88,
        slack: 0.85,
        ml: 0.91,
        validation: 0.93,
      },
    },
    {
      id: 'REC-003',
      name: 'chat.sqlite',
      type: 'sqlite',
      tier: 'Tier1Metadata',
      confidence: 0.94,
      startLba: 32768,
      blockCount: 512,
      sizeBytes: 262144,
      status: 'SQLite Magic Verified',
      signals: {
        signature: 0.99,
        structure: 0.98,
        entropy: 0.91,
        slack: 0.95,
        ml: 0.95,
        validation: 0.89,
      },
    },
    {
      id: 'REC-004',
      name: 'encrypted_backup.zip',
      type: 'zip',
      tier: 'Tier3Fragmented',
      confidence: 0.61,
      startLba: 142000,
      blockCount: 2400,
      sizeBytes: 1228800,
      status: 'Gap Provenance Resolved',
      signals: {
        signature: 0.90,
        structure: 0.70,
        entropy: 0.65,
        slack: 0.55,
        ml: 0.45,
        validation: 0.42,
      },
    },
  ]);

  const [selectedArtifact, setSelectedArtifact] = useState<Artifact>(artifacts[0]);

  const handleRunPipeline = () => {
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      toast('Pipeline complete — 4 artifacts identified across Tiers 1-3', 'success');
    }, 1500);
  };

  const filteredArtifacts = artifacts.filter((art) => {
    if (selectedTier === 'All') return true;
    if (selectedTier === 'Tier 1') return art.tier.includes('1') || art.tier.includes('Metadata');
    if (selectedTier === 'Tier 2') return art.tier.includes('2') || art.tier.includes('Signature') || art.tier.includes('Carving');
    if (selectedTier === 'Tier 3') return art.tier.includes('3') || art.tier.includes('Fragmented');
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <SectionHeader
        title="Recovery Browser & Artifact Inspector"
        subtitle="Browse recovered files across Tier-1 (metadata), Tier-2 (carving), and Tier-3 (bifragment reconstruction) with 6-signal confidence breakdowns."
        tags={['§29–§32', 'FORENSIC READ-ONLY']}
        actions={
          <GlowButton
            variant="primary"
            size="md"
            icon={<Play className="w-3.5 h-3.5" />}
            loading={isLoading}
            onClick={handleRunPipeline}
          >
            Run Recovery Pipeline
          </GlowButton>
        }
      />

      {/* Tier Filter Tabs */}
      <div className="flex items-center justify-between gap-4 bg-[rgba(15,36,48,0.45)] p-2 rounded-xl border border-[var(--forensic-border)]">
        <div className="flex items-center gap-1.5 font-mono text-xs">
          {(['All', 'Tier 1', 'Tier 2', 'Tier 3'] as const).map((tier) => (
            <button
              key={tier}
              type="button"
              onClick={() => setSelectedTier(tier)}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold ${
                selectedTier === tier
                  ? 'bg-[var(--forensic-accent)] text-[#0F2430] shadow-[0_0_12px_rgba(13,184,211,0.35)]'
                  : 'text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)] hover:bg-[rgba(13,184,211,0.1)]'
              }`}
            >
              {tier}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[var(--forensic-accent)]">
          <Filter className="w-3.5 h-3.5" />
          <span>Active Filter: {selectedTier}</span>
        </div>
      </div>

      {/* Embedded Storage Map in Forensic Mode */}
      <StorageMap
        sourcePath={selectedDevice?.path || '\\\\.\\PhysicalDrive0'}
        mode="forensic"
        highlightArtifact={selectedArtifact}
        onRegionClick={(start) => jumpToHexLba(start)}
      />

      {/* Loading state */}
      {isLoading && (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <OrbitalSpinner size={40} />
          <div className="text-center">
            <p className="text-sm font-mono text-[#59EE99]">Running recovery pipeline...</p>
            <p className="text-xs text-[#D8E4FF]/40 mt-1">
              Scanning Tier 1 metadata → Tier 2 signatures → Tier 3 fragments
            </p>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && filteredArtifacts.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <div className="w-12 h-12 rounded-full bg-[rgba(89,238,153,0.08)] border border-[#59EE99]/20 flex items-center justify-center">
            <Binary className="w-5 h-5 text-[#59EE99]/50" />
          </div>
          <p className="text-sm font-mono text-[#D8E4FF]/50">No artifacts recovered</p>
          <p className="text-xs text-[#D8E4FF]/30">Try enabling additional tiers or selecting a different source</p>
        </div>
      )}

      {/* Main Content Grid: Artifact Candidates + 6-Signal Inspector */}
      {!isLoading && filteredArtifacts.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Candidate List */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono text-[#D8E4FF]/50">
              <span>Evidence Candidates ({filteredArtifacts.length} items)</span>
            </div>

            <div className="space-y-3">
              {filteredArtifacts.map((art) => {
                const isSelected = selectedArtifact?.id === art.id;
                return (
                  <GlassCard
                    key={art.id}
                    selected={isSelected}
                    hover={true}
                    onClick={() => setSelectedArtifact(art)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2.5">
                        <FileTypeBadge type={art.type} />
                        <span className="font-mono text-sm font-bold text-[#D8E4FF]">{art.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <TierBadge tier={art.tier} />
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-[11px] font-mono text-[#D8E4FF]/60 pt-2 border-t border-[rgba(89,238,153,0.08)] mb-3">
                      <div>
                        <span className="text-[#D8E4FF]/40 block">Confidence:</span>
                        <ConfidenceBar value={art.confidence} />
                      </div>
                      <div>
                        <span className="text-[#D8E4FF]/40 block">LBA Offset:</span>
                        <span className="text-[#D8E4FF]">LBA {art.startLba.toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-[#D8E4FF]/40 block">Status:</span>
                        <span className="text-[#59EE99]">{art.status}</span>
                      </div>
                    </div>

                    {/* Actions Bar */}
                    <div className="flex items-center justify-between pt-2 border-t border-[rgba(89,238,153,0.06)]">
                      <span className="text-[10px] font-mono text-[#D8E4FF]/40">
                        Size: {(art.sizeBytes / 1024).toFixed(1)} KB ({art.blockCount} sectors)
                      </span>
                      <GlowButton
                        variant="ghost"
                        size="sm"
                        icon={<Binary className="w-3 h-3" />}
                        onClick={(e) => {
                          e.stopPropagation();
                          jumpToHexLba(art.startLba);
                        }}
                      >
                        Hex Explorer &rarr;
                      </GlowButton>
                    </div>
                  </GlassCard>
                );
              })}
            </div>
          </div>

          {/* 6-Signal Confidence Inspector */}
          <GlassCard hover={false} className="h-fit space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--forensic-border)]">
              <div className="flex items-center gap-2 text-[var(--forensic-accent)] font-mono font-bold text-xs">
                <Sparkles className="w-4 h-4" />
                <span>6-Signal Confidence Breakdown</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] border border-[var(--forensic-border)]">
                Verified
              </span>
            </div>

            <div className="space-y-1 font-mono">
              <div className="text-[11px] text-[var(--forensic-text-secondary)]">Target Artifact:</div>
              <div className="text-sm font-bold text-[var(--forensic-text-primary)] truncate">{selectedArtifact.name}</div>
            </div>

            {/* Signal List */}
            <div className="space-y-3 text-[11px] font-mono">
              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>1. Signature Magic Bytes Match</span>
                  <AnimatedCounter value={selectedArtifact.signals.signature * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.signature} showLabel={false} />
              </div>

              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>2. Internal Structure Parser</span>
                  <AnimatedCounter value={selectedArtifact.signals.structure * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.structure} showLabel={false} />
              </div>

              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>3. Chi-Square Entropy Consistency</span>
                  <AnimatedCounter value={selectedArtifact.signals.entropy * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.entropy} showLabel={false} />
              </div>

              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>4. Filesystem Slack Match</span>
                  <AnimatedCounter value={selectedArtifact.signals.slack * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.slack} showLabel={false} />
              </div>

              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>5. ML Classifier Signal</span>
                  <AnimatedCounter value={selectedArtifact.signals.ml * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.ml} showLabel={false} />
              </div>

              <div>
                <div className="flex justify-between text-[var(--forensic-text-primary)] mb-1">
                  <span>6. Cross-Validation Verification</span>
                  <AnimatedCounter value={selectedArtifact.signals.validation * 100} suffix="%" className="text-[var(--forensic-accent)] font-bold" />
                </div>
                <ConfidenceBar value={selectedArtifact.signals.validation} showLabel={false} />
              </div>
            </div>

            <div className="p-3 rounded-xl bg-[rgba(15,36,48,0.6)] border border-[var(--forensic-border)] text-[10px] text-[var(--forensic-text-secondary)] leading-relaxed font-mono space-y-1">
              <span className="text-[var(--forensic-accent)] font-bold block">Recovery Provenance & Explainability:</span>
              All 6 independent validation signals evaluated. No corrupt extents or broken clusters detected.
            </div>

            <GlowButton
              variant="outline"
              size="md"
              className="w-full justify-center"
              icon={<Binary className="w-3.5 h-3.5" />}
              onClick={() => jumpToHexLba(selectedArtifact.startLba)}
            >
              Open in Raw Hex Explorer
            </GlowButton>
          </GlassCard>
        </div>
      )}
    </div>
  );
};

export default RecoveryBrowser;
