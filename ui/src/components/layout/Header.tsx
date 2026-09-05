import React from 'react';
import { useApp } from '../../context/AppContext';

export const Header: React.FC = () => {
  const { mode, setMode } = useApp();
  const isForensic = mode === 'forensic';

  return (
    <header
      className={`h-10 px-6 flex items-center justify-between z-40 relative select-none ${
        isForensic
          ? 'bg-[var(--forensic-navbar-bg)] border-b border-[var(--forensic-border)]'
          : 'border-b border-[rgba(89,238,153,0.06)] bg-[rgba(0,18,11,0.95)] backdrop-blur-md'
      }`}
    >
      {/* Left: Brand */}
      <div className="flex items-center gap-2">
        <span
          className={`w-1.5 h-1.5 rounded-full animate-pulse ${
            isForensic
              ? 'bg-[var(--forensic-accent)] shadow-[0_0_6px_var(--forensic-accent)]'
              : 'bg-[#59EE99] shadow-[0_0_6px_#59EE99]'
          }`}
        />
        <span
          className={`font-mono font-bold text-[11px] tracking-wider ${
            isForensic ? 'text-[var(--forensic-text-primary)]' : 'glow-green'
          }`}
        >
          VAJRA <span className={`text-[9px] ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'opacity-60'}`}>v0.1.0</span>
        </span>
      </div>

      {/* Center: Mode Badge */}
      <div className="flex items-center">
        {isForensic ? (
          <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-[rgba(13,184,211,0.12)] border border-[var(--forensic-border)] text-[var(--forensic-accent)] font-mono text-[10px] tracking-widest uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--forensic-accent)] shadow-[0_0_6px_var(--forensic-accent)]" />
            Forensic Mode
          </div>
        ) : (
          <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-[rgba(239,68,68,0.12)] border border-[#EF4444]/30 text-[#EF4444] font-mono text-[10px] tracking-widest uppercase animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] shadow-[0_0_6px_#EF4444]" />
            Sanitization Mode
          </div>
        )}
      </div>

      {/* Right: Mode Toggle Buttons */}
      <div
        className={`flex rounded-md overflow-hidden border ${
          isForensic ? 'border-[var(--forensic-border)]' : 'border-[rgba(89,238,153,0.1)]'
        }`}
      >
        <button
          onClick={() => setMode('forensic')}
          className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
            isForensic
              ? 'bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] font-bold'
              : 'text-[#D8E4FF]/40 hover:text-[#D8E4FF]/70'
          }`}
        >
          Forensic
        </button>
        <button
          onClick={() => setMode('sanitization')}
          className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
            !isForensic
              ? 'bg-[rgba(239,68,68,0.15)] text-[#EF4444]'
              : 'text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)]'
          }`}
        >
          Sanitize
        </button>
      </div>
    </header>
  );
};
