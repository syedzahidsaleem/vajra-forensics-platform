import React from 'react';
import { useApp } from '../../context/AppContext';
import { useTheme } from '../../context/ThemeContext';
import { Sun, Moon } from 'lucide-react';

export const Header: React.FC = () => {
  const { mode, setMode } = useApp();
  const { theme, toggleTheme } = useTheme();
  const isForensic = mode === 'forensic';

  return (
    <header className="h-10 px-6 flex items-center justify-between border-b border-[var(--border)]/20 bg-[var(--surface)] backdrop-blur-md z-40 relative select-none text-[var(--text)]">
      {/* Left: Brand */}
      <div className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-[#59EE99] animate-pulse shadow-[0_0_6px_#59EE99]" />
        <span className="font-mono font-bold text-[11px] tracking-wider text-[var(--text)]">
          VAJRA <span className="text-[9px] opacity-60">v0.1.0</span>
        </span>
      </div>

      {/* Center: Mode Badge */}
      <div className="flex items-center">
        {isForensic ? (
          <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-[var(--primary)]/10 border border-[var(--primary)]/30 text-[var(--primary-text)] font-mono text-[10px] tracking-widest uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] shadow-[0_0_6px_var(--primary)]" />
            Forensic Mode
          </div>
        ) : (
          <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-[var(--primary)]/15 border border-[var(--primary)]/30 text-[var(--primary-text)] font-mono text-[10px] tracking-widest uppercase animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] shadow-[0_0_6px_var(--primary)]" />
            Sanitization Mode
          </div>
        )}
      </div>

      {/* Right: Actions (Theme Toggle + Mode Toggle) */}
      <div className="flex items-center gap-3">
        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle Theme"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          className="p-1.5 rounded-md border border-[var(--border)]/30 text-[var(--text)]/70 hover:text-[var(--primary-text)] hover:border-[var(--primary)]/50 bg-[var(--surface)] transition-colors cursor-pointer flex items-center justify-center"
        >
          {theme === 'dark' ? (
            <Sun className="w-3.5 h-3.5 text-amber-400" />
          ) : (
            <Moon className="w-3.5 h-3.5 text-indigo-400" />
          )}
        </button>

        {/* Existing Mode Toggle Buttons */}
        <div className="flex rounded-md overflow-hidden border border-[var(--border)]/30">
          <button
            onClick={() => setMode('forensic')}
            className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
              isForensic
                ? 'bg-[var(--primary-text)]/15 text-[var(--primary-text)] font-bold'
                : 'text-[var(--text)]/50 hover:text-[var(--text)]'
            }`}
          >
            Forensic
          </button>
          <button
            onClick={() => setMode('sanitization')}
            className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
              !isForensic
                ? 'bg-[var(--primary-text)]/15 text-[var(--primary-text)] font-bold'
                : 'text-[var(--text)]/50 hover:text-[var(--text)]'
            }`}
          >
            Sanitize
          </button>
        </div>
      </div>
    </header>
  );
};
