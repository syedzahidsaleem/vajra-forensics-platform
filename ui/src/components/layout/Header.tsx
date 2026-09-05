import React from 'react';
import { useApp } from '../../context/AppContext';
import { useTheme } from '../../context/ThemeContext';
import { Sun, Moon, Menu } from 'lucide-react';

export const Header: React.FC = () => {
  const { mode, setMode, sidebarOpen, toggleSidebar } = useApp();
  const { theme, toggleTheme } = useTheme();
  const isForensic = mode === 'forensic';

  return (
    <header
      className={`h-10 px-4 sm:px-6 flex items-center justify-between z-40 relative select-none ${
        isForensic
          ? 'bg-[var(--forensic-navbar-bg)] border-b border-[var(--forensic-border)]'
          : 'border-b border-[rgba(89,238,153,0.06)] bg-[rgba(0,18,11,0.95)] backdrop-blur-md'
      }`}
    >
      {/* Left: Brand & Sidebar Toggle */}
      <div className="flex items-center gap-2.5">
        <button
          onClick={toggleSidebar}
          aria-label="Toggle Sidebar"
          title={sidebarOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
          className="p-1.5 -ml-1 rounded-md text-[var(--text)]/70 hover:text-[var(--text)] hover:bg-[var(--surface)] transition-colors cursor-pointer flex items-center justify-center"
        >
          <Menu className="w-4 h-4" />
        </button>

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

        {/* Mode Toggle Buttons */}
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
