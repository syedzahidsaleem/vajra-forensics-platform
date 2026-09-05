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
          : 'bg-[var(--sanitize-navbar-bg)] border-b border-[var(--sanitize-border)]'
      }`}
    >
      {/* Left: Brand & Sidebar Toggle */}
      <div className="flex items-center gap-2.5">
        <button
          onClick={toggleSidebar}
          aria-label="Toggle Sidebar"
          title={sidebarOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
          className={`p-1.5 -ml-1 rounded-md transition-colors cursor-pointer flex items-center justify-center ${
            isForensic
              ? 'text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)] hover:bg-[var(--surface)]'
              : 'text-[var(--sanitize-text-secondary)] hover:text-[var(--sanitize-text-primary)] hover:bg-[var(--surface)]'
          }`}
        >
          <Menu className="w-4 h-4" />
        </button>

        <span
          className={`w-1.5 h-1.5 rounded-full animate-pulse ${
            isForensic
              ? 'bg-[var(--forensic-accent)] shadow-[0_0_6px_var(--forensic-accent)]'
              : 'bg-[var(--sanitize-accent)] shadow-[0_0_6px_var(--sanitize-accent)]'
          }`}
        />
        <span
          className={`font-mono font-bold text-[11px] tracking-wider ${
            isForensic ? 'text-[var(--forensic-text-primary)]' : 'text-[var(--sanitize-text-primary)]'
          }`}
        >
          VAJRA <span className={`text-[9px] ${isForensic ? 'text-[var(--forensic-text-secondary)]' : 'text-[var(--sanitize-text-secondary)]'}`}>v0.1.0</span>
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
          <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-[rgba(255,59,59,0.12)] border border-[var(--sanitize-border)] text-[var(--sanitize-accent)] font-mono text-[10px] tracking-widest uppercase animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--sanitize-accent)] shadow-[0_0_6px_var(--sanitize-accent)]" />
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
          className={`p-1.5 rounded-md border transition-colors cursor-pointer flex items-center justify-center ${
            isForensic
              ? 'border-[var(--forensic-border)] text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)] hover:border-[var(--forensic-accent)]/50 bg-[var(--surface)]'
              : 'border-[var(--sanitize-border)] text-[var(--sanitize-text-secondary)] hover:text-[var(--sanitize-text-primary)] hover:border-[var(--sanitize-accent)]/50 bg-[var(--surface)]'
          }`}
        >
          {theme === 'dark' ? (
            <Sun className="w-3.5 h-3.5 text-amber-400" />
          ) : (
            <Moon className="w-3.5 h-3.5 text-indigo-400" />
          )}
        </button>

        {/* Mode Toggle Buttons */}
        <div className={`flex rounded-md overflow-hidden border ${
          isForensic ? 'border-[var(--forensic-border)]' : 'border-[var(--sanitize-border)]'
        }`}>
          <button
            onClick={() => setMode('forensic')}
            className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
              isForensic
                ? 'bg-[var(--forensic-accent)]/20 text-[var(--forensic-accent)] font-bold'
                : 'text-[var(--sanitize-text-secondary)] hover:text-[var(--sanitize-text-primary)]'
            }`}
          >
            Forensic
          </button>
          <button
            onClick={() => setMode('sanitization')}
            className={`px-3 py-1 text-[10px] font-mono transition-colors cursor-pointer ${
              !isForensic
                ? 'bg-[var(--sanitize-accent)]/20 text-[var(--sanitize-accent)] font-bold'
                : 'text-[var(--forensic-text-secondary)] hover:text-[var(--forensic-text-primary)]'
            }`}
          >
            Sanitize
          </button>
        </div>
      </div>
    </header>
  );
};
