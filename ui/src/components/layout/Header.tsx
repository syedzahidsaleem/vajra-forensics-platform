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
      <div className="flex items-center gap-3">
        <button
          onClick={toggleSidebar}
          aria-label="Toggle Sidebar"
          title={sidebarOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
          className={`p-1.5 -ml-1 rounded-md transition-colors cursor-pointer flex items-center justify-center ${
            isForensic
              ? 'text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:text-[#044E38] dark:hover:text-[var(--forensic-text-primary)] hover:bg-[var(--surface)]'
              : 'text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:text-[#680E18] dark:hover:text-[var(--sanitize-text-primary)] hover:bg-[var(--surface)]'
          }`}
        >
          <Menu className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-sm rotate-45 shrink-0 ${
              isForensic
                ? 'bg-[#044E38] dark:bg-[var(--forensic-accent)] shadow-[0_0_8px_var(--forensic-accent)]'
                : 'bg-[#680E18] dark:bg-[var(--sanitize-accent)] shadow-[0_0_8px_var(--sanitize-accent)]'
            }`}
          />
          <span
            className={`font-industrial font-black text-sm sm:text-base tracking-[0.18em] uppercase ${
              isForensic ? 'text-[#044E38] dark:text-[var(--forensic-text-primary)]' : 'text-[#680E18] dark:text-[var(--sanitize-text-primary)]'
            }`}
          >
            VAJRA
          </span>
          <span
            className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider uppercase border ${
              isForensic
                ? 'bg-emerald-950/10 dark:bg-emerald-500/15 text-[#044E38] dark:text-[var(--forensic-accent)] border-[var(--forensic-border)]'
                : 'bg-red-950/10 dark:bg-red-500/15 text-[#680E18] dark:text-[var(--sanitize-accent)] border-[var(--sanitize-border)]'
            }`}
          >
            v0.1.0
          </span>
        </div>
      </div>

      {/* Center: Command Mode Header (Prominent Cyber-Industrial Typography) */}
      <div className="flex items-center">
        {isForensic ? (
          <div className="flex items-center gap-2.5 animate-pulse select-none">
            <span className="w-2 h-2 rounded-sm rotate-45 bg-[#044E38] dark:bg-[var(--forensic-accent)] shadow-[0_0_8px_var(--forensic-accent)] shrink-0" />
            <span className="font-industrial font-black text-sm sm:text-base tracking-[0.24em] text-[#044E38] dark:text-[var(--forensic-accent)] uppercase">
              Forensic Mode
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2.5 animate-pulse select-none">
            <span className="w-2 h-2 rounded-sm rotate-45 bg-[#680E18] dark:bg-[var(--sanitize-accent)] shadow-[0_0_8px_var(--sanitize-accent)] shrink-0" />
            <span className="font-industrial font-black text-sm sm:text-base tracking-[0.24em] text-[#680E18] dark:text-[var(--sanitize-accent)] uppercase">
              Sanitization Mode
            </span>
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
              ? 'border-[var(--forensic-border)] text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:text-[#044E38] dark:hover:text-[var(--forensic-text-primary)] hover:border-[var(--forensic-accent)]/50 bg-[var(--surface)]'
              : 'border-[var(--sanitize-border)] text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:text-[#680E18] dark:hover:text-[var(--sanitize-text-primary)] hover:border-[var(--sanitize-accent)]/50 bg-[var(--surface)]'
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
            className={`px-3 py-1 text-[10px] font-industrial font-bold tracking-wider uppercase transition-colors cursor-pointer ${
              isForensic
                ? 'bg-emerald-950/10 dark:bg-[var(--forensic-accent)]/20 text-[#044E38] dark:text-[var(--forensic-accent)]'
                : 'text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:text-[#044E38] dark:hover:text-[var(--forensic-text-primary)]'
            }`}
          >
            Forensic
          </button>
          <button
            onClick={() => setMode('sanitization')}
            className={`px-3 py-1 text-[10px] font-industrial font-bold tracking-wider uppercase transition-colors cursor-pointer ${
              !isForensic
                ? 'bg-red-950/10 dark:bg-[var(--sanitize-accent)]/20 text-[#680E18] dark:text-[var(--sanitize-accent)]'
                : 'text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:text-[#680E18] dark:hover:text-[var(--sanitize-text-primary)]'
            }`}
          >
            Sanitize
          </button>
        </div>
      </div>
    </header>
  );
};
