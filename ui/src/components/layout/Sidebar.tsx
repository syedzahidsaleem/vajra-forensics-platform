import React from 'react';
import { useApp } from '../../context/AppContext';
import { ScreenId } from '../../types';
import {
  LayoutDashboard,
  HardDrive,
  Download,
  Search,
  Binary,
  FileText,
  AlertTriangle,
} from 'lucide-react';

interface NavItem {
  id: ScreenId;
  label: string;
  icon: React.ReactNode;
}

export const Sidebar: React.FC = () => {
  const { mode, activeScreen, setActiveScreen, setMode, sidebarOpen } = useApp();
  const isForensic = mode === 'forensic';

  if (!sidebarOpen) {
    return null;
  }

  const forensicNav: NavItem[] = [
    { id: 'dashboard', label: 'Case Dashboard', icon: <LayoutDashboard className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'devices', label: 'Storage Devices', icon: <HardDrive className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'acquisition', label: 'Acquisition Wizard', icon: <Download className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'recovery', label: 'Recovery Browser', icon: <Search className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'hex', label: 'Hex Data Explorer', icon: <Binary className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'reports', label: 'Report Center', icon: <FileText className="w-3.5 h-3.5 shrink-0" /> },
  ];

  const sanitizationNav: NavItem[] = [
    { id: 'sanitization', label: 'Sanitization Console', icon: <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'devices', label: 'Target Devices', icon: <HardDrive className="w-3.5 h-3.5 shrink-0" /> },
    { id: 'reports', label: 'Sanitization Certs', icon: <FileText className="w-3.5 h-3.5 shrink-0" /> },
  ];

  const currentNav = isForensic ? forensicNav : sanitizationNav;

  return (
    <aside
      className={`w-[180px] h-full flex flex-col py-4 select-none shrink-0 z-30 ${
        isForensic
          ? 'bg-[var(--forensic-sidebar-bg)] border-r border-[var(--forensic-border)]'
          : 'bg-[var(--sanitize-sidebar-bg)] border-r border-[var(--sanitize-border)]'
      }`}
    >
      {/* Section label: Static Text Label */}
      <div
        className={`px-3 mb-2 text-[10px] font-industrial uppercase tracking-[0.2em] font-black select-none ${
          isForensic ? 'text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)]' : 'text-[#680E18] dark:text-[var(--sanitize-accent)]'
        }`}
      >
        {isForensic ? 'Forensic Workflows' : 'Destructive Workflows'}
      </div>

      {/* Navigation items */}
      <nav className="flex-1 space-y-1 px-2">
        {currentNav.map((item) => {
          const isActive = activeScreen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveScreen(item.id)}
              className={`
                w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-sans text-left transition-colors cursor-pointer
                ${
                  isActive
                    ? isForensic
                      ? 'bg-[#05664B]/10 dark:bg-[#38C193]/20 text-[#05664B] dark:text-[#38C193] font-bold border border-[#05664B]/30 dark:border-[#38C193]/30'
                      : 'bg-red-900/10 dark:bg-red-500/20 text-[#680E18] dark:text-[#FF7B88] font-bold border border-red-600/30 dark:border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.15)]'
                    : isForensic
                    ? 'font-semibold text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:bg-[var(--border)]/20 hover:text-[var(--forensic-text-primary)] border border-transparent'
                    : 'font-semibold text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:bg-[var(--border)]/20 hover:text-[var(--sanitize-text-primary)] border border-transparent'
                }
              `}
            >
              <span
                className={
                  isActive
                    ? isForensic
                      ? 'text-[#05664B] dark:text-[#38C193]'
                      : 'text-[#680E18] dark:text-[#FF7B88]'
                    : isForensic
                    ? 'text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)]'
                    : 'text-[#7A222C] dark:text-[var(--sanitize-text-secondary)]'
                }
              >
                {item.icon}
              </span>
              <span
                className={`truncate font-bold ${
                  isActive
                    ? isForensic
                      ? 'text-[#05664B] dark:text-[#38C193]'
                      : 'text-[#680E18] dark:text-[#FF7B88]'
                    : isForensic
                    ? 'text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)]'
                    : 'text-[#7A222C] dark:text-[var(--sanitize-text-secondary)]'
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Bottom section: Safety Engine & Slim Switch Button */}
      <div className="mt-auto px-3 pb-2 space-y-3">
        {/* Compliance / Legal Links */}
        <div className="pt-2 border-t border-[var(--border)]/30 flex flex-col gap-1 text-[10px] font-sans">
          <button
            onClick={() => setActiveScreen('privacy')}
            className={`text-left px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
              activeScreen === 'privacy'
                ? isForensic
                  ? 'text-[#05664B] dark:text-[#38C193] font-bold'
                  : 'text-[#680E18] dark:text-[#FF7B88] font-bold'
                : isForensic
                ? 'font-medium text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:text-[var(--text)]'
                : 'font-medium text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            Privacy Policy
          </button>
          <button
            onClick={() => setActiveScreen('terms')}
            className={`text-left px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
              activeScreen === 'terms'
                ? isForensic
                  ? 'text-[#05664B] dark:text-[#38C193] font-bold'
                  : 'text-[#680E18] dark:text-[#FF7B88] font-bold'
                : isForensic
                ? 'font-medium text-[#0D3B2E] dark:text-[var(--forensic-text-secondary)] hover:text-[var(--text)]'
                : 'font-medium text-[#7A222C] dark:text-[var(--sanitize-text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            Terms & Conditions
          </button>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-sm rotate-45 shrink-0 ${
              isForensic
                ? 'bg-[#05664B] dark:bg-[var(--forensic-accent)] shadow-[0_0_6px_rgba(5,102,75,0.3)] dark:shadow-[0_0_6px_var(--forensic-accent)]'
                : 'bg-[#680E18] dark:bg-[var(--sanitize-accent)] shadow-[0_0_6px_var(--sanitize-accent)]'
            }`}
          />
          <span
            className={`text-[9px] font-industrial font-bold uppercase tracking-widest ${
              isForensic
                ? 'text-[#05664B] dark:text-[var(--forensic-accent)]'
                : 'text-[#680E18] dark:text-[var(--sanitize-accent)]'
            }`}
          >
            {isForensic ? 'Safety Active' : 'Sanitizer Armed'}
          </span>
        </div>

        <button
          onClick={() => setMode(isForensic ? 'sanitization' : 'forensic')}
          className={`
            w-full py-1.5 rounded-md border font-industrial font-bold text-[10px] tracking-wider uppercase transition-all duration-200 cursor-pointer
            ${
              isForensic
                ? 'border-[rgba(168,40,58,0.4)] text-[#680E18] dark:text-[var(--sanitize-accent)] hover:border-[var(--sanitize-accent)] hover:bg-[var(--sanitize-accent)]/10'
                : 'border-[#05664B]/40 text-[#05664B] dark:text-[var(--forensic-accent)] hover:border-[#05664B] hover:bg-[#05664B]/10'
            }
          `}
        >
          {isForensic ? 'Switch to Sanitize' : 'Switch to Forensic'}
        </button>
      </div>
    </aside>
  );
};
