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
        className={`px-3 mb-2 text-[10px] font-industrial uppercase tracking-[0.2em] font-bold select-none ${
          isForensic ? 'text-[var(--forensic-text-secondary)]/80' : 'text-[#FCA5A5]'
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
                      ? 'bg-[rgba(13,184,211,0.15)] text-[var(--forensic-accent)] font-semibold border border-[var(--forensic-border)]'
                      : 'bg-[rgba(255,59,59,0.2)] text-[#FCA5A5] font-semibold border border-[rgba(255,107,122,0.4)] shadow-[0_0_10px_rgba(239,68,68,0.15)]'
                    : isForensic
                    ? 'text-[var(--forensic-text-secondary)] hover:bg-[var(--border)]/20 hover:text-[var(--forensic-text-primary)] border border-transparent'
                    : 'text-[var(--sanitize-text-secondary)] hover:bg-[var(--border)]/20 hover:text-[#FDEDEC] border border-transparent'
                }
              `}
            >
              <span className={isActive ? (isForensic ? 'text-[var(--forensic-accent)]' : 'text-[#FCA5A5]') : (isForensic ? 'text-[var(--forensic-text-secondary)]/60' : 'text-[var(--sanitize-text-secondary)]')}>
                {item.icon}
              </span>
              <span className="truncate">{item.label}</span>
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
            className={`text-left px-1.5 py-0.5 rounded transition-colors ${
              activeScreen === 'privacy'
                ? isForensic ? 'text-[var(--forensic-accent)] font-bold' : 'text-[#FCA5A5] font-bold'
                : 'text-[var(--forensic-text-secondary)]/60 hover:text-[var(--text)]'
            }`}
          >
            Privacy Policy
          </button>
          <button
            onClick={() => setActiveScreen('terms')}
            className={`text-left px-1.5 py-0.5 rounded transition-colors ${
              activeScreen === 'terms'
                ? isForensic ? 'text-[var(--forensic-accent)] font-bold' : 'text-[#FCA5A5] font-bold'
                : 'text-[var(--forensic-text-secondary)]/60 hover:text-[var(--text)]'
            }`}
          >
            Terms & Conditions
          </button>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-sm rotate-45 shrink-0 ${
              isForensic
                ? 'bg-[var(--forensic-accent)] shadow-[0_0_6px_var(--forensic-accent)]'
                : 'bg-[#FF7B88] shadow-[0_0_6px_#FF7B88]'
            }`}
          />
          <span
            className={`text-[9px] font-industrial font-bold uppercase tracking-widest ${
              isForensic ? 'text-[var(--forensic-accent)]' : 'text-[#FCA5A5]'
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
                ? 'border-[#EF4444]/40 text-[#EF4444] hover:border-[#EF4444] hover:bg-[rgba(239,68,68,0.1)]'
                : 'border-[var(--forensic-accent)]/40 text-[var(--forensic-accent)] hover:border-[var(--forensic-accent)] hover:bg-[rgba(13,184,211,0.1)]'
            }
          `}
        >
          {isForensic ? 'Switch to Sanitize' : 'Switch to Forensic'}
        </button>
      </div>
    </aside>
  );
};
