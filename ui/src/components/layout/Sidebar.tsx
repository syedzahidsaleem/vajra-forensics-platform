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
          ? 'bg-[rgba(15,36,48,0.45)] border-r border-[var(--forensic-border)]'
          : 'bg-[rgba(0,18,11,0.6)] border-r border-[rgba(89,238,153,0.04)]'
      }`}
    >
      {/* Section label — Static Text Label */}
      <div className="px-3 mb-2 text-[9px] font-mono uppercase tracking-[0.15em] text-[var(--text)]/40 font-semibold select-none">
        {isForensic ? 'Forensic Workflows' : 'Destructive Workflows'}
      </div>

      {/* Nav links — Flat Button Style */}
      <nav className="space-y-1 px-2">
        {currentNav.map((item) => {
          const isActive = activeScreen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveScreen(item.id)}
              className={`
                w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans text-left transition-colors cursor-pointer
                ${
                  isActive
                    ? 'bg-[var(--surface)] text-[var(--primary-text)] font-semibold border border-[var(--border)]/40'
                    : 'text-[var(--text)]/70 hover:bg-[var(--surface)]/50 hover:text-[var(--text)] border border-transparent'
                }
              `}
            >
              <span className={isActive ? 'text-[var(--primary-text)]' : 'text-[var(--text)]/50'}>
                {item.icon}
              </span>
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Bottom section — Safety Engine & Slim Switch Button */}
      <div className="mt-auto px-4 pb-2">
        <div className="flex items-center gap-2 mb-3">
          <span
            className={`w-1.5 h-1.5 rounded-full animate-pulse shrink-0 ${
              isForensic
                ? 'bg-[var(--forensic-accent)] shadow-[0_0_5px_var(--forensic-accent)]'
                : 'bg-[#EF4444] shadow-[0_0_5px_#EF4444]'
            }`}
          />
          <span
            className={`text-[9px] font-mono uppercase tracking-wider ${
              isForensic ? 'text-[var(--forensic-accent)]' : 'text-[#EF4444]/70'
            }`}
          >
            {isForensic ? 'Safety Active' : 'Sanitizer Armed'}
          </span>
        </div>

        <button
          onClick={() => setMode(isForensic ? 'sanitization' : 'forensic')}
          className={`
            w-full py-1.5 rounded border font-mono text-[10px] tracking-wider uppercase transition-all duration-200 cursor-pointer
            ${
              isForensic
                ? 'border-[#EF4444]/30 text-[#EF4444]/70 hover:border-[#EF4444]/60 hover:text-[#EF4444] hover:bg-[rgba(239,68,68,0.05)]'
                : 'border-[var(--forensic-accent)]/30 text-[var(--forensic-accent)] hover:border-[var(--forensic-accent)] hover:bg-[rgba(13,184,211,0.1)]'
            }
          `}
        >
          {isForensic ? 'Switch to Sanitize' : 'Switch to Forensic'}
        </button>
      </div>
    </aside>
  );
};
