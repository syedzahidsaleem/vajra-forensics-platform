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
  const { mode, activeScreen, setActiveScreen, setMode } = useApp();
  const isForensic = mode === 'forensic';

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
    <aside className="w-[180px] h-full flex flex-col bg-[var(--surface)]/70 border-r border-[var(--border)]/20 py-4 select-none shrink-0 z-30 text-[var(--text)]">
      {/* Section label */}
      <p className="px-4 mb-3 text-[9px] font-mono text-[var(--text)]/40 uppercase tracking-[0.15em]">
        {isForensic ? 'Forensic Workflows' : 'Destructive Workflows'}
      </p>

      {/* Nav links */}
      <nav className="space-y-0.5">
        {currentNav.map((item) => {
          const isActive = activeScreen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveScreen(item.id)}
              className={`
                w-full flex items-center gap-3 px-4 py-2.5 text-[11px] font-sans text-left transition-all duration-150 cursor-pointer
                ${
                  isActive
                    ? 'text-[var(--primary)] bg-[var(--primary)]/10 border-l-2 border-[var(--primary)] shadow-[-4px_0_12px_rgba(0,0,0,0.1)] font-semibold'
                    : 'text-[var(--text)]/60 hover:text-[var(--text)] hover:bg-[var(--primary)]/5 border-l-2 border-transparent'
                }
              `}
            >
              <span className={isActive ? 'text-[var(--primary)]' : 'text-[var(--text)]/50'}>
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
                ? 'bg-[#59EE99] shadow-[0_0_5px_#59EE99]'
                : 'bg-[#EF4444] shadow-[0_0_5px_#EF4444]'
            }`}
          />
          <span
            className={`text-[9px] font-mono uppercase tracking-wider ${
              isForensic ? 'text-[#59EE99]/70' : 'text-[#EF4444]/70'
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
                : 'border-[#59EE99]/30 text-[#59EE99]/70 hover:border-[#59EE99]/60 hover:text-[#59EE99] hover:bg-[rgba(89,238,153,0.05)]'
            }
          `}
        >
          {isForensic ? 'Switch to Sanitize' : 'Switch to Forensic'}
        </button>
      </div>
    </aside>
  );
};
