import React, { useState, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { AlertTriangle, ShieldAlert, CheckCircle, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { mode, activeScreen, setActiveScreen, pendingModeSwitch, confirmModeSwitch, cancelModeSwitch } = useApp();
  const isForensic = mode === 'forensic';
  const [timeStr, setTimeStr] = useState<string>('');
  const currentMode = mode === 'sanitization' ? 'sanitize' : 'forensic';

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-mode', currentMode);
  }, [currentMode]);

  return (
    <div
      className={`w-full h-screen flex flex-col overflow-hidden relative select-none ${isForensic ? 'forensic-mode' : 'sanitize-mode'}`}
      style={{ background: isForensic ? 'var(--forensic-page-bg, var(--bg))' : 'var(--sanitize-page-bg, var(--bg))', color: 'var(--text)' }}
    >
      {/* Top Application Header */}
      <Header />

      {/* Main Container */}
      <div
        style={{ color: 'var(--text)' }}
        className="flex-1 flex overflow-hidden z-10 relative bg-transparent"
      >
        {/* Left Navigation Sidebar */}
        <Sidebar />

        {/* Center Main Screen Viewport with centering constraint & page transitions */}
        <main
          style={{ color: 'var(--text)', scrollbarGutter: 'stable' }}
          className="flex-1 min-w-0 overflow-y-auto bg-transparent"
        >
          <div className="max-w-[1400px] w-full mx-auto px-4 sm:px-8 py-6 sm:py-8 pb-16">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeScreen}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
              >
                {children}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>

      {/* Bottom Status Bar Footer */}
      <footer
        className={`h-6 px-4 sm:px-6 flex items-center justify-between font-mono text-[9px] z-40 ${
          isForensic
            ? 'bg-[var(--forensic-navbar-bg)] border-t border-[var(--forensic-border)] text-[var(--forensic-text-secondary)] font-semibold'
            : 'bg-[var(--sanitize-navbar-bg)] border-t border-[var(--sanitize-border)] text-[var(--sanitize-text-secondary)] font-semibold'
        }`}
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-sm rotate-45 bg-[#05664B] dark:bg-[#59EE99] opacity-90 shadow-[0_0_4px_rgba(5,102,75,0.3)] dark:shadow-[0_0_4px_#59EE99]" />
            <span className={isForensic ? 'text-[var(--forensic-text-primary)] font-bold' : 'text-[var(--sanitize-text-primary)] font-bold'}>
              AIRGAP VERIFIED
            </span>
          </div>
          <span className="text-[var(--border)] hidden sm:inline">|</span>
          <span className={isForensic ? 'text-[var(--forensic-text-secondary)] font-medium hidden sm:inline' : 'text-[var(--sanitize-text-secondary)] font-medium hidden sm:inline'}>vajra-forensics.org</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveScreen('privacy')}
            className={`hover:underline cursor-pointer ${activeScreen === 'privacy' ? 'font-bold text-[var(--text)]' : ''}`}
          >
            Privacy Policy
          </button>
          <span className="text-[var(--border)]">|</span>
          <button
            onClick={() => setActiveScreen('terms')}
            className={`hover:underline cursor-pointer ${activeScreen === 'terms' ? 'font-bold text-[var(--text)]' : ''}`}
          >
            Terms & Conditions
          </button>
          <span className="text-[var(--border)]">|</span>
          <div>{timeStr || 'UTC'}</div>
        </div>
      </footer>

      {/* Mode Switch Intercept Modal */}
      {pendingModeSwitch === 'sanitization' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[var(--surface)] border border-[#DC2626]/40 dark:border-[#EF4444]/40 rounded-2xl p-6 shadow-2xl space-y-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 bg-red-100 dark:bg-[rgba(239,68,68,0.15)] text-[#DC2626] dark:text-[#EF4444] border border-red-300 dark:border-[#EF4444]/40 rounded-xl">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-industrial font-black text-[#DC2626] dark:text-[#EF4444] tracking-wide uppercase">
                    ATTENTION: ENTERING SANITIZATION MODE
                  </h3>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 font-sans font-medium">
                    Part VIII: Destructive Operation Protocol
                  </p>
                </div>
              </div>
              <button
                onClick={cancelModeSwitch}
                className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white p-1 rounded-lg hover:bg-slate-200/60 dark:hover:bg-white/10 transition-colors cursor-pointer"
                title="Cancel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 rounded-xl bg-red-50/70 dark:bg-[rgba(239,68,68,0.08)] border border-red-200 dark:border-[#EF4444]/30 text-xs text-slate-800 dark:text-slate-200 leading-relaxed space-y-3 font-sans">
              <p>
                You are transitioning from <strong className="text-slate-950 dark:text-white font-bold">Forensic Mode</strong> (where all connected drives are guarded by read-only block source wrappers) to <strong className="text-[#DC2626] dark:text-[#FF6B7A] font-bold">Sanitization Mode</strong>.
              </p>
              <div className="p-3 rounded-lg bg-red-100/70 dark:bg-[rgba(239,68,68,0.18)] border border-red-300 dark:border-[#EF4444]/50 flex items-start space-x-2.5 text-[11px] font-mono text-[#991B1B] dark:text-[#FCA5A5] leading-normal">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-[#DC2626] dark:text-[#EF4444]" />
                <span>
                  Operations executed in Sanitization Mode are permanent and irrecoverable. The system-disk hard block and two-phase authorization gate will remain strictly enforced.
                </span>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={cancelModeSwitch}
                className="px-4 py-2 rounded-lg text-xs font-mono font-semibold text-slate-800 dark:text-slate-200 hover:text-slate-950 dark:hover:text-white bg-white/70 dark:bg-white/5 hover:bg-white dark:hover:bg-white/10 border border-slate-300 dark:border-white/20 transition-all cursor-pointer shadow-sm select-none"
              >
                Cancel (Stay in Forensic Mode)
              </button>
              <button
                onClick={confirmModeSwitch}
                className="px-4 py-2 rounded-lg text-xs font-mono font-bold bg-[#EF4444] hover:bg-[#DC2626] text-white shadow-[0_0_16px_rgba(239,68,68,0.4)] flex items-center space-x-2 transition-all cursor-pointer select-none"
              >
                <CheckCircle className="w-4 h-4 text-white shrink-0" />
                <span className="text-white font-bold">Authorize & Enter Sanitization Mode</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
