import React, { useState, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { AlertTriangle, ShieldAlert, CheckCircle, X } from 'lucide-react';
import { GradientDots } from '../ui/gradient-dots';
import { motion, AnimatePresence } from 'framer-motion';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { mode, activeScreen, pendingModeSwitch, confirmModeSwitch, cancelModeSwitch } = useApp();
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
    <div className={`w-full h-screen flex flex-col overflow-hidden relative select-none ${isForensic ? 'forensic-mode' : 'app-bg'}`}>
      <GradientDots />

      {/* Top Application Header */}
      <Header />

      {/* Main Container */}
      <div
        data-mode={currentMode}
        style={{ background: 'var(--bg)', color: 'var(--text)' }}
        className="flex-1 flex overflow-hidden z-10 relative"
      >
        {/* Left Navigation Sidebar */}
        <Sidebar />

        {/* Center Main Screen Viewport with 960px centering constraint & page transitions */}
        <main
          data-mode={currentMode}
          style={{ background: 'var(--bg)', color: 'var(--text)' }}
          className="flex-1 overflow-y-auto"
        >
          <div className="max-w-[960px] mx-auto px-8 py-8">
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
        className={`h-5 px-6 flex items-center justify-between font-mono text-[9px] z-40 ${
          isForensic
            ? 'bg-[var(--forensic-navbar-bg)] border-t border-[var(--forensic-border)] text-[var(--forensic-text-secondary)]'
            : 'border-t border-[rgba(89,238,153,0.04)] bg-[rgba(0,18,11,0.9)] text-[#D8E4FF]/25'
        }`}
      >
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#59EE99] opacity-75 shadow-[0_0_4px_#59EE99]" />
          <span className={isForensic ? 'text-[var(--forensic-text-primary)] font-bold' : ''}>AIRGAP VERIFIED</span>
        </div>
        <div>{timeStr || 'UTC'}</div>
      </footer>

      {/* Mode Switch Intercept Modal */}
      {pendingModeSwitch === 'sanitization' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[var(--surface)] border border-[#EF4444]/40 rounded-2xl p-6 shadow-[0_0_50px_rgba(239,68,68,0.3)] space-y-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 bg-[rgba(239,68,68,0.15)] text-[#EF4444] border border-[#EF4444]/40 rounded-xl">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-mono font-bold text-[#EF4444] tracking-wide">
                    ATTENTION: ENTERING SANITIZATION MODE
                  </h3>
                  <p className="text-[11px] text-[var(--text)]/40 font-sans">
                    Part VIII — Destructive Operation Protocol
                  </p>
                </div>
              </div>
              <button
                onClick={cancelModeSwitch}
                className="text-[var(--text)]/40 hover:text-[var(--text)] p-1 rounded-lg hover:bg-[var(--primary)]/10"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 rounded-xl bg-[rgba(239,68,68,0.08)] border border-[#EF4444]/30 text-[11px] text-[var(--text)]/80 leading-relaxed space-y-2 font-sans">
              <p>
                You are transitioning from <strong>Forensic Mode</strong> (where all connected drives are guarded by read-only block source wrappers) to <strong>Sanitization Mode</strong>.
              </p>
              <div className="p-2.5 rounded bg-[rgba(239,68,68,0.15)] border border-[#EF4444]/40 flex items-start space-x-2 text-[10px] font-mono text-[#EF4444]">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>
                  Operations executed in Sanitization Mode are permanent and irrecoverable. The system-disk hard block and two-phase authorization gate will remain strictly enforced.
                </span>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={cancelModeSwitch}
                className="px-3.5 py-1.5 rounded-lg text-[11px] font-mono text-[var(--text)]/70 hover:bg-[var(--primary)]/10 border border-[var(--border)] transition-colors"
              >
                Cancel (Stay in Forensic Mode)
              </button>
              <button
                onClick={confirmModeSwitch}
                className="px-4 py-1.5 rounded-lg text-[11px] font-mono font-bold bg-[#EF4444] hover:bg-[#f55] text-[var(--text)] shadow-[0_0_16px_rgba(239,68,68,0.4)] flex items-center space-x-2 transition-all cursor-pointer"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Authorize & Enter Sanitization Mode</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
