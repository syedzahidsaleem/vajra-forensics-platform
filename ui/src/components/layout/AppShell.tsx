import React, { useState, useEffect, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { AlertTriangle, ShieldAlert, CheckCircle, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTheme } from '../../context/ThemeContext';
import { HoverButton } from '../ui/hover-glow-button';

const DECRYPT_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function generateDecryptTexture(length = 2600): string {
  let result = '';
  let chunkCount = 0;
  for (let i = 0; i < length; i++) {
    if (chunkCount === 5) {
      result += ' ';
      chunkCount = 0;
    } else {
      result += DECRYPT_CHARS[Math.floor(Math.random() * DECRYPT_CHARS.length)];
      chunkCount++;
    }
  }
  return result;
}

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { mode, activeScreen, setActiveScreen, pendingModeSwitch, confirmModeSwitch, cancelModeSwitch } = useApp();
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const isForensic = mode === 'forensic';
  const [timeStr, setTimeStr] = useState<string>('');
  const currentMode = mode === 'sanitization' ? 'sanitize' : 'forensic';

  // Decrypt texture state & handlers for Sanitization Mode confirmation modal
  const modalCardRef = useRef<HTMLDivElement>(null);
  const glowIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [isHoveringModal, setIsHoveringModal] = useState(false);
  const [dimTexture] = useState(() => generateDecryptTexture(2600));
  const [glowTexture, setGlowTexture] = useState(() => generateDecryptTexture(2600));

  const startGlowLoop = () => {
    setIsHoveringModal(true);
    if (!glowIntervalRef.current) {
      setGlowTexture(generateDecryptTexture(2600));
      glowIntervalRef.current = setInterval(() => {
        setGlowTexture(generateDecryptTexture(2600));
      }, 80);
    }
  };

  const stopGlowLoop = () => {
    setIsHoveringModal(false);
    if (glowIntervalRef.current) {
      clearInterval(glowIntervalRef.current);
      glowIntervalRef.current = null;
    }
  };

  const updateCursorPos = (clientX: number, clientY: number) => {
    if (!modalCardRef.current) return;
    const rect = modalCardRef.current.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const x = Math.max(0, Math.min(100, ((clientX - rect.left) / rect.width) * 100));
    const y = Math.max(0, Math.min(100, ((clientY - rect.top) / rect.height) * 100));
    modalCardRef.current.style.setProperty('--mx', `${x.toFixed(2)}%`);
    modalCardRef.current.style.setProperty('--my', `${y.toFixed(2)}%`);
  };

  const handleModalMouseEnter = (e: React.MouseEvent<HTMLDivElement>) => {
    startGlowLoop();
    updateCursorPos(e.clientX, e.clientY);
  };

  const handleModalMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    updateCursorPos(e.clientX, e.clientY);
  };

  const handleModalMouseLeave = () => {
    stopGlowLoop();
  };

  const handleModalTouchStart = (e: React.TouchEvent<HTMLDivElement>) => {
    if (e.touches[0]) {
      startGlowLoop();
      updateCursorPos(e.touches[0].clientX, e.touches[0].clientY);
    }
  };

  const handleModalTouchMove = (e: React.TouchEvent<HTMLDivElement>) => {
    if (e.touches[0]) {
      updateCursorPos(e.touches[0].clientX, e.touches[0].clientY);
    }
  };

  const handleModalTouchEnd = () => {
    stopGlowLoop();
  };

  useEffect(() => {
    if (pendingModeSwitch !== 'sanitization') {
      stopGlowLoop();
    }
  }, [pendingModeSwitch]);

  useEffect(() => {
    return () => {
      if (glowIntervalRef.current) {
        clearInterval(glowIntervalRef.current);
        glowIntervalRef.current = null;
      }
    };
  }, []);

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
            <span className="w-1.5 h-1.5 rounded-sm rotate-45 bg-[#05664B] dark:bg-[#38C193] opacity-90 shadow-[0_0_4px_rgba(5,102,75,0.3)] dark:shadow-[0_0_4px_#38C193]" />
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div
            ref={modalCardRef}
            data-hovered={isHoveringModal}
            onMouseMove={handleModalMouseMove}
            onMouseEnter={handleModalMouseEnter}
            onMouseLeave={handleModalMouseLeave}
            onTouchStart={handleModalTouchStart}
            onTouchMove={handleModalTouchMove}
            onTouchEnd={handleModalTouchEnd}
            style={{
              background: isDark
                ? 'linear-gradient(145deg, #0d161d 0%, #070e12 100%)'
                : 'linear-gradient(145deg, #ffffff 0%, #fdf7f7 100%)',
              border: isDark ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(239, 68, 68, 0.35)',
              boxShadow: isDark
                ? '0 25px 60px -15px rgba(0, 0, 0, 0.9), 0 0 40px -10px rgba(239, 68, 68, 0.3)'
                : '0 25px 60px -15px rgba(239, 68, 68, 0.15)',
            }}
            className="modal-decrypt-card w-full max-w-lg rounded-2xl p-6 sm:p-7 relative overflow-hidden"
          >
            {/* Top Red Accent Glow Line in Dark Mode */}
            {isDark && (
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-[#EF4444] to-transparent shadow-[0_0_10px_#EF4444] z-[2]" />
            )}

            {/* Sibling Texture Layer 1: Static Dim Monospace Texture */}
            <div className="bg-texture-dim" aria-hidden="true">
              {dimTexture}
            </div>

            {/* Sibling Texture Layer 2: Interactive Dynamic Glow Monospace Texture with Spotlight Mask */}
            <div className="bg-texture-glow" aria-hidden="true">
              {glowTexture}
            </div>

            {/* Wrapped Content Container with position: relative; z-index: 1 */}
            <div className="relative z-[1] space-y-5">
              {/* Modal Header */}
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <div
                    className={`p-2.5 rounded-xl border flex items-center justify-center shrink-0 ${
                      isDark
                        ? 'bg-red-500/15 border-red-500/40 text-[#FF7B88] shadow-[0_0_15px_rgba(239,68,68,0.25)]'
                        : 'bg-red-100 border-red-300 text-[#DC2626]'
                    }`}
                  >
                    <ShieldAlert className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-base sm:text-lg font-industrial font-black text-[#DC2626] dark:text-[#FF7B88] tracking-wider uppercase leading-tight">
                      ATTENTION: ENTERING SANITIZATION MODE
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono font-medium mt-0.5 tracking-wide">
                      Part VIII: Destructive Operation Protocol
                    </p>
                  </div>
                </div>
                <button
                  onClick={cancelModeSwitch}
                  className="text-slate-400 hover:text-slate-200 dark:hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
                  title="Cancel"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Modal Body Container */}
              <div
                style={{
                  background: isDark ? '#0c141a' : '#FFFFFF',
                  border: isDark ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid rgba(254, 202, 202, 0.8)',
                }}
                className="p-4 sm:p-5 rounded-xl text-xs leading-relaxed space-y-3 font-sans shadow-md"
              >
                <p className={isDark ? 'text-slate-300' : 'text-slate-700'}>
                  You are transitioning from{' '}
                  <strong className={isDark ? 'text-[#38C193] font-bold' : 'text-[#05664B] font-bold'}>
                    Forensic Mode
                  </strong>{' '}
                  (where all connected drives are guarded by read-only block source wrappers) to{' '}
                  <strong className={isDark ? 'text-[#FF7B88] font-bold' : 'text-[#DC2626] font-bold'}>
                    Sanitization Mode
                  </strong>.
                </p>

                {/* Warning Callout Box */}
                <div
                  style={{
                    background: isDark ? '#1a0709' : '#FEF2F2',
                    border: isDark ? '1px solid rgba(239, 68, 68, 0.35)' : '1px solid rgba(252, 165, 165, 0.9)',
                  }}
                  className="p-3 sm:p-3.5 rounded-lg flex items-start space-x-2.5 text-[11px] font-mono leading-normal"
                >
                  <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${isDark ? 'text-[#FF7B88]' : 'text-[#DC2626]'}`} />
                  <span className={isDark ? 'text-red-200' : 'text-[#991B1B]'}>
                    Operations executed in Sanitization Mode are permanent and irrecoverable. The system-disk hard block and two-phase authorization gate will remain strictly enforced.
                  </span>
                </div>
              </div>

              {/* Modal Footer / Actions */}
              <div className="flex items-center justify-end space-x-3 pt-2 relative z-20">
                <button
                  onClick={cancelModeSwitch}
                  className={`relative z-10 px-4 py-2.5 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer shadow-md select-none ${
                    isDark
                      ? 'text-slate-200 hover:text-white bg-[#0f1722] hover:bg-[#182434] border border-white/20'
                      : 'text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-100 border border-slate-300'
                  }`}
                >
                  Cancel (Stay in Forensic Mode)
                </button>

                <HoverButton
                  onClick={confirmModeSwitch}
                  glowColor="#EF4444"
                  backgroundColor={isDark ? '#8F1E28' : '#DC2626'}
                  textColor="#FFFFFF"
                  hoverTextColor="#FFFFFF"
                  className={`!text-xs !px-5 !py-2.5 border relative z-10 ${
                    isDark ? 'border-red-500/60 shadow-[0_0_20px_rgba(239,68,68,0.35)]' : 'border-red-600 shadow-md hover:bg-red-600'
                  } font-industrial font-black uppercase tracking-wider inline-flex items-center gap-2 cursor-pointer select-none`}
                >
                  <CheckCircle className="w-4 h-4 shrink-0" />
                  <span>Authorize & Enter Sanitization Mode</span>
                </HoverButton>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
