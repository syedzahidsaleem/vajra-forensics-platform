import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

/* ─────────────────────────────────────────
   1. ANIMATED COUNTER
   For: confidence scores, sector counts, % sanitized
───────────────────────────────────────── */
interface AnimatedCounterProps {
  value: number;
  decimals?: number;
  suffix?: string;
  prefix?: string;
  className?: string;
  glowColor?: 'green' | 'amethyst' | 'red';
}

export function AnimatedCounter({
  value,
  decimals = 0,
  suffix = '',
  prefix = '',
  className = '',
  glowColor,
}: AnimatedCounterProps) {
  const [display, setDisplay] = React.useState(0);

  React.useEffect(() => {
    let start = display;
    const end = value;
    const duration = 800;
    const startTime = performance.now();

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(start + (end - start) * eased);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value]);

  const glowStyle =
    glowColor === 'green'
      ? { color: '#59EE99', textShadow: '0 0 12px rgba(89,238,153,0.5)' }
      : glowColor === 'amethyst'
      ? { color: '#AA77A9', textShadow: '0 0 12px rgba(170,119,169,0.5)' }
      : glowColor === 'red'
      ? { color: '#EF4444', textShadow: '0 0 12px rgba(239,68,68,0.5)' }
      : {};

  return (
    <span
      className={`font-mono tabular-nums ${className}`}
      style={glowStyle}
    >
      {prefix}{display.toFixed(decimals)}{suffix}
    </span>
  );
}

/* ─────────────────────────────────────────
   2. GLOW BUTTON
   For: primary CTAs — Acquire Image, Generate Report, Run Pipeline
───────────────────────────────────────── */
interface GlowButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  loading?: boolean;
}

export function GlowButton({
  variant = 'primary',
  size = 'md',
  icon,
  loading = false,
  children,
  className = '',
  disabled,
  ...props
}: GlowButtonProps) {
  const base =
    'relative inline-flex items-center gap-2 font-mono font-semibold tracking-wide rounded-md transition-all duration-200 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed select-none';

  const sizes = {
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2 text-xs',
    lg: 'px-6 py-3 text-sm',
  };

  const variants = {
    primary: `
      bg-[#59EE99] text-[#00120B]
      hover:bg-[#6fffaa]
      shadow-[0_0_0_0_rgba(89,238,153,0)]
      hover:shadow-[0_0_20px_rgba(89,238,153,0.5),0_0_40px_rgba(89,238,153,0.2)]
      active:shadow-[0_0_8px_rgba(89,238,153,0.3)]
    `,
    danger: `
      bg-[#EF4444] text-white
      hover:bg-[#f55]
      shadow-[0_0_0_0_rgba(239,68,68,0)]
      hover:shadow-[0_0_20px_rgba(239,68,68,0.5),0_0_40px_rgba(239,68,68,0.2)]
      border border-[#EF4444]
    `,
    ghost: `
      bg-transparent text-[var(--text)]
      border border-[var(--border)]/40
      hover:border-[#59EE99]/50 hover:text-[#59EE99]
      hover:bg-[#59EE99]/5
    `,
    outline: `
      bg-transparent text-[#59EE99]
      border border-[#59EE99]/40
      hover:border-[#59EE99] hover:bg-[#59EE99]/8
      hover:shadow-[0_0_12px_rgba(89,238,153,0.2)]
    `,
  };

  return (
    <motion.button
      whileTap={{ scale: 0.97 }}
      className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
      disabled={disabled || loading}
      {...(props as any)}
    >
      {loading ? (
        <OrbitalSpinner size={14} />
      ) : icon ? (
        <span className="shrink-0">{icon}</span>
      ) : null}
      {children}
    </motion.button>
  );
}

/* ─────────────────────────────────────────
   3. ORBITAL SPINNER
   For: recovery pipeline loading, sector loading, report generation
───────────────────────────────────────── */
interface OrbitalSpinnerProps {
  size?: number;
  color?: string;
}

export function OrbitalSpinner({
  size = 24,
  color = '#59EE99',
}: OrbitalSpinnerProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className="shrink-0"
    >
      <motion.circle
        cx="12"
        cy="12"
        r="9"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeDasharray="20 40"
        animate={{ rotate: 360 }}
        transition={{ duration: 1, ease: 'linear', repeat: Infinity }}
        style={{ transformOrigin: '12px 12px' }}
      />
      <motion.circle
        cx="12"
        cy="12"
        r="5"
        stroke={color}
        strokeWidth="1"
        strokeOpacity="0.4"
        strokeDasharray="10 20"
        animate={{ rotate: -360 }}
        transition={{ duration: 1.5, ease: 'linear', repeat: Infinity }}
        style={{ transformOrigin: '12px 12px' }}
      />
      <circle cx="12" cy="12" r="2" fill={color} opacity="0.8" />
    </svg>
  );
}

/* ─────────────────────────────────────────
   4. GLASS CARD
   For: device cards, artifact cards, evidence records, report cards
───────────────────────────────────────── */
interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  selected?: boolean;
  danger?: boolean;
  onClick?: () => void;
  style?: React.CSSProperties;
}

export function GlassCard({
  children,
  className = '',
  hover = true,
  selected = false,
  danger = false,
  onClick,
  style,
}: GlassCardProps) {
  return (
    <motion.div
      onClick={onClick}
      style={{
        border: selected ? '1px solid var(--primary)' : danger ? '1px solid #EF4444' : '1px solid var(--border)',
        borderRadius: '12px',
        ...style,
      }}
      whileHover={hover ? { y: -1 } : undefined}
      className={`
        relative rounded-[12px] p-4 transition-all duration-200
        bg-[var(--surface)]/70
        backdrop-blur-sm
        ${selected
          ? 'shadow-[0_0_0_1px_var(--primary),0_0_20px_var(--primary)]'
          : danger
          ? 'shadow-[0_0_12px_rgba(239,68,68,0.1)]'
          : ''
        }
        ${hover && !selected ? 'hover:border-[var(--primary)] hover:shadow-[0_0_16px_rgba(0,0,0,0.08)] cursor-pointer' : ''}
        ${className}
      `}
    >
      {selected && (
        <div className="absolute top-0 left-4 right-4 h-px bg-gradient-to-r from-transparent via-[var(--primary)]/60 to-transparent" />
      )}
      {children}
    </motion.div>
  );
}

/* ─────────────────────────────────────────
   5. FILE TYPE BADGE
   For: artifact file types in Recovery Browser
───────────────────────────────────────── */
const FILE_TYPE_COLORS: Record<string, { bg: string; text: string }> = {
  jpeg: { bg: 'rgba(59,130,246,0.2)', text: '#60a5fa' },
  jpg:  { bg: 'rgba(59,130,246,0.2)', text: '#60a5fa' },
  png:  { bg: 'rgba(34,197,94,0.2)',  text: '#4ade80' },
  pdf:  { bg: 'rgba(239,68,68,0.2)',  text: '#f87171' },
  docx: { bg: 'rgba(99,102,241,0.2)', text: '#818cf8' },
  xlsx: { bg: 'rgba(34,197,94,0.2)',  text: '#4ade80' },
  sqlite:{ bg: 'rgba(245,158,11,0.2)',text: '#fbbf24' },
  db:   { bg: 'rgba(245,158,11,0.2)', text: '#fbbf24' },
  zip:  { bg: 'rgba(170,119,169,0.2)',text: '#AA77A9' },
  mp4:  { bg: 'rgba(236,72,153,0.2)', text: '#f472b6' },
  eml:  { bg: 'rgba(14,165,233,0.2)', text: '#38bdf8' },
};

export function FileTypeBadge({ type }: { type: string }) {
  const normalized = type.toLowerCase().replace(/^\./, '');
  const colors = FILE_TYPE_COLORS[normalized] ?? {
    bg: 'var(--surface)',
    text: 'var(--text)',
  };

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider"
      style={{ backgroundColor: colors.bg, color: colors.text }}
    >
      {normalized}
    </span>
  );
}

/* ─────────────────────────────────────────
   6. TIER BADGE
   For: Recovery tier in artifact grid
───────────────────────────────────────── */
export function TierBadge({ tier }: { tier: 'Tier1Metadata' | 'Tier2Signature' | 'Tier3Fragmented' | string }) {
  const config = {
    Tier1Metadata:   { label: 'Tier 1', color: 'var(--primary-text)', bg: 'color-mix(in srgb, var(--primary-text) 15%, transparent)' },
    Tier2Signature:  { label: 'Tier 2', color: '#AA77A9', bg: 'rgba(170,119,169,0.15)' },
    Tier3Fragmented: { label: 'Tier 3', color: 'var(--text)', bg: 'var(--surface)' },
    'Tier 1 (Metadata)': { label: 'Tier 1', color: 'var(--primary-text)', bg: 'color-mix(in srgb, var(--primary-text) 15%, transparent)' },
    'Tier 2 (Structural Carving)': { label: 'Tier 2', color: '#AA77A9', bg: 'rgba(170,119,169,0.15)' },
    'Tier 3 (Bifragment Reconstructed)': { label: 'Tier 3', color: 'var(--text)', bg: 'var(--surface)' },
  }[tier] ?? { label: tier, color: 'var(--text)', bg: 'var(--surface)' };

  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold"
      style={{ backgroundColor: config.bg, color: config.color }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ backgroundColor: config.color, boxShadow: `0 0 6px ${config.color}` }}
      />
      {config.label}
    </span>
  );
}

/* ─────────────────────────────────────────
   7. CONFIDENCE BAR
   For: artifact confidence score display
───────────────────────────────────────── */
export function ConfidenceBar({
  value,
  showLabel = true,
}: {
  value: number;
  showLabel?: boolean;
}) {
  const color =
    value >= 0.8
      ? '#59EE99'
      : value >= 0.5
      ? '#AA77A9'
      : '#EF4444';

  const glow =
    value >= 0.8
      ? 'rgba(89,238,153,0.5)'
      : value >= 0.5
      ? 'rgba(170,119,169,0.5)'
      : 'rgba(239,68,68,0.5)';

  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 rounded-full bg-[rgba(216,228,255,0.08)] overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${value * 100}%` }}
          transition={{ duration: 0.6, ease: [0.34, 1.56, 0.64, 1] }}
          style={{
            backgroundColor: color,
            boxShadow: `0 0 8px ${glow}`,
          }}
        />
      </div>
      {showLabel && (
        <span
          className="text-[11px] font-mono font-bold w-10 text-right tabular-nums"
          style={{ color }}
        >
          {(value * 100).toFixed(0)}%
        </span>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────
   8. DARK TOOLTIP
   For: hex byte hover, LBA segment hover
───────────────────────────────────────── */
interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactElement;
}

export function Tooltip({ content, children }: TooltipProps) {
  const [visible, setVisible] = React.useState(false);

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      <AnimatePresence>
        {visible && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            transition={{ duration: 0.12 }}
            className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2
              bg-[var(--surface)] border border-[var(--border)]/40 rounded-lg px-2.5 py-1.5
              text-[11px] font-mono text-[var(--text)] whitespace-nowrap
              shadow-[0_4px_20px_rgba(0,0,0,0.6)]"
          >
            {content}
            <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-[var(--border)]/60" />
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  );
}

/* ─────────────────────────────────────────
   9. TOAST NOTIFICATION
   For: "Pipeline complete", "Gate authorized", "Error: rate limit"
───────────────────────────────────────── */
type ToastVariant = 'success' | 'danger' | 'info';

interface ToastItem {
  id: string;
  message: string;
  variant: ToastVariant;
}

const ToastContext = React.createContext<{
  toast: (message: string, variant?: ToastVariant) => void;
}>({ toast: () => {} });

export function useToast() {
  return React.useContext(ToastContext);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ToastItem[]>([]);

  const toast = React.useCallback(
    (message: string, variant: ToastVariant = 'success') => {
      const id = Math.random().toString(36).slice(2);
      setToasts((prev) => [...prev, { id, message, variant }]);
      setTimeout(
        () => setToasts((prev) => prev.filter((t) => t.id !== id)),
        3500
      );
    },
    []
  );

  const variantStyles: Record<ToastVariant, string> = {
    success:
      'border-[var(--primary-text)]/40 bg-[var(--primary-text)]/10 text-[var(--primary-text)]',
    danger:
      'border-[#EF4444]/40 bg-[rgba(239,68,68,0.08)] text-[#EF4444]',
    info: 'border-[#AA77A9]/40 bg-[rgba(170,119,169,0.08)] text-[var(--text)]',
  };

  const icons: Record<ToastVariant, string> = {
    success: '✓',
    danger: '⚠',
    info: 'ℹ',
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, x: 40, scale: 0.95 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 40, scale: 0.95 }}
              transition={{ duration: 0.2, ease: [0.34, 1.56, 0.64, 1] }}
              className={`
                flex items-center gap-2.5 px-4 py-2.5 rounded-lg border
                font-mono text-xs font-medium
                shadow-[0_8px_32px_rgba(0,0,0,0.5)]
                backdrop-blur-sm min-w-[240px]
                ${variantStyles[t.variant]}
              `}
            >
              <span className="text-sm">{icons[t.variant]}</span>
              {t.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

/* ─────────────────────────────────────────
   10. DARK FLOATING LABEL INPUT
   For: LBA jump input, source path, case ID entry
───────────────────────────────────────── */
interface FloatingInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
}

export function FloatingInput({ label, error, className = '', ...props }: FloatingInputProps) {
  const [focused, setFocused] = React.useState(false);
  const hasValue = !!props.value || !!props.defaultValue;

  return (
    <div className={`relative ${className}`}>
      <input
        {...props}
        onFocus={(e) => { setFocused(true); props.onFocus?.(e); }}
        onBlur={(e) => { setFocused(false); props.onBlur?.(e); }}
        className={`
          peer w-full bg-[var(--surface)]/50 border rounded-md
          font-mono text-xs text-[var(--text)] placeholder-transparent
          px-3 pt-5 pb-2
          outline-none transition-all duration-200
          ${error
            ? 'border-[#EF4444]/50 focus:border-[#EF4444] focus:shadow-[0_0_0_2px_rgba(239,68,68,0.15)]'
            : 'border-[var(--border)] focus:border-[var(--primary)] focus:shadow-[0_0_0_2px_color-mix(in_srgb,var(--primary)_30%,transparent)]'
          }
        `}
      />
      <label
        className={`
          absolute left-3 font-sans text-[10px] font-medium tracking-wider uppercase
          transition-all duration-200 pointer-events-none
          ${focused || hasValue ? 'top-1.5 text-[9px]' : 'top-3.5 text-xs'}
          ${focused
            ? error ? 'text-[#EF4444]' : 'text-[var(--primary)]'
            : 'text-[var(--text)]/60'
          }
        `}
      >
        {label}
      </label>
      {error && (
        <p className="mt-1 text-[10px] font-mono text-[#EF4444]">{error}</p>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────
   11. SECTION HEADER
   For: page titles with blueprint reference tags
───────────────────────────────────────── */
export function SectionHeader({
  title,
  subtitle,
  tags,
  actions,
}: {
  title: string;
  subtitle?: string;
  tags?: string[];
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <h1 className="text-xl font-sans font-semibold text-[var(--text)] tracking-tight">
            {title}
          </h1>
          {tags?.map((tag) => (
            <span
              key={tag}
              className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--primary-text)]/10 text-[var(--primary-text)] border border-[var(--primary-text)]/30 font-semibold"
            >
              {tag}
            </span>
          ))}
        </div>
        {subtitle && (
          <p className="text-[11px] text-[var(--text)]/60 font-sans max-w-xl">
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ─────────────────────────────────────────
   12. LINEAR PROGRESS BAR
   For: acquisition progress, sanitization progress, report generation
───────────────────────────────────────── */
export function LinearProgress({
  value,
  label,
  variant = 'green',
}: {
  value: number;
  label?: string;
  variant?: 'green' | 'amethyst' | 'danger';
}) {
  const colors = {
    green: { bar: '#59EE99', glow: 'rgba(89,238,153,0.4)' },
    amethyst: { bar: '#AA77A9', glow: 'rgba(170,119,169,0.4)' },
    danger: { bar: '#EF4444', glow: 'rgba(239,68,68,0.4)' },
  }[variant];

  return (
    <div className="w-full space-y-1.5">
      {label && (
        <div className="flex justify-between items-center">
          <span className="text-[10px] font-mono text-[var(--text)]/70 uppercase tracking-wider">
            {label}
          </span>
          <AnimatedCounter
            value={value}
            suffix="%"
            decimals={1}
            glowColor={variant === 'green' ? 'green' : variant === 'amethyst' ? 'amethyst' : 'red'}
            className="text-[11px]"
          />
        </div>
      )}
      <div className="w-full h-1 rounded-full bg-[rgba(216,228,255,0.06)] overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(100, value)}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          style={{
            backgroundColor: colors.bar,
            boxShadow: `0 0 10px ${colors.glow}`,
          }}
        />
      </div>
    </div>
  );
}
