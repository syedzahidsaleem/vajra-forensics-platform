/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Forensic Mode Colors (Teal/Cyan/Navy - Read Only Assurance)
        forensic: {
          950: '#070B12',
          900: '#0B132B',
          800: '#111D4A',
          700: '#1C2E6A',
          600: '#0284C7',
          500: '#0EA5E9',
          400: '#38BDF8',
          300: '#7DD3FC',
          accent: '#06B6D4',
          glow: '#0891B2',
          card: '#0E1726',
          border: '#1E293B',
        },
        // Sanitization Mode Colors (Amber/Crimson/Charcoal - Destructive Safety)
        sanitize: {
          950: '#0F0707',
          900: '#1A0C0C',
          800: '#2E1212',
          700: '#4D1717',
          600: '#991B1B',
          500: '#DC2626',
          400: '#EF4444',
          300: '#F87171',
          accent: '#F59E0B',
          warning: '#F97316',
          hazard: '#DC2626',
          glow: '#B91C1C',
          card: '#1F1010',
          border: '#3E1C1C',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-hazard': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
        shine: "shine var(--duration) infinite linear",
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        shine: {
          "0%": { "background-position": "0% 0%" },
          "50%": { "background-position": "100% 100%" },
          to: { "background-position": "0% 0%" },
        },
      },
    },
  },
  plugins: [],
}
