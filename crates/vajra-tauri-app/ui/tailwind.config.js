/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        onyx: '#00120B',
        'dark-slate': '#35605A',
        'light-green': '#59EE99',
        'amethyst-smoke': '#AA77A9',
        lavender: '#D8E4FF',
      },
    },
  },
  plugins: [],
};
