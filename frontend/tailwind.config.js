/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#F5F2FC",       // Light lilac background
          card: "#FAF7FD",     // Lilac-white card background
          border: "#DFD5F5",   // Soft lilac border
          glow: "#8B5CF6",     // Vibrant violet accent
          danger: "#E11D48",   // Rose danger
          warning: "#D97706",  // Amber warning
          info: "#3B82F6",     // Soft blue info
          text: "#2C1E47",     // Deep violet text
          muted: "#7E7399"     // Muted violet-slate text
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'glow-green': '0 4px 20px rgba(139, 92, 246, 0.15)',
        'glow-red': '0 4px 20px rgba(225, 29, 72, 0.15)',
        'glow-amber': '0 4px 20px rgba(217, 119, 6, 0.15)',
      }
    },
  },
  plugins: [],
}
