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
          bg: "#F4F7FC",       // Clean light blue-gray
          card: "#FFFFFF",     // Pure white cards
          border: "#E2E8F0",   // Light gray borders
          glow: "#059669",     // Forest green for visibility in light mode
          danger: "#DC2626",   // Alert red
          warning: "#D97706",  // Amber caution
          info: "#2563EB",     // Info blue
          text: "#1E293B",     // Deep dark gray
          muted: "#64748B"     // Cool slate gray for subtitles
        }
      },
      boxShadow: {
        'glow-green': '0 4px 20px rgba(5, 150, 105, 0.15)',
        'glow-red': '0 4px 20px rgba(220, 38, 38, 0.15)',
        'glow-amber': '0 4px 20px rgba(217, 119, 6, 0.15)',
      }
    },
  },
  plugins: [],
}
