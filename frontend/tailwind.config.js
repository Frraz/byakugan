/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Identidade oficial — ver docs/ui.md e "Byakugan identidade visual.png"
        navy: "#0B1220",
        surface: "#111A2E",
        "surface-2": "#0F1728",
        primary: "#00D4FF", // Electric Blue
        accent: "#C8B6FF", // Byakugan Lavender
        success: "#22C55E",
        warning: "#F59E0B",
        danger: "#EF4444",
        "sev-high": "#F97316",
        "sev-info": "#64748B",
        foreground: "#E6EDF6",
        muted: "#8A97AD",
        border: "#1E2A44",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 24px -4px rgba(0, 212, 255, 0.45)",
        "glow-accent": "0 0 24px -4px rgba(200, 182, 255, 0.45)",
        glass: "0 8px 32px -8px rgba(0, 0, 0, 0.6)",
      },
      backgroundImage: {
        "radial-glow":
          "radial-gradient(circle at 50% 0%, rgba(0,212,255,0.10), transparent 60%)",
      },
    },
  },
  plugins: [],
};
