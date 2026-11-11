import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  // The web demo lives under /demo/; set here, not on the command line (Git Bash rewrites "/demo/").
  base: process.env.LOCKDOWN_DEMO_BASE === "1" ? "/demo/" : "/",
  plugins: [react()],
  clearScreen: false,
  server: { port: 5174, strictPort: true },
  build: { sourcemap: false, target: "es2022" },
});
