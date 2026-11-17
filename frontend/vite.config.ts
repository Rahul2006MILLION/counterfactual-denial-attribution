import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  // Same-origin /api calls are proxied to the live FastAPI backend (src/live/api.py).
  server: { port: 5173, strictPort: true, proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
  preview: { proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
  build: {
    target: "es2020",
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: { manualChunks: { three: ["three"] } },
    },
  },
});
