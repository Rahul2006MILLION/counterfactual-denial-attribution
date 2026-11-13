import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  server: { port: 5173, strictPort: true },
  build: {
    target: "es2020",
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: { manualChunks: { three: ["three"] } },
    },
  },
});
