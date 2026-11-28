import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard calls "/api/...". During development Vite forwards ("proxies") those
// requests to the FastAPI backend on port 8000 and removes the "/api" prefix, so
// "/api/health" reaches "http://localhost:8000/health".
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
