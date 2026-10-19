import { defineConfig, loadEnv } from "vite";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  // Use the configured public origin rather than allowing arbitrary Host headers.
  const backendEnv = loadEnv(mode, fileURLToPath(new URL("../backend", import.meta.url)), "PUBLIC_URL");
  const publicUrl = process.env.PUBLIC_URL || backendEnv.PUBLIC_URL;
  const allowedHosts = [];
  if (publicUrl) {
    try {
      const url = new URL(publicUrl);
      if (["http:", "https:"].includes(url.protocol)) allowedHosts.push(url.hostname);
    } catch {
      console.warn("Invalid PUBLIC_URL: public webhook host was not enabled.");
    }
  }

  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: false,
      allowedHosts,
      // A tunnel to Vite must forward GitHub deliveries to Express unchanged.
      proxy: {
        "/api/webhooks": { target: "http://127.0.0.1:3000", changeOrigin: true },
      },
    },
  };
});
