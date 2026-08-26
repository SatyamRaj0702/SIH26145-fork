import { defineConfig, loadEnv } from "vite";
import type { ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const appwriteEndpoint = (env.VITE_APPWRITE_ENDPOINT ?? "").replace(/\/v1\/?$/, "");
  const proxy: Record<string, string | ProxyOptions> = {
    "/api": "http://127.0.0.1:8000",
    "/ws": {
      target: "ws://127.0.0.1:8000",
      ws: true,
    },
  };
  // Proxy Appwrite API calls so the browser only talks to the Vite origin.
  if (appwriteEndpoint) {
    proxy["/v1"] = { target: appwriteEndpoint, changeOrigin: true };
  }
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy,
    },
  };
});
