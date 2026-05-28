import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// COOP/COEP headers are required for `@aztec/bb.js`'s threaded WASM mode
// (SharedArrayBuffer is gated behind cross-origin isolation). The same
// headers must be served by whatever hosts the production build — see
// `Caddyfile`.
const crossOriginIsolation = {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
};

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            // SDK uses `node:crypto` for sha256; shim to @noble/hashes
            // in the browser.
            "node:crypto": fileURLToPath(
                new URL("./src/shims/node-crypto.ts", import.meta.url),
            ),
        },
    },
    optimizeDeps: {
        esbuildOptions: { target: "es2022" },
        exclude: ["@aztec/bb.js"],
    },
    worker: {
        format: "es",
    },
    server: {
        port: 5174,
        headers: crossOriginIsolation,
    },
    preview: {
        port: 4174,
        headers: crossOriginIsolation,
    },
    build: {
        target: "es2022",
        sourcemap: true,
    },
});
