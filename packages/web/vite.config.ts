import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// COOP/COEP headers are required for `@aztec/bb.js`'s threaded WASM mode
// (SharedArrayBuffer is gated behind cross-origin isolation). The same
// headers must be served by whatever hosts the production build.
const crossOriginIsolation = {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
};

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            // The SDK was originally Node-targeted and imports `node:crypto`
            // for sha256. In the browser we shim it with @noble/hashes.
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
        port: 5173,
        headers: crossOriginIsolation,
    },
    preview: {
        port: 4173,
        headers: crossOriginIsolation,
    },
    build: {
        target: "es2022",
        sourcemap: true,
    },
});
