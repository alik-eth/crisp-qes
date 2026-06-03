// ADR-0001 path (C): SEPARATE build for the in-browser vote prover worker.
//
// The vote SDK (@crisp-e3/sdk) needs the LEGACY v3 toolchain (bb.js
// 3.0.0-nightly.20260102 + noir beta.16 + @crisp-e3/zk-inputs), which is
// incompatible with the main app's v4 bb.js. Vite resolve.alias is global, so we
// isolate the v3 graph in this dedicated build and emit a self-contained worker
// to public/vote/. The main app loads it via lib/voteProver.ts; its v3 bb.js
// lives in a separate Worker realm and never shares the main thread's v4
// singleton (proven: scripts/validate-dual-bbjs.mjs).
//
// Build:  vite build -c vite.voteworker.config.ts   (run before the app build)

import { resolve } from "node:path";
import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

// The fork's crisp-sdk owns the v3 toolchain; alias the whole v3 graph to it.
const SDK = resolve(__dirname, "../../vendor/crisp-qes-enclave/examples/CRISP/packages/crisp-sdk");
const SDK_NM = resolve(SDK, "node_modules");

export default defineConfig({
    plugins: [wasm(), topLevelAwait()],
    resolve: {
        alias: {
            "@crisp-e3/sdk": resolve(SDK, "dist/index.js"),
            "@aztec/bb.js": resolve(SDK_NM, "@aztec/bb.js"),
            "@noir-lang/noir_js": resolve(SDK_NM, "@noir-lang/noir_js"),
            "@crisp-e3/zk-inputs": resolve(SDK_NM, "@crisp-e3/zk-inputs"),
        },
        dedupe: ["@aztec/bb.js", "@noir-lang/noir_js"],
    },
    // Emitted chunks/wasm/nested-workers are served from /vote/ by the main app.
    base: "/vote/",
    worker: { format: "es" },
    build: {
        target: "esnext",
        outDir: "public/vote",
        emptyOutDir: true,
        sourcemap: true,
        rollupOptions: {
            input: resolve(__dirname, "src/worker/voteProve.worker.ts"),
            output: {
                entryFileNames: "voteProve.worker.js", // stable name for the loader
                chunkFileNames: "assets/[name]-[hash].js",
                assetFileNames: "assets/[name]-[hash][extname]",
                format: "es",
            },
        },
    },
});
