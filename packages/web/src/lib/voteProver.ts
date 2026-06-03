// ADR-0001 path (C) client: spawn the vote proof in its own Web Worker realm on
// the legacy v3 bb.js, isolated from the main thread's v4 bb.js. The worker URL
// pattern (new Worker(new URL(...), { type: "module" })) lets Vite emit a
// separate chunk that bundles @aztec/bb.js-v3 distinct from the v4 bb.js.

export type VoteWorkerSelftest = {
    /** the v3 bb.js version the worker realm loaded */
    version: string;
    /** the v3 WASM executed (CRS-free pedersen) in the worker realm */
    initialized: boolean;
};

/**
 * Spin up the vote worker (v3 realm) and run its selftest: instantiate the v3
 * bb.js WASM off the main thread and confirm it's the v3 build. Proves path (C)
 * coexistence at runtime in the browser (the main thread keeps its v4 bb.js for
 * enrollment). Desktop-only; experimental.
 */
export function voteWorkerSelftest(): Promise<VoteWorkerSelftest> {
    const worker = new Worker(new URL("../worker/vote.worker.ts", import.meta.url), { type: "module" });
    return new Promise<VoteWorkerSelftest>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent) => {
            const m = ev.data as
                | ({ type: "selftest:done" } & VoteWorkerSelftest)
                | { type: "error"; detail: string };
            if (m.type === "selftest:done") {
                resolve({ version: m.version, initialized: m.initialized });
            } else {
                reject(new Error(m.type === "error" ? m.detail : "unexpected worker message"));
            }
            worker.terminate();
        };
        worker.onerror = (e) => {
            reject(new Error(e.message || "vote worker failed to load"));
            worker.terminate();
        };
        worker.postMessage({ type: "selftest" });
    });
}
