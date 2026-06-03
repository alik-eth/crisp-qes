// ADR-0001 path (C) client: drive the in-browser vote prover, which runs the v3
// vote SDK in its own Web Worker realm (built separately to /vote/ by
// vite.voteworker.config.ts, aliased to the fork's v3 bb.js / noir beta.16 /
// zk-inputs). The main app stays pure v4; the v3 graph never touches it.
// Desktop only (the fold proof is ~1.5M gates, past the iOS browser floor).

const VOTE_WORKER_URL = `${import.meta.env.BASE_URL}vote/voteProve.worker.js`;

function spawn(): Worker {
    // Module worker; same-origin, runs under the page's COOP/COEP (SharedArrayBuffer).
    return new Worker(VOTE_WORKER_URL, { type: "module" });
}

export type SdkCheck = {
    generateCircuitInputsImpl: string;
    generateProof: string;
    encodeSolidityProof: string;
};

/**
 * Load the pre-built v3 vote worker and confirm the v3 SDK + its toolchain
 * (v3 bb.js + noir beta.16 + zk-inputs) loaded in the worker realm. No CRS or
 * witness needed (proving is the only step that fetches the CRS). Proves the
 * version-isolated bundle works in-browser.
 */
export function voteSdkCheck(): Promise<SdkCheck> {
    const worker = spawn();
    return new Promise<SdkCheck>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent) => {
            const m = ev.data as ({ type: "sdkcheck:done"; fns: SdkCheck }) | { type: "error"; detail: string };
            if (m.type === "sdkcheck:done") resolve(m.fns);
            else reject(new Error(m.type === "error" ? m.detail : "unexpected worker message"));
            worker.terminate();
        };
        worker.onerror = (e) => {
            reject(new Error(e.message || "vote worker failed to load"));
            worker.terminate();
        };
        worker.postMessage({ type: "sdkcheck" });
    });
}

export type VoteWitness = {
    vote: number[];
    publicKey: Uint8Array;
    enrollmentSecret: bigint;
    merklePath: bigint[];
    merklePathIndices: number[];
    enrollmentRoot: bigint;
    nullifier: bigint;
    petitionId: bigint;
};

export type VoteProof = { encoded: `0x${string}`; nullifier: string; publicInputs: string[] };

/**
 * Generate a real (non-mask) vote proof in the v3 worker realm. Requires the
 * CRS to be reachable (same-origin /crs/ mirror — present in the deployed app,
 * not in `vite preview`). Returns the ABI-encoded proof for CRISPQESProgram.
 */
export function proveVoteInBrowser(w: VoteWitness, onStage?: (s: string) => void): Promise<VoteProof> {
    const worker = spawn();
    return new Promise<VoteProof>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent) => {
            const m = ev.data as
                | { type: "stage"; stage: string }
                | ({ type: "prove:done" } & VoteProof)
                | { type: "error"; detail: string };
            if (m.type === "stage") {
                onStage?.(m.stage);
                return;
            }
            if (m.type === "prove:done") resolve({ encoded: m.encoded, nullifier: m.nullifier, publicInputs: m.publicInputs });
            else reject(new Error(m.type === "error" ? m.detail : "unexpected worker message"));
            worker.terminate();
        };
        worker.onerror = (e) => {
            reject(new Error(e.message || "vote worker failed to load"));
            worker.terminate();
        };
        worker.postMessage({ type: "prove", ...w });
    });
}
