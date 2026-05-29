// Off-main-thread proof generation for the v2 circuit.
//
// Witness shape (mirrors v2 circuit `main(...)` in #30):
//   enrollment_secret: 0x-hex32         (private)
//   merkle_path: 0x-hex32 [TREE_DEPTH]  (private)
//   merkle_path_indices: 0|1 [TREE_DEPTH]
//   petition_id: 0x-hex32                (public)
//   enrollment_root: 0x-hex32            (public)
//   nullifier: 0x-hex32                  (public)
//
// Protocol:
//   Main → Worker: { type: "prove", witness, circuitUrl }
//   Worker → Main: { type: "stage", stage: "..." }
//   Worker → Main: { type: "done", proofBytes: number[], publicInputs: string[] }
//   Worker → Main: { type: "error", detail: string }

/// <reference lib="webworker" />

import type { CompiledCircuit, InputMap } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

export interface V2WitnessInputs {
    enrollment_secret: string;
    merkle_path: string[];
    merkle_path_indices: number[]; // 0 | 1 per slot
    petition_id: string;
    enrollment_root: string;
    nullifier: string;
}

type InMsg = {
    type: "prove";
    witness: V2WitnessInputs;
    circuitUrl: string;
};

type OutMsg =
    | {
          type: "stage";
          stage: "loadingCircuit" | "buildWitness" | "proving" | "done";
      }
    | { type: "done"; proofBytes: number[]; publicInputs: string[] }
    | { type: "error"; detail: string };

function post(msg: OutMsg) {
    (self as unknown as DedicatedWorkerGlobalScope).postMessage(msg);
}

// Pick a thread count for the bb.js threaded prover. bb defaults to the
// hardware max (up to 32); each extra thread holds its own polynomial
// buffers during proving, so peak WASM memory grows with thread count.
// iOS Safari has a hard per-tab memory ceiling that the default blows
// past on real devices (e.g. iPhone 14 Pro → "Out of memory"), so we cap
// aggressively there and modestly elsewhere. Fewer threads = slower, but
// it actually completes instead of getting the tab killed.
function pickThreads(): number {
    const nav = (self as unknown as { navigator?: WorkerNavigator }).navigator;
    const hw = nav?.hardwareConcurrency ?? 4;
    const ua = nav?.userAgent ?? "";
    const isIOS = /iP(hone|od|ad)/.test(ua);
    if (isIOS) return Math.max(1, Math.min(hw, 2));
    return Math.max(1, Math.min(hw, 8));
}

self.addEventListener("message", (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    if (!msg || msg.type !== "prove") return;
    (async () => {
        try {
            post({ type: "stage", stage: "loadingCircuit" });
            const res = await fetch(msg.circuitUrl, { credentials: "omit" });
            if (!res.ok) {
                throw new Error(
                    `circuit fetch ${msg.circuitUrl}: HTTP ${res.status}`,
                );
            }
            const circuit = (await res.json()) as CompiledCircuit;

            post({ type: "stage", stage: "buildWitness" });
            const noir = new Noir(circuit);
            const { witness: compressedWitness } = await noir.execute(
                msg.witness as unknown as InputMap,
            );

            post({ type: "stage", stage: "proving" });
            const api = await Barretenberg.new({ threads: pickThreads() });
            try {
                const backend = new UltraHonkBackend(circuit.bytecode, api);
                const { proof, publicInputs } = await backend.generateProof(
                    compressedWitness,
                    { verifierTarget: "evm" },
                );
                post({
                    type: "done",
                    proofBytes: Array.from(proof),
                    publicInputs,
                });
            } finally {
                await api.destroy();
            }
        } catch (err) {
            post({
                type: "error",
                detail: err instanceof Error ? err.message : String(err),
            });
        }
    })();
});
