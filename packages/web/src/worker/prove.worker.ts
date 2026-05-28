// Long-running ZK proof generation, off the main thread.
//
// Protocol:
//   Main → Worker: { type: "prove", witness, circuitUrl }
//   Worker → Main: { type: "stage", stage: <string> }
//   Worker → Main: { type: "done", proofBytes: number[], publicInputs: string[] }
//   Worker → Main: { type: "error", detail: string }
//
// We import the SDK's `prove` directly; that pulls in `@aztec/bb.js` and
// `@noir-lang/noir_js` which both work in workers as long as COOP/COEP
// are configured on the host (see vite.config.ts).

/// <reference lib="webworker" />

import { prove, type WitnessInputs } from "@crisp-qes/sdk";

type InMsg = {
    type: "prove";
    witness: WitnessInputs;
    circuitUrl: string;
};

type OutMsg =
    | { type: "stage"; stage: "loadingCircuit" | "buildWitness" | "proving" | "done" }
    | { type: "done"; proofBytes: number[]; publicInputs: string[] }
    | { type: "error"; detail: string };

function post(msg: OutMsg) {
    (self as unknown as DedicatedWorkerGlobalScope).postMessage(msg);
}

self.addEventListener("message", (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    if (!msg || msg.type !== "prove") return;
    (async () => {
        try {
            post({ type: "stage", stage: "loadingCircuit" });
            const res = await fetch(msg.circuitUrl, { credentials: "omit" });
            if (!res.ok) {
                throw new Error(`circuit fetch ${msg.circuitUrl}: HTTP ${res.status}`);
            }
            const circuit = await res.json();

            post({ type: "stage", stage: "proving" });
            const { proofBytes, publicInputs } = await prove({
                witness: msg.witness,
                circuit,
            });
            post({
                type: "done",
                proofBytes: Array.from(proofBytes),
                publicInputs,
            });
        } catch (err) {
            post({
                type: "error",
                detail: err instanceof Error ? err.message : String(err),
            });
        }
    })();
});
