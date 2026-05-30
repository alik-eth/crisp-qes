// v3 off-main-thread proof generation. Proves EITHER the enroll_commit_v2
// circuit (~118k gates — the iOS in-browser feasibility test) or the
// oprf_nullifier circuit, depending on the message. EXPERIMENTAL / UNAUDITED.
//
// The worker is intentionally circuit-agnostic: the caller supplies the
// circuitUrl + the InputMap witness already built in grumpkin.ts. We mirror
// prove.worker.ts: Noir.execute -> UltraHonkBackend.generateProof, with the
// same iOS thread/memory caps in bbOptions().
//
// Protocol:
//   Main → Worker: { type:"prove", witness, circuitUrl, label }
//   Worker → Main: { type:"stage", label, stage }
//   Worker → Main: { type:"done", label, proofBytes:number[], publicInputs:string[] }
//   Worker → Main: { type:"error", label, detail }

/// <reference lib="webworker" />

import type { CompiledCircuit, InputMap } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

type Label = "enroll" | "nullifier";

type InMsg = {
    type: "prove";
    label: Label;
    witness: InputMap;
    circuitUrl: string;
};

type OutMsg =
    | {
          type: "stage";
          label: Label;
          stage: "loadingCircuit" | "buildWitness" | "proving" | "done";
      }
    | {
          type: "done";
          label: Label;
          proofBytes: number[];
          publicInputs: string[];
      }
    | { type: "error"; label: Label; detail: string };

function post(msg: OutMsg) {
    (self as unknown as DedicatedWorkerGlobalScope).postMessage(msg);
}

// Identical iOS thread/memory caps to prove.worker.ts. bb reserves a *shared*
// WASM memory's `maximum` up front; iOS Safari refuses the 1 GiB default and
// kills the tab, so we cap iOS to 384 MiB (6144 pages). The enroll_commit_v2
// circuit is ~118k gates — this is the iOS feasibility test, so the cap matters.
function bbOptions(): { threads: number; memory?: { maximum: number } } {
    const nav = (self as unknown as { navigator?: WorkerNavigator }).navigator;
    const hw = nav?.hardwareConcurrency ?? 4;
    const ua = nav?.userAgent ?? "";
    const isIOS = /iP(hone|od|ad)/.test(ua);
    if (isIOS) {
        return {
            threads: Math.max(1, Math.min(hw, 2)),
            memory: { maximum: 6144 }, // 6144 pages × 64 KiB = 384 MiB
        };
    }
    return { threads: Math.max(1, Math.min(hw, 8)) };
}

self.addEventListener("message", (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    if (!msg || msg.type !== "prove") return;
    const label = msg.label;
    (async () => {
        try {
            post({ type: "stage", label, stage: "loadingCircuit" });
            const res = await fetch(msg.circuitUrl, { credentials: "omit" });
            if (!res.ok) {
                throw new Error(
                    `circuit fetch ${msg.circuitUrl}: HTTP ${res.status}`,
                );
            }
            const circuit = (await res.json()) as CompiledCircuit;

            post({ type: "stage", label, stage: "buildWitness" });
            const noir = new Noir(circuit);
            const { witness: compressedWitness } = await noir.execute(
                msg.witness,
            );

            post({ type: "stage", label, stage: "proving" });
            const api = await Barretenberg.new(bbOptions());
            try {
                const backend = new UltraHonkBackend(circuit.bytecode, api);
                const { proof, publicInputs } = await backend.generateProof(
                    compressedWitness,
                    { verifierTarget: "evm" },
                );
                post({
                    type: "done",
                    label,
                    proofBytes: Array.from(proof),
                    publicInputs,
                });
            } finally {
                await api.destroy();
            }
        } catch (err) {
            post({
                type: "error",
                label,
                detail: err instanceof Error ? err.message : String(err),
            });
        }
    })();
});
