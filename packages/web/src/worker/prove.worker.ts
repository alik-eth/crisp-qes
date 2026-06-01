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

// Redirect bb.js's CRS download off the (TLS-expired) crs.aztec.network host
// to our same-origin /crs/ mirror. Side-effect import — load before bb.js.
import "./crsRedirect.js";
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

// bb.js options for the threaded WASM prover.
//
// The iOS "Out of memory" is NOT proving exhausting RAM. Measured floor
// (bench/v2-mem-floor.mjs): the v2 sign/revoke proof completes with a cap
// as low as 192 MiB, peak working set ~164 MB. It's instantiation: bb
// creates a *shared* WASM memory and reserves its `maximum` up front, and
// on iOS bb defaults that maximum to 2**14 pages = 1 GiB. iOS Safari
// refuses the 1 GiB reservation and kills the tab. Reservation size is set
// by `maximum`, not thread count — so we cap the iOS maximum to 384 MiB
// (6144 pages), ~2× the measured 192 MiB floor: plenty of proving headroom,
// and a small enough reservation for iOS to grant. (Non-iOS keeps defaults.)
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
            const api = await Barretenberg.new(bbOptions());
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
