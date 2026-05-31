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
        // The bound-challenge enroll circuit is ~2^19 gates and needs ~700 MiB of
        // wasm linear memory to prove. The old 384 MiB cap (set when the circuit
        // was ~2^17) is now too small — the prover hits the ceiling and traps
        // ("Unreachable code should not be executed"). Use a SINGLE thread so the
        // memory is a regular (non-shared) WebAssembly.Memory that commits pages
        // lazily: iOS refuses large *shared* (multi-thread) reservations — the
        // original 1 GiB OOM — so single-thread lets the working set grow to
        // ~700 MiB without that up-front reservation. Confirmed: traps ≤640 MiB,
        // proves at 768; 832 gives margin. Slower than multi-thread, but it works.
        return {
            threads: 1,
            memory: { maximum: 13312 }, // 13312 pages × 64 KiB = 832 MiB ceiling
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
                // DEFAULT flavor (Poseidon oracle) — NOT { verifierTarget: "evm" }.
                // Both v3 proofs (enroll_commit_v2, oprf_nullifier) are verified
                // OFF-CHAIN by the bb.js service (/v3/blind-eval, /v3/register),
                // whose ProofGate derives its VK and verifies with the default
                // flavor. The proof + VK are flavor-specific: an evm/Keccak-oracle
                // proof checked by a default verifier fails deserialization
                // ("Conversion err: grumpkin::fr >= 2^128"). The EVM flavor is only
                // for the v2 SIGN proof (prove.worker.ts), which IS verified
                // on-chain by the Solidity UltraVerifierV2.
                const { proof, publicInputs } =
                    await backend.generateProof(compressedWitness);
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
