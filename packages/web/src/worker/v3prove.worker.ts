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

// Redirect bb.js's CRS download off the (TLS-expired) crs.aztec.network host
// to our same-origin /crs/ mirror. Side-effect import — load before bb.js.
import "./crsRedirect.js";
import type { CompiledCircuit, InputMap } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend, BackendType } from "@aztec/bb.js";

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

function isIOS(): boolean {
    const ua =
        (self as unknown as { navigator?: WorkerNavigator }).navigator
            ?.userAgent ?? "";
    return /iP(hone|od|ad)/.test(ua);
}

// bb.js options. iOS needs a special memory strategy — see the comment below and
// hideSharedArrayBufferForIOS().
function bbOptions(): {
    threads: number;
    memory?: { maximum: number };
    backend?: BackendType;
} {
    const hw =
        (self as unknown as { navigator?: WorkerNavigator }).navigator
            ?.hardwareConcurrency ?? 4;
    if (isIOS()) {
        // The ~2^19 enroll_commit_v2 prove needs ~840 MiB of wasm linear memory.
        // The page is cross-origin-isolated, so by default bb.js builds a SHARED
        // WebAssembly.Memory and reserves its whole `maximum` up front. iOS refuses
        // a ~1 GiB shared reservation (kills the tab), while any maximum small
        // enough to reserve (≤832 MiB) is too small for the prove — it bad_allocs
        // at the ceiling and traps ("Unreachable code should not be executed").
        // So on iOS we force a NON-shared, lazily-committed memory (see
        // hideSharedArrayBufferForIOS) with a generous 1 GiB cap: it commits only
        // the ~840 MiB the prove touches, with no up-front reservation. iOS proves
        // single-threaded regardless, so running the wasm in THIS worker (the
        // `Wasm` backend, vs a nested thread worker) costs nothing — and is what
        // lets the SharedArrayBuffer hide below take effect.
        return {
            threads: 1,
            memory: { maximum: 16384 }, // 16384 pages × 64 KiB = 1 GiB lazy cap
            backend: BackendType.Wasm,
        };
    }
    return { threads: Math.max(1, Math.min(hw, 8)) };
}

// iOS only: hide SharedArrayBuffer so bb.js's getSharedMemoryAvailable() returns
// false and it builds a non-shared (lazy) memory + single-thread wasm. Paired
// with backend:"Wasm" (runs the wasm in THIS worker, not a fresh nested one) so
// the check runs in this scope. Must run before Barretenberg.new.
function hideSharedArrayBufferForIOS() {
    if (isIOS()) {
        try {
            (self as unknown as Record<string, unknown>).SharedArrayBuffer =
                undefined;
        } catch {
            /* ignore */
        }
    }
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
            hideSharedArrayBufferForIOS();
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
