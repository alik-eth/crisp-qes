// ADR-0001 path (C) — REAL in-browser vote prover (desktop only).
//
// Runs the v3 vote SDK (@crisp-e3/sdk) entirely in this Web Worker realm. The
// SDK + its v3 bb.js (3.0.0-nightly.20260102) + noir beta.16 + @crisp-e3/zk-inputs
// (BFV wasm) are bundled by a SEPARATE vite build (vite.voteworker.config.ts)
// that aliases all four to the fork's v3 toolchain — isolated from the main
// thread's v4 bb.js (which can't share a realm; see ADR-0001 + validate-dual-bbjs).
//
// Built to packages/web/public/vote/ and loaded via lib/voteProver.ts. The fold
// proof is ~1.5M gates (past the iOS browser floor) — desktop only.
//
// Protocol:
//   { type:"sdkcheck" }            -> { type:"sdkcheck:done", fns, circuits }   (no CRS/witness)
//   { type:"prove", witness }      -> { type:"prove:done", encoded, nullifier, publicInputs }
//   error                          -> { type:"error", detail }

/// <reference lib="webworker" />

import "./bufferPolyfill.js";
import "./crsRedirect.js";
import { generateCircuitInputsImpl, generateProof, encodeSolidityProof } from "@crisp-e3/sdk";

// Witness for a real (non-mask) ballot — mirrors qes-e2e.mjs / lib/vote.ts.
type ProveMsg = {
    type: "prove";
    vote: number[];
    publicKey: Uint8Array;
    enrollmentSecret: bigint;
    merklePath: bigint[];
    merklePathIndices: number[];
    enrollmentRoot: bigint;
    nullifier: bigint;
    petitionId: bigint;
};
type InMsg = { type: "sdkcheck" } | ProveMsg;

self.onmessage = async (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    try {
        if (msg.type === "sdkcheck") {
            // Proves the v3 SDK + its toolchain bundled + loaded in this realm.
            // No CRS/witness needed (proving is the only step that fetches CRS).
            self.postMessage({
                type: "sdkcheck:done",
                fns: {
                    generateCircuitInputsImpl: typeof generateCircuitInputsImpl,
                    generateProof: typeof generateProof,
                    encodeSolidityProof: typeof encodeSolidityProof,
                },
            });
            return;
        }
        if (msg.type === "prove") {
            const { circuitInputs, encryptedVote } = await generateCircuitInputsImpl({
                vote: msg.vote,
                publicKey: msg.publicKey,
                enrollmentSecret: msg.enrollmentSecret,
                merklePath: msg.merklePath,
                merklePathIndices: msg.merklePathIndices,
                enrollmentRoot: msg.enrollmentRoot,
                nullifier: msg.nullifier,
                petitionId: msg.petitionId,
                isMaskVote: false,
            });
            const proof = await generateProof(circuitInputs);
            const encoded = encodeSolidityProof({ ...proof, encryptedVote }, false);
            self.postMessage({
                type: "prove:done",
                encoded,
                nullifier: msg.nullifier.toString(),
                publicInputs: proof.publicInputs ?? [],
            });
            return;
        }
        self.postMessage({ type: "error", detail: `unknown message: ${(msg as { type?: string })?.type}` });
    } catch (e) {
        self.postMessage({ type: "error", detail: e instanceof Error ? (e.stack ?? e.message) : String(e) });
    }
};
