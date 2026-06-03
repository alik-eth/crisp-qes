// ADR-0001 path (C): the VOTE proof runs in its OWN Web Worker realm on the
// LEGACY v3 bb.js (pnpm-aliased `@aztec/bb.js-v3` = 3.0.0-nightly.20260102),
// isolated from the v4 bb.js the main thread uses for enrollment. Two bb.js
// WASM singletons can't share one realm, but separate worker realms can — see
// scripts/validate-dual-bbjs.mjs (proven) and docs/adr/0001-...md.
//
// EXPERIMENTAL / desktop-only: the actual vote proof is the ~1.5M-gate crisp_fold
// recursion (past the iOS browser memory floor). The full proving wiring needs
// the v3 vote SDK (@crisp-e3/sdk) + circuit artifacts in this realm (Task 4.0);
// this worker currently proves the v3 toolchain LOADS + runs here (selftest) and
// hosts the proving entrypoint stub.
//
// Protocol:
//   Main → Worker: { type:"selftest" }
//   Worker → Main: { type:"selftest:done", version, hasFr, initialized }
//   Main → Worker: { type:"prove", ... }   (not yet wired — Task 4.0)
//   Worker → Main: { type:"error", detail }

/// <reference lib="webworker" />

// Redirect bb.js's CRS download to our same-origin mirror (TLS-expired host).
import "./crsRedirect.js";
import * as bbv3 from "@aztec/bb.js-v3";

const { Barretenberg } = bbv3;

// The aliased package version is fixed at build time; report it for clarity.
const V3_VERSION = "3.0.0-nightly.20260102";

type InMsg = { type: "selftest" } | { type: "prove"; [k: string]: unknown };

self.onmessage = async (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    try {
        if (msg.type === "selftest") {
            // Runtime proof this realm loaded v3, NOT v4: bb.js v4 removed the
            // top-level `Fr` export that v3 still has (see lib/pedersen.ts).
            const hasFr = "Fr" in bbv3;
            // Instantiate the v3 WASM in this realm (single-threaded for the
            // selftest; the real prover would use the threaded path).
            const bb = await Barretenberg.new({ threads: 1 });
            await (bb as { destroy?: () => Promise<void> }).destroy?.();
            self.postMessage({ type: "selftest:done", version: V3_VERSION, hasFr, initialized: true });
            return;
        }
        if (msg.type === "prove") {
            // The crisp_fold/crisp_qes proving path goes here once the v3 vote
            // SDK (@crisp-e3/sdk) + circuit artifacts are bundled into this
            // worker (ADR-0001 follow-up / Task 4.0). It stays in THIS realm so
            // the v3 bb.js never touches the main thread's v4 singleton.
            self.postMessage({ type: "error", detail: "vote proving not yet wired (Task 4.0); selftest only" });
            return;
        }
        self.postMessage({ type: "error", detail: `unknown message: ${(msg as { type?: string })?.type}` });
    } catch (e) {
        self.postMessage({ type: "error", detail: e instanceof Error ? e.message : String(e) });
    }
};
