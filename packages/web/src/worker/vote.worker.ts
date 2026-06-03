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
//   Worker → Main: { type:"selftest:done", version, initialized }
//   Main → Worker: { type:"prove", ... }   (not yet wired — Task 4.0)
//   Worker → Main: { type:"error", detail }

/// <reference lib="webworker" />

// Redirect bb.js's CRS download to our same-origin mirror (TLS-expired host).
import "./crsRedirect.js";
import * as bbv3 from "@aztec/bb.js-v3";

const { BarretenbergSync } = bbv3;

// The aliased package version is fixed at build time; report it for clarity.
const V3_VERSION = "3.0.0-nightly.20260102";

// CRS-free proof that the v3 WASM actually executes in this realm: a pedersen
// hash uses the WASM but NOT the SRS/CRS (which Barretenberg.new() would require
// and which is only provisioned for the real proving path, Task 4.0). Tolerates
// the v3/v4 pedersen API skew (positional vs { inputs, hashIndex }).
async function v3PedersenWorks(): Promise<boolean> {
    try {
        const sync = await BarretenbergSync.initSingleton();
        const inputs = [1, 2, 3].map((n) => {
            const u = new Uint8Array(32);
            u[31] = n;
            return u;
        });
        const api = sync as unknown as { pedersenHash: (a: unknown, b?: unknown) => unknown };
        let out: unknown;
        try {
            out = api.pedersenHash(inputs, 0);
        } catch {
            out = api.pedersenHash({ inputs, hashIndex: 0 });
        }
        return out != null;
    } catch {
        return false;
    }
}

type InMsg = { type: "selftest" } | { type: "prove"; [k: string]: unknown };

self.onmessage = async (ev: MessageEvent<InMsg>) => {
    const msg = ev.data;
    try {
        if (msg.type === "selftest") {
            // CRS-free proof the v3 WASM executes in this realm (real proving
            // CRS is Task 4.0). The build proves this chunk is the only one
            // carrying the v3 bb.js (distinct from the main thread's v4).
            const initialized = await v3PedersenWorks();
            self.postMessage({ type: "selftest:done", version: V3_VERSION, initialized });
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
