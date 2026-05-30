// Proof-gating helper for the v3 Grumpkin VOPRF node (build, unaudited).
//
// Wires REAL admission gating for POST /v3/blind-eval: before the node spends a
// scalar-mul on a client's blinded element M, we require a valid ZK proof from
// the `enroll_commit_v2` circuit whose PUBLIC OUTPUT is exactly that same M.
// This replaces the v2 cleartext Diia cert/age attestation: the proof itself
// attests (in zero knowledge) that M = r*H2C(RNOKPP) for a RNOKPP extracted
// from a valid, age>=18 P-256 cert.
//
// HOW THE GATE WORKS
//   * Verification runs entirely IN-PROCESS via @aztec/bb.js (UltraHonk wasm),
//     so the deployed container needs NO `bb`/barretenberg CLI binary. At
//     startup we build one UltraHonkBackend over the committed circuit bytecode
//     and derive its verification key once (the vk is FIXED per circuit); this
//     doubles as a fail-closed liveness check — if bb.js can't load the circuit
//     the gate is unavailable and every request is rejected.
//   * Each request carries { proof, publicInputs } (both 0x-hex / arrays of
//     0x-hex field words) plus M. We:
//       (1) confirm the proof's public-output M words equal the request's M,
//       (2) call backend.verifyProof({ proof, publicInputs }) in-process.
//     BOTH must hold, else the request is rejected (4xx) and NOT evaluated.
//
// PUBLIC INPUTS LAYOUT (enroll_commit_v2, 14 field words of 32 bytes BE):
//   [0..8)  today[8]  (ASCII bytes of YYYYMMDD)
//   [8..12) c1,c2,c3,c4  (SvdW suite constants)
//   [12]    M.x   <- the circuit's first public return value
//   [13]    M.y   <- the circuit's second public return value
// So M = (publicInputs[12], publicInputs[13]).

import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
    Barretenberg,
    UltraHonkBackend,
    UltraHonkVerifierBackend,
} from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Path to the committed circuit artifact (bytecode JSON) used to derive the vk.
export const ENROLL_COMMIT_V2_JSON = join(
    __dirname,
    "..",
    "circuits",
    "enroll_commit_v2",
    "target",
    "enroll_commit_v2.json",
);

// Index of the M.x public-input word and total expected word count. Asserted
// against the request so a circuit-shape change can't silently weaken the gate.
export const M_X_WORD_INDEX = 12;
export const PUBLIC_INPUT_WORD_COUNT = 14;
const FIELD_BYTES = 32;

// Threads for the bb.js wasm backend. Verification is light; 1 thread keeps the
// container memory footprint predictable. Override via BB_THREADS if needed.
const BB_THREADS = Number(process.env.BB_THREADS || 1);

// Backend selection. We default to the self-contained Wasm backend: the native
// NAPI backend spawns a Unix-socket child process that fails to come up in the
// slim deploy container, whereas wasm runs in-process everywhere we tested.
// Override with BB_BACKEND (e.g. "NativeSharedMemory") if a host benefits.
const BB_BACKEND = process.env.BB_BACKEND || "Wasm";

function backendOpts() {
    const opts = { threads: BB_THREADS };
    if (BB_BACKEND) opts.backend = BB_BACKEND;
    return opts;
}

/**
 * An in-process proof gate over a single circuit. Holds the (fixed) circuit
 * verification key plus an UltraHonkVerifierBackend (bb.js wasm). Verifying via
 * the verifier backend with a precomputed vk avoids recomputing the vk from
 * bytecode on every request (which UltraHonkBackend.verifyProof would do).
 * Construct once at startup via {@link createGate}; reuse for the process
 * lifetime. No `bb` CLI / barretenberg binary is required.
 */
export class ProofGate {
    /** @param {UltraHonkVerifierBackend} verifier  @param {Uint8Array} vk */
    constructor(verifier, vk) {
        this.verifier = verifier;
        this.vk = vk;
    }

    /**
     * Verify a proof in-process against this gate's fixed circuit + vk.
     * @param {{ proof: Uint8Array, publicInputs: string[] }} proofData
     * @returns {Promise<boolean>} true iff the proof is valid.
     */
    async verify(proofData) {
        return this.verifier.verifyProof({ ...proofData, verificationKey: this.vk });
    }
}

// — gate construction (once at startup) ───────────────────────────────────────

/**
 * Build the in-process proof gate for the enroll_commit_v2 circuit using
 * @aztec/bb.js. Loads the committed circuit bytecode, derives the (fixed)
 * verification key once via UltraHonkBackend.getVerificationKey() — which also
 * serves as a fail-closed liveness check — and wraps a verifier backend that
 * reuses that vk. Callers cache the returned gate for the process lifetime.
 * Throws if bb.js cannot load the circuit or the artifact can't be found.
 *
 * @param {string} [circuitJson] path to the circuit bytecode JSON.
 * @returns {Promise<ProofGate>}
 */
export async function createGate(circuitJson = ENROLL_COMMIT_V2_JSON) {
    const artifact = JSON.parse(await readFile(circuitJson, "utf8"));
    if (typeof artifact.bytecode !== "string" || artifact.bytecode.length === 0) {
        throw new Error("circuit artifact missing base64 bytecode");
    }
    const api = await Barretenberg.new(backendOpts());
    // Derive the vk once from the circuit bytecode (fail-closed startup check).
    const vk = await new UltraHonkBackend(artifact.bytecode, api).getVerificationKey();
    const verifier = new UltraHonkVerifierBackend(api);
    return new ProofGate(verifier, vk);
}

// — helpers ───────────────────────────────────────────────────────────────────

// Normalize a field word (0x-hex string OR byte array OR Buffer) to a 32-byte
// big-endian Buffer. Throws on anything wider than 32 bytes.
function wordToBE32(word) {
    let v;
    if (typeof word === "string") {
        const h = word.startsWith("0x") || word.startsWith("0X") ? word.slice(2) : word;
        if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error("public input word not hex");
        v = BigInt("0x" + (h === "" ? "0" : h));
    } else if (typeof word === "bigint") {
        v = word;
    } else {
        throw new Error("public input word must be hex string or bigint");
    }
    const out = Buffer.alloc(FIELD_BYTES);
    for (let i = FIELD_BYTES - 1; i >= 0; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    if (v !== 0n) throw new Error("public input word exceeds 32 bytes");
    return out;
}

// Normalize an array of field words to the canonical `0x{64 hex}` string form
// bb.js's verifyProof expects for publicInputs. Each word is round-tripped
// through wordToBE32 so over-wide / non-hex words are rejected here.
function normalizePublicInputs(words) {
    if (!Array.isArray(words)) throw new Error("publicInputs must be an array");
    return words.map((w) => "0x" + wordToBE32(w).toString("hex"));
}

// Parse a proof field that may arrive as 0x-hex or a byte array into a
// Uint8Array (the form bb.js's verifyProof expects).
function proofToBytes(proof) {
    if (proof instanceof Uint8Array) return proof;
    if (typeof proof === "string") {
        const h = proof.startsWith("0x") || proof.startsWith("0X") ? proof.slice(2) : proof;
        if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2 !== 0) {
            throw new Error("proof hex malformed");
        }
        return new Uint8Array(Buffer.from(h, "hex"));
    }
    if (Array.isArray(proof)) return Uint8Array.from(proof);
    throw new Error("proof must be 0x-hex string or byte array");
}

// Extract M.x / M.y as bigints from the public-input words.
export function extractMFromPublicInputs(words) {
    if (!Array.isArray(words) || words.length !== PUBLIC_INPUT_WORD_COUNT) {
        throw new Error(
            `publicInputs must have exactly ${PUBLIC_INPUT_WORD_COUNT} words`,
        );
    }
    const toBig = (w) => BigInt("0x" + wordToBE32(w).toString("hex"));
    return {
        x: toBig(words[M_X_WORD_INDEX]),
        y: toBig(words[M_X_WORD_INDEX + 1]),
    };
}

// — the gate ────────────────────────────────────────────────────────────────

/**
 * Verify a client's enroll_commit_v2 proof AND bind it to the request's M.
 *
 * @param {object} args
 * @param {ProofGate} args.gate         in-process gate (from createGate()).
 * @param {string|Uint8Array} args.proof   the bb proof (0x-hex or bytes).
 * @param {Array<string|bigint>} args.publicInputs  the 14 public-input words.
 * @param {{x: bigint, y: bigint}} args.expectedM   M parsed from the request.
 * @returns {Promise<{ ok: true } | { ok: false, code: string, detail: string }>}
 */
export async function verifyEnrollCommitProof({ gate, proof, publicInputs, expectedM }) {
    // (1) Structural + M-binding checks first — cheap, and they let us reject
    //     mismatched-M without ever invoking the (heavier) wasm verifier.
    let proofBytes, piWords, m;
    try {
        proofBytes = proofToBytes(proof);
        piWords = normalizePublicInputs(publicInputs);
        m = extractMFromPublicInputs(publicInputs);
    } catch (e) {
        return { ok: false, code: "MalformedProof", detail: e.message };
    }
    if (piWords.length !== PUBLIC_INPUT_WORD_COUNT) {
        return {
            ok: false,
            code: "MalformedProof",
            detail: `public_inputs must be ${PUBLIC_INPUT_WORD_COUNT} field words`,
        };
    }
    if (m.x !== expectedM.x || m.y !== expectedM.y) {
        return {
            ok: false,
            code: "ProofMismatchedM",
            detail: "proof public output M does not equal request M",
        };
    }

    // (2) Cryptographic verification IN-PROCESS via bb.js (no `bb` CLI).
    let valid;
    try {
        valid = await gate.verify({ proof: proofBytes, publicInputs: piWords });
    } catch (e) {
        // A throw here means the verifier choked on the inputs (malformed proof
        // bytes, wrong size, etc.) rather than a clean false — treat as reject.
        return {
            ok: false,
            code: "ProofRejected",
            detail: (e.message || "bb.js verifyProof failed").toString().trim().slice(0, 300),
        };
    }
    if (!valid) {
        return { ok: false, code: "ProofRejected", detail: "proof verification failed" };
    }
    return { ok: true };
}
