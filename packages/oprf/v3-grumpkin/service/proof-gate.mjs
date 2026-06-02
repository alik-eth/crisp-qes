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
// PUBLIC INPUTS LAYOUT (enroll_commit_v2, 13 field words of 32 bytes BE):
//   [0..8)  today[8]  (ASCII bytes of YYYYMMDD)
//   [8]     M.x        <- the circuit's first public return value
//   [9]     M.y        <- the circuit's second public return value
//   [10]    C_r        <- commit_r(r) = pedersen([CR_DOMAIN, r_lo, r_hi]); the
//                         cross-proof shared-r binding (F2). The oprf_nullifier
//                         register proof re-asserts commit_r(its r) == this C_r.
//   [11]    digest_hi  <- signedAttrs messageDigest, high 16 bytes
//   [12]    digest_lo  <- signedAttrs messageDigest, low 16 bytes
// So M = (publicInputs[8], publicInputs[9]), C_r = publicInputs[10], and the
// bound messageDigest = digest_hi*2^128 + digest_lo = (publicInputs[11],[12]).
// (The SvdW suite constants c1..c4 are no longer public inputs -- they are pinned
// inside grumpkin_voprf, F3.)

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

// Path to the committed oprf_nullifier circuit artifact. Its proof binds the
// post-blind-eval enrollment commitment to the same M the enroll proof commits
// to, closing the Sybil-binding gap at /v3/register (see verifyThresholdNullifierProof).
export const OPRF_NULLIFIER_JSON = join(
    __dirname,
    "..",
    "circuits",
    "oprf_nullifier",
    "target",
    "oprf_nullifier.json",
);

// Index of the M.x public-input word and total expected word count. Asserted
// against the request so a circuit-shape change can't silently weaken the gate.
export const M_X_WORD_INDEX = 8;
// C_r (cross-proof shared-r commitment) is the circuit's third return value.
export const C_R_WORD_INDEX = 10;
// enroll_commit_v2 returns (M.x, M.y, C_r, digest_hi, digest_lo); the two digest
// limbs are the signedAttrs messageDigest the circuit bound to the signature.
export const DIGEST_HI_WORD_INDEX = 11;
export const DIGEST_LO_WORD_INDEX = 12;
export const PUBLIC_INPUT_WORD_COUNT = 13;
const FIELD_BYTES = 32;

// — THRESHOLD oprf_nullifier public-input layout (13 field words of 32B BE) ─────
// The circuit's `main` declares these public inputs IN ABI ORDER, then appends
// its single public return value (the nullifier) as the final word:
//   [0]  M.x   [1]  M.y    (blinded element — must equal the enroll proof's M)
//   [2]  kp1.x [3]  kp1.y  (PUBLISHED Kpub_1 — must be the canonical node-1 key)
//   [4]  kp2.x [5]  kp2.y  (PUBLISHED Kpub_2)
//   [6]  kp3.x [7]  kp3.y  (PUBLISHED Kpub_3)
//   [8]  idx1  [9]  idx2   (the t=2 responder indices, distinct, in {1,2,3})
//   [10] epoch             (session tag — must equal the current enrollEpoch)
//   [11] c_r               (shared-r commitment — must equal the enroll proof's C_r)
//   [12] nullifier         (RETURN: pedersen([N.x, N.y]), N = rinv*Y, Y combined)
// PRIVATE (not here): the responder partials B_a/B_b, the two per-share DLEQ
// limb sets, and r/rinv. Y is COMPUTED in-circuit (no free Y) so the proof
// SELF-ATTESTS the t-of-n evaluation: per-share epoch-bound DLEQs vs the pinned
// GEN (F1+C-1+session), idx->Kpub selection from the published set, and the
// pinned mod-N Lagrange combine. The service only pins M / c_r / the published
// Kpub set / epoch / the submitted commitment.
export const THRESHOLD_NULLIFIER_M_X_WORD_INDEX = 0;
export const THRESHOLD_NULLIFIER_KP1_X_WORD_INDEX = 2;
export const THRESHOLD_NULLIFIER_KP2_X_WORD_INDEX = 4;
export const THRESHOLD_NULLIFIER_KP3_X_WORD_INDEX = 6;
export const THRESHOLD_NULLIFIER_IDX1_WORD_INDEX = 8;
export const THRESHOLD_NULLIFIER_IDX2_WORD_INDEX = 9;
export const THRESHOLD_NULLIFIER_EPOCH_WORD_INDEX = 10;
export const THRESHOLD_NULLIFIER_C_R_WORD_INDEX = 11;
export const THRESHOLD_NULLIFIER_COMMITMENT_WORD_INDEX = 12;
export const THRESHOLD_NULLIFIER_WORD_COUNT = 13;

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

// Extract the messageDigest the proof bound (as a single 32-byte bigint) from
// the enroll proof's public words [11],[12] (hi*2^128 + lo).
export function extractDigestFromPublicInputs(words) {
    if (!Array.isArray(words) || words.length !== PUBLIC_INPUT_WORD_COUNT) {
        throw new Error(`publicInputs must have exactly ${PUBLIC_INPUT_WORD_COUNT} words`);
    }
    const toBig = (w) => BigInt("0x" + wordToBE32(w).toString("hex"));
    return {
        hi: toBig(words[DIGEST_HI_WORD_INDEX]),
        lo: toBig(words[DIGEST_LO_WORD_INDEX]),
    };
}

// Extract C_r (the cross-proof shared-r commitment) as a bigint from the enroll
// proof's public word [10]. Passed into verifyThresholdNullifierProof as expectedCr so
// the register proof's commit_r(r) must equal it (binds the same blind r across
// the two proofs -> F2).
export function extractCrFromEnroll(words) {
    if (!Array.isArray(words) || words.length !== PUBLIC_INPUT_WORD_COUNT) {
        throw new Error(`publicInputs must have exactly ${PUBLIC_INPUT_WORD_COUNT} words`);
    }
    return BigInt("0x" + wordToBE32(words[C_R_WORD_INDEX]).toString("hex"));
}

// Extract the load-bearing public values from a THRESHOLD oprf_nullifier proof's
// public inputs: M, the published 3-node Kpub set (Kpub1/2/3 as {x,y} bigints),
// the responder indices idx1/idx2, the session epoch, the cross-proof commitment
// c_r, and the returned nullifier (= pedersen(N)) bigint. Used at /v3/register to
// cross-check the proof against the enroll proof (M and C_r), the canonical
// published Kpub set, the current epoch, and the submitted commitment. The proof
// self-attests the per-share DLEQs + idx->Kpub selection + Lagrange combine, so
// the service pins ONLY these values (not Y, which is computed in-circuit).
export function extractThresholdNullifierPublics(words) {
    if (!Array.isArray(words) || words.length !== THRESHOLD_NULLIFIER_WORD_COUNT) {
        throw new Error(
            `threshold nullifier publicInputs must have exactly ${THRESHOLD_NULLIFIER_WORD_COUNT} words`,
        );
    }
    const toBig = (w) => BigInt("0x" + wordToBE32(w).toString("hex"));
    const pt = (i) => ({ x: toBig(words[i]), y: toBig(words[i + 1]) });
    return {
        M: pt(THRESHOLD_NULLIFIER_M_X_WORD_INDEX),
        Kpub1: pt(THRESHOLD_NULLIFIER_KP1_X_WORD_INDEX),
        Kpub2: pt(THRESHOLD_NULLIFIER_KP2_X_WORD_INDEX),
        Kpub3: pt(THRESHOLD_NULLIFIER_KP3_X_WORD_INDEX),
        idx1: toBig(words[THRESHOLD_NULLIFIER_IDX1_WORD_INDEX]),
        idx2: toBig(words[THRESHOLD_NULLIFIER_IDX2_WORD_INDEX]),
        epoch: toBig(words[THRESHOLD_NULLIFIER_EPOCH_WORD_INDEX]),
        cr: toBig(words[THRESHOLD_NULLIFIER_C_R_WORD_INDEX]),
        nullifier: toBig(words[THRESHOLD_NULLIFIER_COMMITMENT_WORD_INDEX]),
    };
}

// — the gate ────────────────────────────────────────────────────────────────

/**
 * Verify a client's enroll_commit_v2 proof AND bind it to the request's M.
 *
 * @param {object} args
 * @param {ProofGate} args.gate         in-process gate (from createGate()).
 * @param {string|Uint8Array} args.proof   the bb proof (0x-hex or bytes).
 * @param {Array<string|bigint>} args.publicInputs  the 13 public-input words.
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

/**
 * Verify a client's THRESHOLD (2-of-3) oprf_nullifier proof and enforce the
 * cross-checks that bind the enrollment commitment back to the certificate at
 * /v3/register. The circuit ITSELF proves, in zero knowledge:
 *   nullifier = pedersen(N),  N = rinv*Y,  r*N == Y (binds r),
 *   commit_r(r) == c_r (binds r to the enroll proof's blind, F2),
 *   for each of the t=2 responders: an epoch-bound per-share Chaum-Pedersen DLEQ
 *     B_i = k_i*M vs the PUBLISHED Kpub_{idx_i} (idx->Kpub selected in-circuit
 *     from the published set, against the PINNED GEN, F1+C-1+session), and
 *   Y = Lagrange-combine(B_a, B_b) with PINNED mod-N coefficients (no free Y).
 * So the proof SELF-ATTESTS the t-of-n evaluation; the service only pins:
 *   (a) the proof's M   == the (cert-bound) enroll proof's M   [HARD: identity
 *       binding; c_r binds r but NOT the identity, so this is non-skippable],
 *   (d) the proof's c_r == the enroll proof's C_r (same blind r across proofs),
 *   (e) the proof's {Kpub1,Kpub2,Kpub3} == the canonical PUBLISHED Kpub set,
 *       by value in index order 1,2,3 (so a forged/foreign key set is rejected;
 *       the in-circuit idx->Kpub selection then makes mislabeling impossible),
 *   (f) the proof's epoch == the current enrollEpoch (the in-circuit binding
 *       rejects a stale DLEQ; the service pins which epoch is live),
 *   (c) the proof's nullifier == the commitment being registered.
 *
 * @param {object} args
 * @param {ProofGate} args.gate    in-process nullifier gate (createGate(OPRF_NULLIFIER_JSON)).
 * @param {string|Uint8Array} args.proof  the bb proof (0x-hex or bytes).
 * @param {Array<string|bigint>} args.publicInputs  the 13 threshold public-input words.
 * @param {{x:bigint,y:bigint}} args.expectedM      M from the enroll proof.
 * @param {Array<{x:bigint,y:bigint}>} args.publishedKpubSet  the canonical
 *        3-node Kpub set for indices [1,2,3].
 * @param {bigint} args.expectedEpoch               the current enrollEpoch.
 * @param {bigint} args.expectedCr                  C_r from the enroll proof.
 * @param {bigint} args.expectedCommitment          the submitted commitment leaf.
 * @returns {Promise<{ ok: true, publics: object } | { ok: false, code: string, detail: string }>}
 */
export async function verifyThresholdNullifierProof({
    gate, proof, publicInputs, expectedM, publishedKpubSet, expectedEpoch, expectedCr, expectedCommitment,
}) {
    // (1) Structural parse + cross-checks first (cheap; reject before the wasm
    //     verifier). A mismatch here means the proof — even if internally valid —
    //     does not bind THIS commitment / M / Kpub-set / epoch, so it cannot admit.
    let proofBytes, piWords, p;
    try {
        proofBytes = proofToBytes(proof);
        piWords = normalizePublicInputs(publicInputs);
        p = extractThresholdNullifierPublics(publicInputs);
    } catch (e) {
        return { ok: false, code: "MalformedProof", detail: e.message };
    }
    if (piWords.length !== THRESHOLD_NULLIFIER_WORD_COUNT) {
        return {
            ok: false,
            code: "MalformedProof",
            detail: `threshold nullifier public_inputs must be ${THRESHOLD_NULLIFIER_WORD_COUNT} field words`,
        };
    }
    // (a) same M as the enroll proof (chains M -> cert). HARD identity binding.
    if (p.M.x !== expectedM.x || p.M.y !== expectedM.y) {
        return {
            ok: false,
            code: "NullifierMismatchedM",
            detail: "nullifier proof M does not equal the enroll proof M",
        };
    }
    // (d) the proof's C_r == the enroll proof's C_r (same blind r across proofs).
    if (p.cr !== expectedCr) {
        return {
            ok: false,
            code: "NullifierMismatchedCr",
            detail: "nullifier proof C_r does not equal the enroll proof C_r",
        };
    }
    // (e) the proof's published Kpub set == the canonical set, BY VALUE in index
    //     order 1,2,3. The in-circuit idx->Kpub selection then makes mislabeling
    //     impossible; the service just pins WHICH 3 keys are the canonical nodes.
    if (!Array.isArray(publishedKpubSet) || publishedKpubSet.length !== 3) {
        return {
            ok: false,
            code: "MalformedConfig",
            detail: "publishedKpubSet must be 3 points [Kpub1,Kpub2,Kpub3]",
        };
    }
    const setOk =
        p.Kpub1.x === publishedKpubSet[0].x && p.Kpub1.y === publishedKpubSet[0].y &&
        p.Kpub2.x === publishedKpubSet[1].x && p.Kpub2.y === publishedKpubSet[1].y &&
        p.Kpub3.x === publishedKpubSet[2].x && p.Kpub3.y === publishedKpubSet[2].y;
    if (!setOk) {
        return {
            ok: false,
            code: "NullifierMismatchedKpubSet",
            detail: "nullifier proof Kpub set does not equal the canonical published set",
        };
    }
    // (f) the proof's epoch == the current enrollEpoch (session binding).
    if (p.epoch !== expectedEpoch) {
        return {
            ok: false,
            code: "NullifierMismatchedEpoch",
            detail: "nullifier proof epoch does not equal the current enrollEpoch",
        };
    }
    // (c) the proof's returned nullifier is exactly the commitment being registered.
    if (p.nullifier !== expectedCommitment) {
        return {
            ok: false,
            code: "NullifierMismatchedCommitment",
            detail: "nullifier proof commitment does not equal the registered commitment",
        };
    }

    // (2) Cryptographic verification IN-PROCESS via bb.js (no `bb` CLI).
    let valid;
    try {
        valid = await gate.verify({ proof: proofBytes, publicInputs: piWords });
    } catch (e) {
        return {
            ok: false,
            code: "ProofRejected",
            detail: (e.message || "bb.js verifyProof failed").toString().trim().slice(0, 300),
        };
    }
    if (!valid) {
        return { ok: false, code: "ProofRejected", detail: "nullifier proof verification failed" };
    }
    return { ok: true, publics: p };
}
