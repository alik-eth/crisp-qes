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
//   * The verification key (vk) is FIXED per circuit. We compute it once at
//     startup from the committed circuit artifact via `bb write_vk`.
//   * Each request carries { proof, publicInputs } (both 0x-hex / arrays of
//     0x-hex field words) plus M. We:
//       (1) confirm the proof's public-output M words equal the request's M,
//       (2) shell out to `bb verify` against temp {proof, public_inputs, vk}.
//     BOTH must hold, else the request is rejected (4xx) and NOT evaluated.
//
// PUBLIC INPUTS LAYOUT (enroll_commit_v2, 14 field words of 32 bytes BE):
//   [0..8)  today[8]  (ASCII bytes of YYYYMMDD)
//   [8..12) c1,c2,c3,c4  (SvdW suite constants)
//   [12]    M.x   <- the circuit's first public return value
//   [13]    M.y   <- the circuit's second public return value
// So M = (publicInputs[12], publicInputs[13]).

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);

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

const BB_BIN = process.env.BB_BIN || "bb";

// — vk derivation (once at startup) ──────────────────────────────────────────

/**
 * Compute the verification key bytes for the enroll_commit_v2 circuit by
 * running `bb write_vk` against its committed bytecode. The vk is deterministic
 * for a fixed circuit, so callers cache the returned Buffer for the process
 * lifetime. Throws if bb is missing or the artifact can't be found.
 *
 * @param {string} [circuitJson] path to the circuit bytecode JSON.
 * @returns {Promise<Buffer>} raw vk bytes.
 */
export async function computeVk(circuitJson = ENROLL_COMMIT_V2_JSON) {
    const dir = await mkdtemp(join(tmpdir(), "v3gate-vk-"));
    try {
        await execFileP(BB_BIN, ["write_vk", "-b", circuitJson, "-o", dir]);
        const { readFile } = await import("node:fs/promises");
        return await readFile(join(dir, "vk"));
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
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

// Concatenate an array of field words into the flat little-of-words big-endian
// buffer layout that bb's `-i`/public_inputs file expects (each word 32B BE).
function publicInputsToBuffer(words) {
    if (!Array.isArray(words)) throw new Error("publicInputs must be an array");
    return Buffer.concat(words.map(wordToBE32));
}

// Parse a proof field that may arrive as 0x-hex or a byte array into a Buffer.
function proofToBuffer(proof) {
    if (Buffer.isBuffer(proof)) return proof;
    if (typeof proof === "string") {
        const h = proof.startsWith("0x") || proof.startsWith("0X") ? proof.slice(2) : proof;
        if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2 !== 0) {
            throw new Error("proof hex malformed");
        }
        return Buffer.from(h, "hex");
    }
    if (Array.isArray(proof)) return Buffer.from(proof);
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
 * @param {Buffer} args.vk             fixed circuit vk (from computeVk()).
 * @param {string|Uint8Array} args.proof   the bb proof (0x-hex or bytes).
 * @param {Array<string|bigint>} args.publicInputs  the 14 public-input words.
 * @param {{x: bigint, y: bigint}} args.expectedM   M parsed from the request.
 * @returns {Promise<{ ok: true } | { ok: false, code: string, detail: string }>}
 */
export async function verifyEnrollCommitProof({ vk, proof, publicInputs, expectedM }) {
    // (1) Structural + M-binding checks first — cheap, and they let us reject
    //     mismatched-M without ever spawning bb.
    let proofBuf, piBuf, m;
    try {
        proofBuf = proofToBuffer(proof);
        piBuf = publicInputsToBuffer(publicInputs);
        m = extractMFromPublicInputs(publicInputs);
    } catch (e) {
        return { ok: false, code: "MalformedProof", detail: e.message };
    }
    if (piBuf.length !== PUBLIC_INPUT_WORD_COUNT * FIELD_BYTES) {
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

    // (2) Cryptographic verification via `bb verify` over temp files.
    const dir = await mkdtemp(join(tmpdir(), "v3gate-verify-"));
    try {
        const proofPath = join(dir, "proof");
        const piPath = join(dir, "public_inputs");
        const vkPath = join(dir, "vk");
        await Promise.all([
            writeFile(proofPath, proofBuf),
            writeFile(piPath, piBuf),
            writeFile(vkPath, vk),
        ]);
        try {
            await execFileP(BB_BIN, [
                "verify",
                "-k", vkPath,
                "-p", proofPath,
                "-i", piPath,
            ]);
        } catch (e) {
            // Non-zero exit => invalid proof (or bb error). Treat as rejection.
            return {
                ok: false,
                code: "ProofRejected",
                detail: (e.stderr || e.message || "bb verify failed").toString().trim().slice(0, 300),
            };
        }
        return { ok: true };
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
}
