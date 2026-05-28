// Fastify wiring for the single-node v2.1 OPRF service.
//
// Routes (full shapes in the v2.1 spec § 2 + the task brief):
//
//   POST /oprf/blind-eval                — BlindEvaluate (RFC 9497 § 3.3.2)
//   POST /oprf/register                  — append commitment to Merkle tree
//   GET  /healthz                        — boot + state snapshot
//   GET  /enrollment/:commitment/path    — on-demand Merkle inclusion proof
//
// v2.1-prod: in the threshold deploy these routes are spoken by every
// ciphernode; the client Lagrange-combines BlindEvaluate responses and
// posts the resulting commitment to a *coordinator* that runs `/register`
// once per fresh commitment. The wire format stays identical so v2-web
// doesn't change.

import Fastify, { type FastifyInstance } from "fastify";
import fastifyCors from "@fastify/cors";
import { bytesToHex } from "@noble/hashes/utils";
import { z } from "zod";

import { Attester } from "./attester.js";
import type { OprfConfig } from "./config.js";
import { EnrollmentStore } from "./db.js";
import { MerkleIndex, TREE_DEPTH } from "./merkle.js";
import {
    blindEvaluate,
    derivePublicKey,
    fromHex,
    ristretto255,
    toHex,
    type BlindEvaluateOutput,
} from "./oprf.js";
import {
    AttestationError,
    verifyAttestation,
} from "./attestation.js";
import { commitmentFromOprfOutput } from "./pedersen.js";

// — Body validators ────────────────────────────────────────────────────────

const hex32 = z
    .string()
    .regex(/^0x[0-9a-fA-F]{64}$/, "expected 0x-prefixed 32-byte hex");
const base64 = z.string().regex(/^[A-Za-z0-9+/=]+$/, "expected base64");

const BlindEvalBody = z.object({
    blindedInput: hex32, // M = r * H_to_curve(input), 32-byte ristretto255 enc
    attestation: z.object({ p7s: base64 }),
});
const RegisterBody = z.object({
    commitment: hex32,
    blindedInputUsed: hex32,
    /**
     * Unblinded OPRF output N = k * H_to_curve(input), 32-byte ristretto255
     * encoding. The server uses this to verify that the client-supplied
     * `commitment` equals `pedersen_hash([N_hi, N_lo], 0)`.
     *
     * v2.1-prod simplification note: in the threshold deploy the
     * coordinator never receives N — instead the ciphernode quorum signs
     * a "this commitment was honestly derived" attestation that the
     * coordinator verifies. The demo accepts N directly to keep the
     * single-node Trust-Me model explicit.
     */
    unblindedOutput: hex32,
});

const CommitmentParam = z.object({ commitment: hex32 });

// — Builder ────────────────────────────────────────────────────────────────

export interface BuildAppOptions {
    config: OprfConfig;
    /** Pre-instantiated store, useful for tests with `:memory:` dbs. */
    store?: EnrollmentStore;
    /** Pre-instantiated Merkle index, useful for tests. */
    merkle?: MerkleIndex;
}

export async function buildApp(
    opts: BuildAppOptions,
): Promise<FastifyInstance> {
    const cfg = opts.config;
    const store = opts.store ?? new EnrollmentStore(cfg.dbPath);
    const attester = new Attester(cfg.attesterKey);

    // OPRF k as a bigint (the encoding in cfg.oprfKey is little-endian).
    const k = scalarFromLE(cfg.oprfKey);
    const oprfPubkey = derivePublicKey(k);
    cfg.oprfPubkey = oprfPubkey;

    // Rebuild Merkle from persisted commitments (cheap at demo scale).
    const merkle =
        opts.merkle ??
        (await MerkleIndex.fromLeaves(
            await commitmentsToLeaves(store.allInOrder()),
        ));

    // Stamp last-known root + pubkey snapshot for the operator UI.
    store.kvSet("oprf_pubkey", `0x${bytesToHex(oprfPubkey)}`);
    store.kvSet("attester_addr", attester.address);
    store.kvSet("current_root", bigintToHex32(merkle.snapshot().root));

    const app = Fastify({
        logger: { level: cfg.isProd ? "info" : "warn" },
    });

    const allowAll = cfg.corsAllowedOrigins.includes("*");
    void app.register(fastifyCors, {
        origin: allowAll ? true : cfg.corsAllowedOrigins,
        methods: ["GET", "POST", "OPTIONS"],
        credentials: false,
        maxAge: 86400,
    });

    // — /healthz ────────────────────────────────────────────────────────
    app.get("/healthz", async () => {
        const snap = merkle.snapshot();
        return {
            ok: true,
            suite: "ristretto255-SHA512",
            mode: "VOPRF (v2.1 demo: single node)",
            treeDepth: TREE_DEPTH,
            enrolledCount: snap.leafCount,
            currentRoot: bigintToHex32(snap.root),
            oprfPubkey: `0x${bytesToHex(oprfPubkey)}`,
            attesterAddr: attester.address,
            chainId: cfg.chainId,
            enrollmentRegistry: cfg.enrollmentRegistry,
        };
    });

    // — POST /oprf/blind-eval ───────────────────────────────────────────
    app.post("/oprf/blind-eval", async (req, reply) => {
        const parsed = BlindEvalBody.safeParse(req.body);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }

        const { blindedInput, attestation } = parsed.data;

        // 1. Diia attestation gate. v2.1-prod also binds attestation
        //    payload → blindedInput; demo only checks the TINUA- prefix.
        try {
            const p7sBytes = base64ToBytes(attestation.p7s);
            const verified = verifyAttestation(p7sBytes);
            req.log.info(
                { serial: verified.subjectSerialAscii },
                "attestation ok",
            );
        } catch (e) {
            if (e instanceof AttestationError) {
                return reply
                    .code(401)
                    .send({ error: e.code, detail: e.message });
            }
            throw e;
        }

        // 2. BlindEvaluate + DLEQ proof.
        let out: BlindEvaluateOutput;
        try {
            out = blindEvaluate(fromHex(blindedInput), k, oprfPubkey);
        } catch (e) {
            return reply.code(400).send({
                error: "BadBlindedInput",
                detail: `not a valid ristretto255 point: ${(e as Error).message}`,
            });
        }

        return reply.code(200).send({
            Y: toHex(out.Y),
            proof: toHex(out.proof),
            // Echo so the client doesn't have to re-derive it; matches our
            // single-node /register reconciliation field.
            blindedInput,
            // Convenience: clients may want the suite-specific server pub
            // without an extra /healthz round-trip on first contact.
            oprfPubkey: `0x${bytesToHex(oprfPubkey)}`,
        });
    });

    // — POST /oprf/register ─────────────────────────────────────────────
    app.post("/oprf/register", async (req, reply) => {
        const parsed = RegisterBody.safeParse(req.body);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }
        // Zod regex-validated; cast to template-literal type for db.ts.
        const commitment = parsed.data.commitment as `0x${string}`;
        const blindedInputUsed = parsed.data.blindedInputUsed as `0x${string}`;
        const unblindedOutput = parsed.data.unblindedOutput as `0x${string}`;

        // 1. Commitment must be exactly pedersen([N_hi, N_lo], 0). Prevents
        //    a client from registering arbitrary tree leaves.
        const N = fromHex(unblindedOutput);
        const expected = await commitmentFromOprfOutput(N);
        const observed = hexToBigInt(commitment);
        if (expected !== observed) {
            return reply.code(400).send({
                error: "CommitmentMismatch",
                detail:
                    "commitment != pedersen([N_hi, N_lo], 0) — the supplied " +
                    "unblindedOutput does not derive the claimed commitment",
            });
        }

        // 2. Collision check.
        if (store.has(commitment)) {
            return reply
                .code(409)
                .send({ error: "AlreadyEnrolled", commitment });
        }

        // 3. Append to in-memory Merkle, persist, attest.
        const append = await merkle.append(observed);
        try {
            store.insert({
                commitment,
                leafIndex: append.leafIndex,
                enrolledAt: Math.floor(Date.now() / 1000),
                blindedInput: blindedInputUsed,
            });
        } catch (e) {
            // Race / unique-constraint: someone slipped in between has()
            // and insert(). Bail with the same 409 the client expects.
            return reply
                .code(409)
                .send({ error: "AlreadyEnrolled", commitment });
        }

        const { sig: attesterSig, innerDigest: digest } = attester.sign({
            oldRoot: append.oldRoot,
            newRoot: append.newRoot,
            newCommitments: [observed],
            chainId: cfg.chainId,
            enrollmentRegistry: cfg.enrollmentRegistry,
        });
        store.kvSet("current_root", bigintToHex32(append.newRoot));

        return reply.code(200).send({
            leafIndex: append.leafIndex,
            merklePath: append.path.map(bigintToHex32),
            merklePathIndices: append.indices,
            oldRoot: bigintToHex32(append.oldRoot),
            newRoot: bigintToHex32(append.newRoot),
            // Exactly the calldata the client passes to
            // EnrollmentRegistry.updateRoot(newRoot, newCommitments, sig).
            newCommitments: [commitment],
            attesterSig,
            attesterAddr: attester.address,
            attesterDigest: digest,
            chainId: cfg.chainId,
            enrollmentRegistry: cfg.enrollmentRegistry,
        });
    });

    // — GET /enrollment/:commitment/path ───────────────────────────────
    app.get("/enrollment/:commitment/path", async (req, reply) => {
        const parsed = CommitmentParam.safeParse(req.params);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }
        const commitment = parsed.data.commitment as `0x${string}`;
        const idx = store.leafIndexFor(commitment);
        if (idx === null) {
            return reply.code(404).send({ error: "NotEnrolled", commitment });
        }
        const proof = await merkle.proofAt(idx);
        return reply.code(200).send({
            leafIndex: proof.leafIndex,
            merklePath: proof.path.map(bigintToHex32),
            merklePathIndices: proof.indices,
            root: bigintToHex32(proof.root),
        });
    });

    return app;
}

// — Helpers ────────────────────────────────────────────────────────────────

/**
 * Decode a 32-byte little-endian scalar mod n.
 *
 * RFC 9496 ristretto255 scalars are LE. We reduce after read so any
 * 256-bit byte string is a valid OPRF_KEY (matches RFC 8032 §5.1.5
 * SHA-512 → scalar derivation). Without the reduction a value ≥ n
 * triggers `invalid scalar` inside `Point.multiply`.
 *
 * Wire format reminder for ops: `OPRF_KEY` env hex is read as a 32-byte
 * little-endian integer, then reduced mod ristretto255 curve order n
 * before being used. v2-web must use the same LE convention if it ever
 * derives a scalar from the same hex.
 */
function scalarFromLE(bytes: Uint8Array): bigint {
    let acc = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        acc = (acc << 8n) | BigInt(bytes[i]!);
    }
    return ristretto255.Point.Fn.create(acc);
}

function bigintToHex32(v: bigint): `0x${string}` {
    if (v < 0n) throw new Error("bigintToHex32: negative");
    let hex = v.toString(16);
    if (hex.length > 64) {
        throw new Error("bigintToHex32: value exceeds 32 bytes");
    }
    return `0x${hex.padStart(64, "0")}`;
}

function hexToBigInt(h: string): bigint {
    return BigInt(h);
}

function base64ToBytes(b64: string): Uint8Array {
    return new Uint8Array(Buffer.from(b64, "base64"));
}

async function commitmentsToLeaves(
    commitments: `0x${string}`[],
): Promise<bigint[]> {
    // Commitments are stored as 32-byte hex. The Merkle leaf for the v2
    // circuit is `pedersen([s], 0)`, but s is private to the citizen — the
    // EnrollmentRegistry tree commits to the *commitments themselves*, not
    // to leaves derived from s. (The circuit recomputes the leaf from s and
    // walks the path; the path is over commitments.) Demo simplification:
    // we treat the commitment hex as the Merkle leaf field element.
    //
    // v2-circuit may instead want a derivation `leaf = commitment` (since
    // commitment is already `pedersen([N_hi, N_lo], 0)`) — confirmed with
    // team-lead via the pinned formula. If circuit picks a different
    // derivation later, this single function is the seam to update.
    return commitments.map((c) => BigInt(c));
}
