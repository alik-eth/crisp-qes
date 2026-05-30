// Minimal standalone Fastify server for the v3 Grumpkin VOPRF node (build,
// unaudited). This is the v3 analogue of packages/oprf/src/app.ts's
// POST /oprf/blind-eval, but:
//   * over Grumpkin (reuses ../lib.mjs via ./oprf-node.mjs), and
//   * gated on a CLIENT ZK PROOF instead of a cleartext Diia attestation cert.
//
// IMPORTANT: this is standalone and does NOT import or touch the live v2
// service in packages/oprf/src/.
//
// ── Gating status ────────────────────────────────────────────────────────────
//   GATED NOW : (1) request shape validation (M must be a valid on-curve
//               Grumpkin point in the x||y wire format); (2) REAL proof gating —
//               the client's enroll_commit_v2 ZK proof is verified IN-PROCESS
//               via @aztec/bb.js (no `bb` CLI) against a startup-fixed circuit,
//               AND its public-output M is required to equal the request's M,
//               before any evaluation.
//               This replaces the v2 cleartext Diia cert/age attestation.
//   Plus CORS and structured errors.

import Fastify from "fastify";
import fastifyCors from "@fastify/cors";

import { OprfNode, pointFromHex } from "./oprf-node.mjs";
import { createGate, verifyEnrollCommitProof } from "./proof-gate.mjs";
import { Attester } from "./attester.mjs";
import { MerkleIndex, TREE_DEPTH, GENESIS_ROOT, bigintToHex32 } from "./merkle.mjs";

// — EnrollmentRegistry deployment the v3 attester signs root updates for ────────
// Pinned to the SAME live registry v2 enrolls into (Sepolia), so v3 commitments
// become leaves alongside v2's. Override via env for other deployments.
const DEFAULT_CHAIN_ID = 11155111; // Sepolia
const DEFAULT_ENROLLMENT_REGISTRY = "0x0214504C1Be6d664bbE3AE6687507aBE19A36d1a";
// The attester address EnrollmentRegistry.updateRoot trusts. The human sets
// V3_ATTESTER_KEY to the secp256k1 key whose address is this; we assert it at
// boot in production so a wrong key fails closed instead of producing sigs the
// contract silently rejects.
const TRUSTED_ATTESTER_ADDR = "0x876E995c6f4f158ED5D746B5e10A00329df1E246";

// Field range for a Grumpkin/BN254 commitment leaf (< 2^254 is a valid Fr).
const FR_MAX = 1n << 254n;
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

// — Body validation (hand-rolled to keep the module zero-extra-deps; mirrors
//   the intent of the zod validators in v2 app.ts) ───────────────────────────

const POINT_HEX = /^0x[0-9a-fA-F]{128}$/;

function validateBlindEvalBody(body) {
    if (body === null || typeof body !== "object") {
        return { ok: false, detail: "body must be a JSON object" };
    }
    const { M, proof, publicInputs } = body;
    if (typeof M !== "string" || !POINT_HEX.test(M)) {
        return {
            ok: false,
            detail: "M must be 0x-prefixed 64-byte (x||y) Grumpkin point hex",
        };
    }
    // proof is REQUIRED now: a bb proof as 0x-hex string or byte array.
    if (typeof proof !== "string" && !Array.isArray(proof)) {
        return { ok: false, detail: "proof must be 0x-hex string or byte array" };
    }
    // publicInputs is REQUIRED: the circuit's public-input field words
    // (0x-hex strings), including the public output M the proof commits to.
    if (!Array.isArray(publicInputs) || publicInputs.length === 0) {
        return {
            ok: false,
            detail: "publicInputs must be a non-empty array of 0x-hex field words",
        };
    }
    return { ok: true, data: { M, proof, publicInputs } };
}

// Validate POST /v3/register body: { commitment, proof, publicInputs }.
// `commitment` is the enrollment leaf the client derived = pedersen([N.x,N.y])
// where N = rinv * (k*M) is the unblinded OPRF output (see e2e-test.mjs /
// oprf-node.mjs). proof + publicInputs are the SAME enroll_commit_v2 artifacts
// the blind-eval gate consumes.
function validateRegisterBody(body) {
    if (body === null || typeof body !== "object") {
        return { ok: false, detail: "body must be a JSON object" };
    }
    const { commitment, proof, publicInputs } = body;
    if (typeof commitment !== "string" || !HEX32.test(commitment)) {
        return { ok: false, detail: "commitment must be 0x-prefixed 32-byte hex" };
    }
    if (BigInt(commitment) >= FR_MAX) {
        return { ok: false, detail: "commitment exceeds Fr range (must be < 2^254)" };
    }
    if (typeof proof !== "string" && !Array.isArray(proof)) {
        return { ok: false, detail: "proof must be 0x-hex string or byte array" };
    }
    if (!Array.isArray(publicInputs) || publicInputs.length === 0) {
        return {
            ok: false,
            detail: "publicInputs must be a non-empty array of 0x-hex field words",
        };
    }
    return { ok: true, data: { commitment, proof, publicInputs } };
}

/**
 * Resolve the secp256k1 attester key from env V3_ATTESTER_KEY (32-byte hex).
 * REQUIRED in production (the human sets it to the key whose address is
 * TRUSTED_ATTESTER_ADDR). Outside production a labeled deterministic dev key is
 * used so tests / local runs work without secrets — its address will NOT be the
 * trusted one, so on-chain submission would be rejected (fine for local demo).
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string} 0x-prefixed 32-byte hex private key.
 */
export function resolveAttesterKey(env = process.env) {
    const raw = env.V3_ATTESTER_KEY;
    if (raw) {
        const h = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw;
        if (!/^[0-9a-fA-F]{64}$/.test(h)) {
            throw new Error("V3_ATTESTER_KEY must be 32-byte hex (64 hex chars)");
        }
        return `0x${h}`;
    }
    if (env.NODE_ENV === "production") {
        throw new Error("[oprf-v3] V3_ATTESTER_KEY is required in production");
    }
    // eslint-disable-next-line no-console
    console.warn("[oprf-v3] V3_ATTESTER_KEY not set — using deterministic dev key (NOT the trusted attester)");
    const label = "crisp-qes-v3-grumpkin-dev-attester-k";
    const SECP_N =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const raw2 = BigInt("0x" + Buffer.from(label).toString("hex"));
    const k = (raw2 % (SECP_N - 1n)) + 1n;
    return `0x${k.toString(16).padStart(64, "0")}`;
}

// — App builder (exported so the roundtrip test can run it in-process) ────────

export async function buildApp(opts = {}) {
    const node = opts.node ?? new OprfNode(opts.k ?? defaultDevKey());
    const corsOrigins = opts.corsAllowedOrigins ?? ["*"];
    const allowAll = corsOrigins.includes("*");

    // — Proof gate (fixed per circuit, in-process) ───────────────────────────
    // Build the enroll_commit_v2 verifier ONCE at startup via @aztec/bb.js
    // (loads the circuit bytecode + derives the vk in-wasm; no `bb` CLI). Tests
    // may inject a prebuilt gate via opts.gate. If construction fails (bb.js
    // can't load the circuit / artifact absent) we fail closed: the gate cannot
    // be satisfied and every request is rejected.
    let gate = opts.gate ?? null;
    let gateError = null;
    if (!gate) {
        try {
            gate = await createGate();
        } catch (e) {
            gateError = e.message;
        }
    }

    // — Enrollment chain wiring (attester + Pedersen-Merkle store) ────────────
    // The Merkle store is in-memory (demo): commitments are NOT persisted across
    // restarts. The attester signs EnrollmentRegistry.updateRoot digests so the
    // existing relayer /v2/enroll can post a v3 commitment to the SAME contract.
    const chainId = opts.chainId ?? DEFAULT_CHAIN_ID;
    const enrollmentRegistry = opts.enrollmentRegistry ?? DEFAULT_ENROLLMENT_REGISTRY;
    const attester = new Attester(opts.attesterKey ?? resolveAttesterKey());
    if (process.env.NODE_ENV === "production"
        && attester.address.toLowerCase() !== TRUSTED_ATTESTER_ADDR.toLowerCase()) {
        throw new Error(
            `[oprf-v3] V3_ATTESTER_KEY address ${attester.address} != trusted ` +
                `attester ${TRUSTED_ATTESTER_ADDR}; EnrollmentRegistry would reject updateRoot`,
        );
    }
    const merkle = opts.merkle ?? (await MerkleIndex.fromLeaves(opts.leaves ?? []));

    const app = Fastify({ logger: opts.logger ?? { level: "warn" } });

    await app.register(fastifyCors, {
        origin: allowAll ? true : corsOrigins,
        methods: ["GET", "POST", "OPTIONS"],
        credentials: false,
        maxAge: 86400,
    });

    // — GET /healthz ─────────────────────────────────────────────────────
    app.get("/healthz", async () => {
        const snap = merkle.snapshot();
        return {
            ok: true,
            suite: "grumpkin-SHA256-SvdW",
            mode: "VOPRF v3 (build, unaudited — single node, proof-gating ENFORCED)",
            curve: "Grumpkin (y^2 = x^3 - 17)",
            wireFormat: "point = 0x{x:32B BE}{y:32B BE}; scalar = decimal bigint",
            Kpub: node.publicKeyHex(),
            proofGating: gateError
                ? `unavailable (gate init failed: ${gateError}) — failing closed`
                : "enforced (in-process bb.js verify of enroll_commit_v2 proof + M-binding)",
            // Enrollment chain state (in-memory, demo — not persisted).
            treeDepth: TREE_DEPTH,
            enrolledCount: snap.leafCount,
            genesisRoot: bigintToHex32(GENESIS_ROOT),
            currentRoot: bigintToHex32(snap.root),
            attesterAddr: attester.address,
            chainId,
            enrollmentRegistry,
        };
    });

    // — POST /v3/blind-eval ──────────────────────────────────────────────
    app.post("/v3/blind-eval", async (req, reply) => {
        const parsed = validateBlindEvalBody(req.body);
        if (!parsed.ok) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.detail });
        }
        const { M, proof, publicInputs } = parsed.data;

        // — M validity gate (ENFORCED) ───────────────────────────────────
        // Reject anything that is not a valid on-curve Grumpkin point before
        // burning a scalar-mul, mirroring v2's BadBlindedInput path. We also
        // need M's affine coords to bind the proof to this request.
        let Mpoint;
        try {
            Mpoint = pointFromHex(M);
        } catch (e) {
            return reply.code(400).send({
                error: "BadBlindedInput",
                detail: `not a valid Grumpkin point: ${e.message}`,
            });
        }
        const Maff = Mpoint.toAffine();

        // — Proof gate (ENFORCED) ─────────────────────────────────────────
        // Fail closed if the gate could not be built at startup.
        if (!gate) {
            req.log.error({ gateError }, "proof gate unavailable — failing closed");
            return reply.code(503).send({
                error: "ProofGateUnavailable",
                detail: "proof gate unavailable; node refuses to evaluate",
            });
        }
        // Verify the enroll_commit_v2 proof AND require its public-output M to
        // equal the request's M. Any failure => 4xx, NO evaluation.
        let gateResult;
        try {
            gateResult = await verifyEnrollCommitProof({
                gate,
                proof,
                publicInputs,
                expectedM: { x: Maff.x, y: Maff.y },
            });
        } catch (e) {
            req.log.error({ err: e.message }, "proof gate errored");
            return reply.code(400).send({
                error: "MalformedProof",
                detail: e.message,
            });
        }
        if (!gateResult.ok) {
            const status = gateResult.code === "ProofRejected" ? 401 : 400;
            req.log.info({ code: gateResult.code }, "v3 blind-eval proof rejected");
            return reply.code(status).send({ error: gateResult.code, detail: gateResult.detail });
        }
        req.log.info("v3 blind-eval proof accepted");

        // — BlindEvaluate + DLEQ ─────────────────────────────────────────
        let out;
        try {
            out = await node.evaluate(M);
        } catch (e) {
            req.log.error({ err: e.message }, "evaluate failed");
            return reply
                .code(500)
                .send({ error: "EvalError", detail: e.message });
        }

        // Wire shape: { Y: pointHex, dleq: { c, z }, Kpub: pointHex }.
        // c and z are group-order scalars (< N) sent as decimal strings to
        // avoid any BigInt->JSON precision loss; the client re-parses with
        // BigInt(). Echo proofAccepted so clients see the gating posture.
        return reply.code(200).send({
            Y: out.Y,
            dleq: { c: out.dleq.c.toString(), z: out.dleq.z.toString() },
            Kpub: out.Kpub,
            proofAccepted: "verified (in-process bb.js verify + M-binding)",
        });
    });

    // commitment(0x-hex) -> leafIndex, for the recovery path lookup.
    const leafIndexOf = opts.leafIndexOf ?? new Map();

    // — POST /v3/register ────────────────────────────────────────────────
    // Land a v3 enrollment commitment on-chain via the SAME EnrollmentRegistry
    // v2 uses. GATED on the SAME enroll_commit_v2 ZK proof the blind-eval gate
    // verifies (the proof attests, in zero knowledge, that the blinded element
    // M was honestly derived as M = r*H2C(RNOKPP) from a valid age>=18 cert).
    //
    // M-relationship note: the proof's public output is M, NOT the commitment.
    // The enrollment commitment = pedersen([N.x, N.y]) with N = rinv*(k*M) is
    // derived CLIENT-SIDE after blind-eval and depends on the node secret k, so
    // it cannot appear in the (offline) enroll_commit_v2 proof. We therefore
    // (a) cryptographically verify the proof (admission), (b) bind it to its own
    // public-output M (so it is a real, well-formed enroll proof), and (c) treat
    // the submitted commitment as a valid Fr leaf that is unique in the tree.
    // This mirrors v2's intent (a proof/attestation gates the append) within the
    // constraints of the blinded VOPRF; full M<->commitment binding would need
    // an extra circuit, tracked for v3-prod (see SECURITY.md).
    app.post("/v3/register", async (req, reply) => {
        const parsed = validateRegisterBody(req.body);
        if (!parsed.ok) {
            return reply.code(400).send({ error: "BadRequest", detail: parsed.detail });
        }
        const { commitment, proof, publicInputs } = parsed.data;

        // — Proof gate (ENFORCED), same as blind-eval ─────────────────────
        if (!gate) {
            req.log.error({ gateError }, "proof gate unavailable — failing closed");
            return reply.code(503).send({
                error: "ProofGateUnavailable",
                detail: "proof gate unavailable; node refuses to register",
            });
        }
        // Bind the proof to its own public-output M (words 12,13). We don't have
        // a separate request M here, so expectedM == the proof's own M — this
        // still exercises the full structural + crypto verification path and
        // rejects malformed / invalid proofs.
        let expectedM;
        try {
            const { extractMFromPublicInputs } = await import("./proof-gate.mjs");
            expectedM = extractMFromPublicInputs(publicInputs);
        } catch (e) {
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }
        let gateResult;
        try {
            gateResult = await verifyEnrollCommitProof({ gate, proof, publicInputs, expectedM });
        } catch (e) {
            req.log.error({ err: e.message }, "register proof gate errored");
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }
        if (!gateResult.ok) {
            const status = gateResult.code === "ProofRejected" ? 401 : 400;
            req.log.info({ code: gateResult.code }, "v3 register proof rejected");
            return reply.code(status).send({ error: gateResult.code, detail: gateResult.detail });
        }

        // — Collision check ───────────────────────────────────────────────
        if (leafIndexOf.has(commitment)) {
            return reply.code(409).send({ error: "AlreadyEnrolled", commitment });
        }

        // — Append + attest ───────────────────────────────────────────────
        const leaf = BigInt(commitment);
        const append = await merkle.append(leaf);
        leafIndexOf.set(commitment, append.leafIndex);

        const { sig: attesterSig, innerDigest } = attester.sign({
            oldRoot: append.oldRoot,
            newRoot: append.newRoot,
            newCommitments: [leaf],
            chainId,
            enrollmentRegistry,
        });

        req.log.info(
            { leafIndex: append.leafIndex, newRoot: bigintToHex32(append.newRoot) },
            "v3 register: appended commitment + signed updateRoot",
        );

        // Same shape v2's /oprf/register returns so the existing relayer
        // /v2/enroll can post it to EnrollmentRegistry.updateRoot.
        return reply.code(200).send({
            leafIndex: append.leafIndex,
            merklePath: append.path.map(bigintToHex32),
            merklePathIndices: append.indices,
            oldRoot: bigintToHex32(append.oldRoot),
            newRoot: bigintToHex32(append.newRoot),
            newCommitments: [commitment],
            attesterSig,
            attesterAddr: attester.address,
            attesterDigest: innerDigest,
            // Diagnostic extras — not consumed by the contract call.
            chainId,
            enrollmentRegistry,
        });
    });

    // — GET /v3/enrollment/:commitment/path ───────────────────────────────
    // Recovery path lookup (mirrors v2's GET /enrollment/:commitment/path). No
    // append happens, so oldRoot == newRoot and there is no fresh attesterSig.
    app.get("/v3/enrollment/:commitment/path", async (req, reply) => {
        const commitment = req.params.commitment;
        if (typeof commitment !== "string" || !HEX32.test(commitment)) {
            return reply.code(400).send({
                error: "BadRequest",
                detail: "commitment must be 0x-prefixed 32-byte hex",
            });
        }
        const idx = leafIndexOf.get(commitment);
        if (idx === undefined) {
            return reply.code(404).send({ error: "NotEnrolled", commitment });
        }
        const proof = await merkle.proofAt(idx);
        const rootHex = bigintToHex32(proof.root);
        return reply.code(200).send({
            leafIndex: proof.leafIndex,
            merklePath: proof.path.map(bigintToHex32),
            merklePathIndices: proof.indices,
            oldRoot: rootHex,
            newRoot: rootHex,
            root: rootHex,
        });
    });

    return app;
}

// Grumpkin group order (re-exported from oprf-node.mjs as N).
const GRUMPKIN_N =
    21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Deterministic dev key — explicitly NOT a production secret. Matches the
// labeling style of gen-nullifier-witness.mjs's `det()` helper. Used only when
// GRUMPKIN_OPRF_KEY is unset outside production.
function defaultDevKey() {
    const label = "crisp-qes-v3-grumpkin-dev-node-k";
    const raw = BigInt("0x" + Buffer.from(label).toString("hex"));
    // Reduce into [1, N).
    return (raw % (GRUMPKIN_N - 1n)) + 1n;
}

/**
 * Resolve the node secret scalar k from the GRUMPKIN_OPRF_KEY env var (32-byte
 * big-endian hex, 0x-optional), reduced into [1, N). Required in production;
 * outside production a labeled deterministic dev key is used. Mirrors v2's
 * OPRF_KEY handling in packages/oprf/src/config.ts.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {bigint}
 */
export function resolveNodeKey(env = process.env) {
    const isProd = env.NODE_ENV === "production";
    const raw = env.GRUMPKIN_OPRF_KEY;
    if (raw) {
        const h = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw;
        if (!/^[0-9a-fA-F]{64}$/.test(h)) {
            throw new Error("GRUMPKIN_OPRF_KEY must be 32-byte hex (64 hex chars)");
        }
        const k = BigInt("0x" + h) % GRUMPKIN_N;
        if (k === 0n) throw new Error("GRUMPKIN_OPRF_KEY reduces to 0 mod N");
        return k;
    }
    if (isProd) {
        throw new Error("[oprf-v3] GRUMPKIN_OPRF_KEY is required in production");
    }
    // eslint-disable-next-line no-console
    console.warn("[oprf-v3] GRUMPKIN_OPRF_KEY not set — using deterministic dev key");
    return defaultDevKey();
}

// — CLI entrypoint: `node server.mjs` ────────────────────────────────────────
const isMain =
    import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith("server.mjs");

if (isMain) {
    const port = Number(process.env.PORT ?? 8788);
    // Bind all interfaces in a container (Fly health checks hit the VM IP);
    // default to loopback for local dev. Override with HOST.
    const host = process.env.HOST ?? (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
    const app = await buildApp({
        k: resolveNodeKey(),
        attesterKey: resolveAttesterKey(),
        logger: { level: "info" },
    });
    await app.listen({ port, host });
    // logger already prints the listen line.
}
