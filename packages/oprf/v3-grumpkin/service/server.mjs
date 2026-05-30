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
import {
    createGate,
    verifyEnrollCommitProof,
    verifyNullifierProof,
    extractMFromPublicInputs,
    OPRF_NULLIFIER_JSON,
} from "./proof-gate.mjs";
import { Attester } from "./attester.mjs";
import { MerkleIndex, TREE_DEPTH, GENESIS_ROOT, bigintToHex32 } from "./merkle.mjs";

// — EnrollmentRegistry deployment the v3 attester signs root updates for ────────
// FRESH clean-slate registry (genesis, leafCount 0) so the v3 service's
// in-memory genesis tree matches the on-chain root and the first updateRoot's
// oldRoot is accepted. Override via env ENROLLMENT_REGISTRY / CHAIN_ID.
const DEFAULT_CHAIN_ID = Number(process.env.CHAIN_ID ?? 11155111); // Sepolia
const DEFAULT_ENROLLMENT_REGISTRY =
    process.env.ENROLLMENT_REGISTRY ?? "0xC9b35dE202e0Bf92e38603deEC4176557eF249a4";
// The attester address is DERIVED from V3_ATTESTER_KEY (never hardcoded). The
// EnrollmentRegistry was rotated to a new attester; the human sets
// V3_ATTESTER_KEY to its secp256k1 key and the service derives the address from
// it. In production we assert only that the derived address is non-zero so a
// missing/garbage key fails closed instead of silently producing sigs.
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

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

// Validate POST /v3/register body:
//   { commitment, enrollProof, enrollPublicInputs, nullifierProof, nullifierPublicInputs }
// `commitment` is the enrollment leaf the client derived = pedersen([N.x,N.y])
// where N = rinv*(k*M) is the unblinded OPRF output (see e2e-test.mjs).
// The enroll_* artifacts are the SAME enroll_commit_v2 proof the blind-eval gate
// consumes (binds M <-> cert). The nullifier_* artifacts are an oprf_nullifier
// proof that binds the post-blind-eval commitment back to that same M, this
// node's Kpub, and N (closing the Sybil-binding gap).
function isProofField(v) {
    return typeof v === "string" || Array.isArray(v);
}
function isWordArray(v) {
    return Array.isArray(v) && v.length > 0;
}
function validateRegisterBody(body) {
    if (body === null || typeof body !== "object") {
        return { ok: false, detail: "body must be a JSON object" };
    }
    const {
        commitment,
        enrollProof,
        enrollPublicInputs,
        nullifierProof,
        nullifierPublicInputs,
    } = body;
    if (typeof commitment !== "string" || !HEX32.test(commitment)) {
        return { ok: false, detail: "commitment must be 0x-prefixed 32-byte hex" };
    }
    if (BigInt(commitment) >= FR_MAX) {
        return { ok: false, detail: "commitment exceeds Fr range (must be < 2^254)" };
    }
    if (!isProofField(enrollProof)) {
        return { ok: false, detail: "enrollProof must be 0x-hex string or byte array" };
    }
    if (!isWordArray(enrollPublicInputs)) {
        return {
            ok: false,
            detail: "enrollPublicInputs must be a non-empty array of 0x-hex field words",
        };
    }
    if (!isProofField(nullifierProof)) {
        return { ok: false, detail: "nullifierProof must be 0x-hex string or byte array" };
    }
    if (!isWordArray(nullifierPublicInputs)) {
        return {
            ok: false,
            detail: "nullifierPublicInputs must be a non-empty array of 0x-hex field words",
        };
    }
    return {
        ok: true,
        data: {
            commitment,
            enrollProof,
            enrollPublicInputs,
            nullifierProof,
            nullifierPublicInputs,
        },
    };
}

/**
 * Resolve the secp256k1 attester key from env V3_ATTESTER_KEY (32-byte hex).
 * REQUIRED in production; the service derives the attester ADDRESS from this key
 * (the EnrollmentRegistry attester was rotated, so no address is hardcoded).
 * Outside production a labeled deterministic dev key is used so tests / local
 * runs work without secrets — its address will NOT be the rotated on-chain
 * attester, so on-chain submission would be rejected (fine for local demo).
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
    console.warn("[oprf-v3] V3_ATTESTER_KEY not set — using deterministic dev key (NOT the rotated on-chain attester)");
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

    // — Nullifier proof gate (fixed per circuit, in-process) ──────────────────
    // The oprf_nullifier vk is baked ONCE at startup, exactly like the enroll vk
    // above (same ProofGate/bb.js in-process verify pattern). It gates
    // /v3/register: the nullifier proof binds the submitted commitment to N -> Y
    // -> M (and to this node's Kpub via the in-circuit DLEQ). Tests may inject a
    // prebuilt gate via opts.nullifierGate. Fail closed if it can't be built.
    let nullifierGate = opts.nullifierGate ?? null;
    let nullifierGateError = null;
    if (!nullifierGate) {
        try {
            nullifierGate = await createGate(OPRF_NULLIFIER_JSON);
        } catch (e) {
            nullifierGateError = e.message;
        }
    }

    // — Enrollment chain wiring (attester + Pedersen-Merkle store) ────────────
    // The Merkle store is in-memory (demo): commitments are NOT persisted across
    // restarts. The attester signs EnrollmentRegistry.updateRoot digests so the
    // existing relayer /v2/enroll can post a v3 commitment to the SAME contract.
    const chainId = opts.chainId ?? DEFAULT_CHAIN_ID;
    const enrollmentRegistry = opts.enrollmentRegistry ?? DEFAULT_ENROLLMENT_REGISTRY;
    const attester = new Attester(opts.attesterKey ?? resolveAttesterKey());
    // The attester address is whatever V3_ATTESTER_KEY derives to (the registry
    // attester was rotated; no address is hardcoded). In production assert only
    // that it is non-zero so a missing/garbage key fails closed.
    if (process.env.NODE_ENV === "production"
        && attester.address.toLowerCase() === ZERO_ADDR) {
        throw new Error(
            "[oprf-v3] V3_ATTESTER_KEY derived a zero attester address; refusing to boot",
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
            registerGating: nullifierGateError
                ? `unavailable (nullifier gate init failed: ${nullifierGateError}) — failing closed`
                : "enforced (enroll_commit_v2 + oprf_nullifier proofs; commitment bound to cert via N->Y->M)",
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
    // v2 uses. The Sybil-binding gap is CLOSED here by requiring TWO proofs and
    // chaining them:  commitment -> N -> Y -> M -> cert.
    //
    //   1. enroll_commit_v2 proof  — verifies + binds M <-> a valid age>=18 cert
    //      (public output M at enrollPublicInputs[12],[13]).
    //   2. oprf_nullifier proof    — verifies the in-circuit DLEQ (Y = k*M for
    //      Kpub = k*G), unblinds N = rinv*Y bound to r via r*N == Y, and RETURNS
    //      commitment = pedersen([N.x, N.y]) as its public output.
    //
    //   CROSS-CHECKS (verifyNullifierProof):
    //     (a) nullifier.M  == enroll.M                  (chains M -> cert)
    //     (b) nullifier.Kpub == THIS node's Kpub        (Y under our k)
    //     (c) nullifier.commitment == submitted commitment
    //
    // Only when BOTH proofs verify AND all cross-checks hold do we append the
    // leaf and attester-sign. A client can no longer register an arbitrary
    // commitment: it must be exactly pedersen(rinv*(k*M)) for the cert-bound M.
    app.post("/v3/register", async (req, reply) => {
        const parsed = validateRegisterBody(req.body);
        if (!parsed.ok) {
            return reply.code(400).send({ error: "BadRequest", detail: parsed.detail });
        }
        const {
            commitment,
            enrollProof,
            enrollPublicInputs,
            nullifierProof,
            nullifierPublicInputs,
        } = parsed.data;

        // — Both proof gates must be available (ENFORCED), else fail closed ──
        if (!gate) {
            req.log.error({ gateError }, "enroll proof gate unavailable — failing closed");
            return reply.code(503).send({
                error: "ProofGateUnavailable",
                detail: "enroll proof gate unavailable; node refuses to register",
            });
        }
        if (!nullifierGate) {
            req.log.error({ nullifierGateError }, "nullifier proof gate unavailable — failing closed");
            return reply.code(503).send({
                error: "ProofGateUnavailable",
                detail: "nullifier proof gate unavailable; node refuses to register",
            });
        }

        // — (1) Verify the enroll proof; bind it to its own public-output M ──
        // expectedM == the proof's own M: exercises the full structural + crypto
        // path and yields the cert-bound M to cross-check the nullifier proof.
        let enrollM;
        try {
            enrollM = extractMFromPublicInputs(enrollPublicInputs);
        } catch (e) {
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }
        let enrollResult;
        try {
            enrollResult = await verifyEnrollCommitProof({
                gate,
                proof: enrollProof,
                publicInputs: enrollPublicInputs,
                expectedM: enrollM,
            });
        } catch (e) {
            req.log.error({ err: e.message }, "register enroll proof gate errored");
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }
        if (!enrollResult.ok) {
            const status = enrollResult.code === "ProofRejected" ? 401 : 400;
            req.log.info({ code: enrollResult.code }, "v3 register enroll proof rejected");
            return reply.code(status).send({ error: enrollResult.code, detail: enrollResult.detail });
        }

        // — (2) Verify the nullifier proof + enforce the binding cross-checks ─
        // Bind nullifier.M to the enroll proof's M, nullifier.Kpub to THIS
        // node's Kpub, and nullifier.commitment to the submitted commitment.
        const Kaff = node.Kpub.toAffine();
        let nullifierResult;
        try {
            nullifierResult = await verifyNullifierProof({
                gate: nullifierGate,
                proof: nullifierProof,
                publicInputs: nullifierPublicInputs,
                expectedM: enrollM,
                expectedKpub: { x: Kaff.x, y: Kaff.y },
                expectedCommitment: BigInt(commitment),
            });
        } catch (e) {
            req.log.error({ err: e.message }, "register nullifier proof gate errored");
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }
        if (!nullifierResult.ok) {
            const status = nullifierResult.code === "ProofRejected" ? 401 : 400;
            req.log.info({ code: nullifierResult.code }, "v3 register nullifier proof rejected");
            return reply.code(status).send({ error: nullifierResult.code, detail: nullifierResult.detail });
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
