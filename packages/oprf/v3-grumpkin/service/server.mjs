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

import { makeNodes, pointFromHex, N } from "./oprf-node.mjs";
import {
    createGate,
    verifyEnrollCommitProof,
    verifyThresholdNullifierProof,
    extractMFromPublicInputs,
    extractDigestFromPublicInputs,
    extractCrFromEnroll,
    OPRF_NULLIFIER_JSON,
} from "./proof-gate.mjs";
import { sha256 } from "@noble/hashes/sha2";
import { expectedDigestLimbs } from "./challenge.mjs";
import { Attester } from "./attester.mjs";
import { MerkleIndex, TREE_DEPTH, GENESIS_ROOT, bigintToHex32 } from "./merkle.mjs";
import { syncMerkleFromChain, readOnchainRoot } from "./chain-sync.mjs";

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

/**
 * Resolve the threshold keygen SEED from env V3_THRESHOLD_SEED (hex or decimal).
 * The seed deterministically derives the 2-of-3 share set, so the published Kpub
 * set + k' (hence the deterministic nullifier + recovery) are STABLE across
 * restarts. REQUIRED in production -- fail closed if absent, exactly like the
 * attester key. Outside production a labeled deterministic dev seed is used so
 * tests / local runs are stable without a secret (its k' is NOT a production
 * key). The seed is a SECRET: returned as a bigint, NEVER logged.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {bigint} keygen seed.
 */
export function resolveThresholdSeed(env = process.env) {
    const raw = env.V3_THRESHOLD_SEED;
    if (raw) {
        const s = raw.trim();
        const v = /^0x[0-9a-fA-F]+$/.test(s) ? BigInt(s)
            : /^[0-9]+$/.test(s) ? BigInt(s)
            : null;
        if (v === null || v === 0n) {
            throw new Error("V3_THRESHOLD_SEED must be a nonzero hex (0x..) or decimal integer");
        }
        return v;
    }
    if (env.NODE_ENV === "production") {
        throw new Error("[oprf-v3] V3_THRESHOLD_SEED is required in production");
    }
    // eslint-disable-next-line no-console
    console.warn("[oprf-v3] V3_THRESHOLD_SEED not set — using a deterministic dev seed (NOT a production key set)");
    // Labeled dev-only seed (NOT a production secret), matching the dev-attester
    // labeling style. Stable across restarts so local recovery works.
    return BigInt("0x" + Buffer.from("crisp-qes-v3-grumpkin-dev-threshold-seed").toString("hex"));
}

// — App builder (exported so the roundtrip test can run it in-process) ────────

export async function buildApp(opts = {}) {
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
            // TEST-ONLY override: ENROLL_GATE_CIRCUIT lets the LOCAL E2E point the
            // gate at a synthetic-CA-pinned enroll_commit_v2 build (so a synthetic
            // cert proof verifies). Unset in production => the committed real-Diia
            // circuit is used. NEVER set this in a production deploy.
            gate = await createGate(process.env.ENROLL_GATE_CIRCUIT || undefined);
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
            // TEST-ONLY override mirrors ENROLL_GATE_CIRCUIT (see above). Unset in
            // production => committed oprf_nullifier circuit is used.
            nullifierGate = await createGate(
                process.env.OPRF_NULLIFIER_GATE_CIRCUIT || OPRF_NULLIFIER_JSON,
            );
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
    const enrollEpoch = process.env.OPRF_ENROLLMENT_EPOCH_V3 ?? "v3-2026";

    // — Threshold (2-of-3) OPRF node set ─────────────────────────────────────
    // Replaces the single-key OprfNode: the group key k' is Shamir-shared across
    // 3 ShareNodes (any 2 evaluate). k' is NEVER assembled at any node (the F4
    // design). For the co-hosted DEMO all 3 nodes run in THIS process, SEEDED
    // from one secret (V3_THRESHOLD_SEED) so the published Kpub set + k' are
    // STABLE across restarts -- the deterministic nullifier (and recovery /
    // in-flight enrollments) survives reboots. CAVEAT: a real independent-
    // operator deployment would have EACH node hold its OWN share (no shared
    // seed) and run its own gated blind-eval; the single-seed demo trades that
    // independence for restart-stability, and F4 is only mitigated when >=2 nodes
    // are independently operated (an operational property, not a code one).
    // Tests may inject a prebuilt set via opts.nodeSet, or a seed via opts.seed.
    const { nodes, published } =
        opts.nodeSet ?? makeNodes(opts.n ?? 3, opts.t ?? 2, { seed: opts.seed ?? resolveThresholdSeed() });
    // The published Kpub set as {x,y} bigints in index order 1,2,3 -- the
    // canonical set the register cross-check (e) pins by value.
    const publishedKpubSet = published.map((p) => {
        const a = pointFromHex(p.Kpub_i).toAffine();
        return { x: a.x, y: a.y };
    });
    // The DEFAULT t=2 responders for the co-hosted demo (any 2 of 3; nodes 1,2).
    const responderNodes = [nodes[0], nodes[1]];
    // Threshold per-share DLEQ epoch (a Field/bigint) -- bound into every
    // partial's transcript and pinned by the register check (f). Derived
    // deterministically from the string enrollEpoch so blind-eval and register
    // agree, and rotating enrollEpoch rotates the threshold session.
    const thresholdEpoch =
        BigInt("0x" + Buffer.from(sha256(new TextEncoder().encode(`v3-threshold-epoch:${enrollEpoch}`))).toString("hex")) % N;

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
    // — Merkle store, synced from the on-chain EnrollmentRegistry ─────────────
    // The store is a pure function of the ordered leaf set, so we rebuild it
    // from the registry's CommitmentInserted events at boot (and re-sync before
    // each append when the on-chain root has moved). This makes the service
    // self-healing across restarts and failed relays instead of resetting to an
    // empty genesis tree on every cold start. Enabled whenever RPC_URL is set
    // (always, in prod via fly.toml). Tests still inject opts.merkle/opts.leaves
    // directly, which take precedence.
    const syncCfg =
        opts.syncCfg ??
        (process.env.RPC_URL && !opts.merkle && !opts.leaves
            ? {
                  rpcUrl: process.env.RPC_URL,
                  registry: enrollmentRegistry,
                  fromBlock: BigInt(process.env.REGISTRY_FROM_BLOCK ?? 0),
              }
            : null);

    // commitment(0x-hex) -> leafIndex, kept in lock-step with `merkle.leaves`.
    const indexLeaves = (leaves) => {
        const m = new Map();
        leaves.forEach((leaf, i) => m.set(bigintToHex32(BigInt(leaf)), i));
        return m;
    };

    let merkle;
    let leafIndexOf;
    if (opts.merkle) {
        merkle = opts.merkle;
        leafIndexOf = opts.leafIndexOf ?? indexLeaves(opts.merkle.leaves ?? []);
    } else if (syncCfg) {
        const synced = await syncMerkleFromChain(syncCfg);
        merkle = synced.index;
        leafIndexOf = indexLeaves(synced.leaves);
        if (opts.logger !== false) {
            console.info(
                `[oprf-v3] merkle synced from chain: leafCount=${synced.leafCount} ` +
                    `root=${synced.onchainRoot}`,
            );
        }
    } else {
        merkle = await MerkleIndex.fromLeaves(opts.leaves ?? []);
        leafIndexOf = opts.leafIndexOf ?? indexLeaves(opts.leaves ?? []);
    }

    // Re-sync the store to on-chain truth when the registry root has advanced
    // past ours (another node enrolled, our last relay landed after a restart,
    // or a prior append never confirmed on-chain). Called before each append so
    // the oldRoot we sign always equals the live on-chain root. No-op when the
    // roots already agree (one cheap eth_call) or sync is disabled (tests).
    async function resyncIfStale() {
        if (!syncCfg) return;
        const onchain = await readOnchainRoot(syncCfg);
        if (bigintToHex32(merkle.root).toLowerCase() === onchain.toLowerCase()) return;
        const synced = await syncMerkleFromChain(syncCfg);
        merkle = synced.index;
        leafIndexOf = indexLeaves(synced.leaves);
    }

    // Reconstruct the v3 challenge from the PUBLIC M + intent + epoch, sha256 it,
    // and require it equals the digest the enroll proof bound (public words 11/12).
    // Stateless + operator-blind: we never see the cert, only M (which we have).
    function challengeDigestOk(Mhex, publicInputs) {
        let bound, expected;
        try {
            bound = extractDigestFromPublicInputs(publicInputs);
            expected = expectedDigestLimbs(Mhex.toLowerCase(), enrollEpoch);
        } catch {
            return false;
        }
        return bound.hi === expected.hi && bound.lo === expected.lo;
    }

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
            mode: "VOPRF v3 (build, unaudited — 2-of-3 threshold, proof-gating ENFORCED)",
            curve: "Grumpkin (y^2 = x^3 - 17)",
            wireFormat: "point = 0x{x:32B BE}{y:32B BE}; scalar = decimal bigint",
            // Published 2-of-3 Kpub set (the canonical node keys). k' (the group
            // key) is never assembled at any node. The set is SEED-DERIVED (from
            // V3_THRESHOLD_SEED) so it is stable across restarts; the seed itself
            // is a secret and is never exposed here.
            keySet: "seed-derived (stable across restarts)",
            publishedKpubSet: published.map((p) => ({ i: p.i.toString(), Kpub_i: p.Kpub_i })),
            thresholdEpoch: thresholdEpoch.toString(),
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
        if (!challengeDigestOk(M, publicInputs)) {
            req.log.info("v3 blind-eval challenge digest mismatch");
            return reply.code(409).send({
                error: "ChallengeMismatch",
                detail:
                    "proof's bound messageDigest != sha256(challenge) for this M/epoch; " +
                    "re-sign the downloaded challenge for this session",
            });
        }
        req.log.info("v3 blind-eval proof accepted");

        // — Threshold blind-evaluate: t=2 responders' partials ────────────
        // Each responder ShareNode returns B_i = k_i*M + a per-share epoch-bound
        // DLEQ (proving B_i = k_i*M vs its published Kpub_i). The client verifies
        // each DLEQ, combines Y = sum lambda_i*B_i locally for its commitment, and
        // carries the partials into the threshold nullifier proof for in-circuit
        // re-verification. DEMO NOTE: with INDEPENDENT operators, each node would
        // run its OWN gated /v3/blind-eval; the co-hosted demo gates ONCE (this
        // enroll-proof check) and evaluates the 2 responders in-process.
        let partials;
        try {
            partials = await Promise.all(
                responderNodes.map((sn) => sn.evaluate(M, thresholdEpoch)),
            );
        } catch (e) {
            req.log.error({ err: e.message }, "threshold evaluate failed");
            return reply.code(500).send({ error: "EvalError", detail: e.message });
        }

        // Wire shape: { partials: [{ i, B_i, dleq:{c,z}, Kpub_i }], epoch,
        // publishedKpubSet }. c/z are group-order scalars (< N) sent as decimal
        // strings to avoid BigInt->JSON precision loss; the client re-parses with
        // BigInt(). epoch is the threshold session tag (decimal).
        return reply.code(200).send({
            partials: partials.map((p) => ({
                i: p.i.toString(),
                B_i: p.B_i,
                dleq: { c: p.dleq.c.toString(), z: p.dleq.z.toString() },
                Kpub_i: p.Kpub_i,
            })),
            epoch: thresholdEpoch.toString(),
            publishedKpubSet: published.map((p) => ({ i: p.i.toString(), Kpub_i: p.Kpub_i })),
            proofAccepted: "verified (in-process bb.js verify + M-binding)",
        });
    });

    // — POST /v3/register ────────────────────────────────────────────────
    // Land a v3 enrollment commitment on-chain via the SAME EnrollmentRegistry
    // v2 uses. The Sybil-binding gap is CLOSED here by requiring TWO proofs and
    // chaining them:  commitment -> N -> Y -> M -> cert.
    //
    //   1. enroll_commit_v2 proof  — verifies + binds M <-> a valid age>=18 cert
    //      (public output M at enrollPublicInputs[8],[9]; C_r at [10]).
    //   2. THRESHOLD oprf_nullifier proof — self-attests the 2-of-3 evaluation:
    //      per-share epoch-bound DLEQs vs the PINNED GEN, idx->Kpub selection from
    //      the published set, the pinned mod-N Lagrange combine (Y in-circuit), and
    //      the F2 binding (commit_r(r) == C_r + r*N == Y). RETURNS the nullifier =
    //      pedersen([N.x, N.y]).
    //
    //   CROSS-CHECKS (verifyThresholdNullifierProof) — the service pins only:
    //     (a) nullifier.M     == enroll.M               (chains M -> cert; HARD)
    //     (c) nullifier.commitment == submitted commitment
    //     (d) nullifier.C_r   == enroll.C_r             (same blind r across proofs)
    //     (e) nullifier.{Kpub1,Kpub2,Kpub3} == the canonical PUBLISHED Kpub set
    //     (f) nullifier.epoch == the current threshold epoch (session binding)
    //   (b) is GONE: there is no single node Kpub; the published-set check (e) +
    //   the in-circuit idx->Kpub selection bind the responders to the canonical set.
    //
    // Only when BOTH proofs verify AND all cross-checks hold do we append the
    // leaf and attester-sign. A client can no longer register an arbitrary
    // commitment: it must be exactly pedersen(k'*H2C(id)) for the cert-bound M.
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

        // bind the registered leaf to the live-signed challenge as well.
        // M.x/M.y are the enroll proof's first two public-output words [8],[9].
        const exHex = enrollPublicInputs[8].replace(/^0x/, "").padStart(64, "0");
        const eyHex = enrollPublicInputs[9].replace(/^0x/, "").padStart(64, "0");
        if (!challengeDigestOk(`0x${exHex}${eyHex}`, enrollPublicInputs)) {
            return reply.code(409).send({ error: "ChallengeMismatch", detail: "enroll proof challenge digest mismatch" });
        }

        // C_r the enroll proof published (public word [10]); the nullifier proof
        // must re-assert commit_r(its r) == this value (cross-check (d), F2).
        let enrollCr;
        try {
            enrollCr = extractCrFromEnroll(enrollPublicInputs);
        } catch (e) {
            return reply.code(400).send({ error: "MalformedProof", detail: e.message });
        }

        // — (2) Verify the THRESHOLD nullifier proof + binding cross-checks ──
        // Pin nullifier.M to the enroll proof's M, nullifier.C_r to the enroll
        // C_r, the proof's 3-Kpub set to the canonical published set, the epoch to
        // the current threshold epoch, and the nullifier to the submitted
        // commitment. The proof self-attests the per-share DLEQs + Lagrange combine.
        let nullifierResult;
        try {
            nullifierResult = await verifyThresholdNullifierProof({
                gate: nullifierGate,
                proof: nullifierProof,
                publicInputs: nullifierPublicInputs,
                expectedM: enrollM,
                publishedKpubSet,
                expectedEpoch: thresholdEpoch,
                expectedCr: enrollCr,
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

        // — Sync to on-chain truth before signing ─────────────────────────
        // Pull the live registry root; if it has advanced past ours (restart,
        // late relay, another node), rebuild the store from chain so the
        // oldRoot we are about to sign equals the on-chain root and the
        // updateRoot is accepted. Fail closed if the chain is unreachable.
        try {
            await resyncIfStale();
        } catch (e) {
            req.log.error({ err: e.message }, "v3 register: chain re-sync failed");
            return reply.code(503).send({
                error: "ChainSyncUnavailable",
                detail: "could not reconcile the enrollment tree with chain; try again",
            });
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
        // Reconcile to chain BEFORE lookup. Recovery must see on-chain truth
        // regardless of which (possibly cold/other) machine serves this request;
        // otherwise a leaf that /v3/register reported AlreadyEnrolled (after its
        // own resync) would 404 here on an unsynced machine.
        try {
            await resyncIfStale();
        } catch (e) {
            req.log.error({ err: e.message }, "v3 path: chain re-sync failed");
            return reply.code(503).send({
                error: "ChainSyncUnavailable",
                detail: "could not reconcile the enrollment tree with chain; try again",
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

// (The legacy single-key node-key resolver was removed: the deployed service is
// the 2-of-3 threshold set, keyed by V3_THRESHOLD_SEED via resolveThresholdSeed.)

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
        attesterKey: resolveAttesterKey(),
        seed: resolveThresholdSeed(),
        logger: { level: "info" },
    });
    await app.listen({ port, host });
    // logger already prints the listen line.
}
