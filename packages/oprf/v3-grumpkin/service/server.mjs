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

    const app = Fastify({ logger: opts.logger ?? { level: "warn" } });

    await app.register(fastifyCors, {
        origin: allowAll ? true : corsOrigins,
        methods: ["GET", "POST", "OPTIONS"],
        credentials: false,
        maxAge: 86400,
    });

    // — GET /healthz ─────────────────────────────────────────────────────
    app.get("/healthz", async () => ({
        ok: true,
        suite: "grumpkin-SHA256-SvdW",
        mode: "VOPRF v3 (build, unaudited — single node, proof-gating ENFORCED)",
        curve: "Grumpkin (y^2 = x^3 - 17)",
        wireFormat: "point = 0x{x:32B BE}{y:32B BE}; scalar = decimal bigint",
        Kpub: node.publicKeyHex(),
        proofGating: gateError
            ? `unavailable (gate init failed: ${gateError}) — failing closed`
            : "enforced (in-process bb.js verify of enroll_commit_v2 proof + M-binding)",
    }));

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
    const app = await buildApp({ k: resolveNodeKey(), logger: { level: "info" } });
    await app.listen({ port, host });
    // logger already prints the listen line.
}
