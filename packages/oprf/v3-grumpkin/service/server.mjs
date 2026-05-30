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
//               the client's enroll_commit_v2 ZK proof is verified via
//               `bb verify` against a startup-fixed vk, AND its public-output M
//               is required to equal the request's M, before any evaluation.
//               This replaces the v2 cleartext Diia cert/age attestation.
//   Plus CORS and structured errors.

import Fastify from "fastify";
import fastifyCors from "@fastify/cors";

import { OprfNode, pointFromHex } from "./oprf-node.mjs";
import { computeVk, verifyEnrollCommitProof } from "./proof-gate.mjs";

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

    // — Proof-gating vk (fixed per circuit) ──────────────────────────────────
    // Compute the enroll_commit_v2 verification key ONCE at startup via
    // `bb write_vk`. Tests may inject a precomputed Buffer via opts.vk to avoid
    // re-deriving it. If derivation fails (bb missing / artifact absent) we fail
    // closed: the gate cannot be satisfied and every request is rejected.
    let gateVk = opts.vk ?? null;
    let gateVkError = null;
    if (!gateVk) {
        try {
            gateVk = await computeVk();
        } catch (e) {
            gateVkError = e.message;
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
        proofGating: gateVkError
            ? `unavailable (vk derivation failed: ${gateVkError}) — failing closed`
            : "enforced (bb verify of enroll_commit_v2 proof + M-binding)",
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
        // Fail closed if the vk could not be derived at startup.
        if (!gateVk) {
            req.log.error({ gateVkError }, "proof gate unavailable — failing closed");
            return reply.code(503).send({
                error: "ProofGateUnavailable",
                detail: "verification key unavailable; node refuses to evaluate",
            });
        }
        // Verify the enroll_commit_v2 proof AND require its public-output M to
        // equal the request's M. Any failure => 4xx, NO evaluation.
        let gate;
        try {
            gate = await verifyEnrollCommitProof({
                vk: gateVk,
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
        if (!gate.ok) {
            const status = gate.code === "ProofRejected" ? 401 : 400;
            req.log.info({ code: gate.code }, "v3 blind-eval proof rejected");
            return reply.code(status).send({ error: gate.code, detail: gate.detail });
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
            proofAccepted: "verified (bb verify + M-binding)",
        });
    });

    return app;
}

// Deterministic dev key — explicitly NOT a production secret. Matches the
// labeling style of gen-nullifier-witness.mjs's `det()` helper.
function defaultDevKey() {
    const label = "crisp-qes-v3-grumpkin-dev-node-k";
    const raw = BigInt("0x" + Buffer.from(label).toString("hex"));
    // Reduce into [1, N) using the node's exported order.
    const { N } = { N: 21888242871839275222246405745257275088696311157297823662689037894645226208583n };
    return (raw % (N - 1n)) + 1n;
}

// — CLI entrypoint: `node server.mjs` ────────────────────────────────────────
const isMain =
    import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith("server.mjs");

if (isMain) {
    const port = Number(process.env.PORT ?? 8788);
    const host = process.env.HOST ?? "127.0.0.1";
    const app = await buildApp({ logger: { level: "info" } });
    await app.listen({ port, host });
    // logger already prints the listen line.
}
