// Minimal standalone Fastify server for the v3 Grumpkin VOPRF node (build,
// unaudited). This is the v3 analogue of packages/oprf/src/app.ts's
// POST /oprf/blind-eval, but:
//   * over Grumpkin (reuses ../lib.mjs via ./oprf-node.mjs), and
//   * gated on a CLIENT ZK PROOF instead of a cleartext Diia attestation cert.
//
// IMPORTANT: this is standalone and does NOT import or touch the live v2
// service in packages/oprf/src/.
//
// ── Gating status (this milestone) ──────────────────────────────────────────
//   GATED NOW : request shape validation (M must be a valid on-curve Grumpkin
//               point in the x||y wire format), CORS, structured errors.
//   DEFERRED  : verification of the client's enroll_commit ZK proof. The body
//               accepts an OPTIONAL `proof` placeholder field today and only
//               records its presence. The NEXT milestone wires real
//               `bb verify` of the client proof (the oprf_commitment circuit
//               output) as the admission gate — replacing the v2 cert/age
//               attestation entirely. Until then the endpoint will evaluate
//               for any well-formed M, exactly like a permissionless test node.

import Fastify from "fastify";
import fastifyCors from "@fastify/cors";

import { OprfNode, pointFromHex } from "./oprf-node.mjs";

// — Body validation (hand-rolled to keep the module zero-extra-deps; mirrors
//   the intent of the zod validators in v2 app.ts) ───────────────────────────

const POINT_HEX = /^0x[0-9a-fA-F]{128}$/;

function validateBlindEvalBody(body) {
    if (body === null || typeof body !== "object") {
        return { ok: false, detail: "body must be a JSON object" };
    }
    const { M, proof } = body;
    if (typeof M !== "string" || !POINT_HEX.test(M)) {
        return {
            ok: false,
            detail: "M must be 0x-prefixed 64-byte (x||y) Grumpkin point hex",
        };
    }
    // proof is OPTIONAL this milestone. If present, it must at least be an
    // object/string we can later hand to `bb verify`. We do not interpret it.
    if (proof !== undefined && proof !== null) {
        const t = typeof proof;
        if (t !== "object" && t !== "string") {
            return { ok: false, detail: "proof, if present, must be object|string" };
        }
    }
    return { ok: true, data: { M, proof } };
}

// — App builder (exported so the roundtrip test can run it in-process) ────────

export async function buildApp(opts = {}) {
    const node = opts.node ?? new OprfNode(opts.k ?? defaultDevKey());
    const corsOrigins = opts.corsAllowedOrigins ?? ["*"];
    const allowAll = corsOrigins.includes("*");

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
        mode: "VOPRF v3 (build, unaudited — single node, proof-gating DEFERRED)",
        curve: "Grumpkin (y^2 = x^3 - 17)",
        wireFormat: "point = 0x{x:32B BE}{y:32B BE}; scalar = decimal bigint",
        Kpub: node.publicKeyHex(),
        proofGating: "deferred (accepts optional placeholder `proof` field)",
    }));

    // — POST /v3/blind-eval ──────────────────────────────────────────────
    app.post("/v3/blind-eval", async (req, reply) => {
        const parsed = validateBlindEvalBody(req.body);
        if (!parsed.ok) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.detail });
        }
        const { M, proof } = parsed.data;

        // — Proof gate (DEFERRED) ────────────────────────────────────────
        // NEXT milestone: reconstruct the public inputs the client committed
        // to (e.g. M and the node Kpub) and run `bb verify` of the
        // enroll_commit / oprf_commitment proof here. On failure return 401
        // ProofRejected and DO NOT evaluate. For now we only note presence.
        const proofPresent = proof !== undefined && proof !== null;
        req.log.info({ proofPresent }, "v3 blind-eval (proof gating deferred)");

        // — M validity gate (ENFORCED NOW) ───────────────────────────────
        // Reject anything that is not a valid on-curve Grumpkin point before
        // burning a scalar-mul, mirroring v2's BadBlindedInput path.
        try {
            pointFromHex(M);
        } catch (e) {
            return reply.code(400).send({
                error: "BadBlindedInput",
                detail: `not a valid Grumpkin point: ${e.message}`,
            });
        }

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
            proofAccepted: proofPresent ? "noted (verification deferred)" : "absent",
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
