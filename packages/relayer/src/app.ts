// v2 relayer Fastify app.
//
// Three-route surface:
//   POST /v2/enroll  — relay an attester-signed root update to
//                      EnrollmentRegistry.updateRoot. No citizen auth —
//                      the attester signature IS the auth (contract-level
//                      ecrecover gate). Per-IP token bucket + simulate-
//                      before-write keeps replay/stale-sig attempts off
//                      the chain. Added in #55 to drop the citizen-side
//                      wallet step from the enrollment ceremony.
//   POST /v2/submit  — relay a v2 UltraHonk signature proof to
//                      PetitionRegistryV2.signPetition.
//   GET  /tx/:hash   — same shape as MVP relayer; decodes the
//                      PetitionSigned / PetitionRevoked events.
//   GET  /healthz    — config snapshot + chain probe.
//
// Differences from the MVP relayer's `/submit`:
//
//   * Public-input shape is now length-3 `[petitionId, enrollmentRoot,
//     nullifier]` — no CAdES limbs, no SPKI limbs, no leaf-cert sig.
//     v2 circuit moved that work to enrollment time.
//   * We additionally read `EnrollmentRegistry.enrollmentRoot()` and
//     reject the submit pre-flight if `publicInputs[1]` doesn't match.
//     This save a doomed simulate round-trip when the citizen's path
//     was generated under an old root.
//   * A petition is support-only — there is no vote value. Signing means
//     supporting; withdrawing is /v2/revoke.

import Fastify, { type FastifyInstance } from "fastify";
import fastifyCors from "@fastify/cors";
import {
    type Hex,
    decodeEventLog,
    getAddress,
    hexToBigInt,
} from "viem";
import { z } from "zod";

import { enrollmentRegistryAbi, petitionRegistryV2Abi } from "./abi.js";
import { makeClients, type Clients } from "./chain.js";
import type { RelayerConfig } from "./config.js";
import { mapContractError, mapEnrollmentError } from "./errors.js";
import { makeRateLimiter, type RateLimiter } from "./rateLimit.js";

const hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/, "expected 32-byte hex");
const hex = z.string().regex(/^0x[0-9a-fA-F]+$/, "expected hex string");
const sig65 = z
    .string()
    .regex(/^0x[0-9a-fA-F]{130}$/, "expected 65-byte hex signature (r||s||v)");
const decimalUint = z.string().regex(/^\d+$/, "expected decimal integer");

// Body shape pinned by web's submit() — see N4 wire contract:
//   { petitionId, nullifier, proof, publicInputs[] }
// A petition is support-only: signing = supporting it. There is no vote.
const SubmitBody = z.object({
    petitionId: decimalUint,
    nullifier: hex32,
    proof: hex,
    publicInputs: z.array(hex32).length(3),
});

// /v2/revoke body — same shape as submit minus `vote`. Calls
// PetitionRegistryV2.revokeVote(petitionId, nullifier, proof, publicInputs)
// to withdraw a previously-cast signature. Public inputs share the
// signPetition layout: [petitionId, enrollmentRoot, nullifier].
const RevokeBody = z.object({
    petitionId: decimalUint,
    nullifier: hex32,
    proof: hex,
    publicInputs: z.array(hex32).length(3),
});

// `/v2/enroll` body — verbatim relay of the OPRF service's
// `/oprf/register` output's `(newRoot, newCommitments, attesterSig)` to
// `EnrollmentRegistry.updateRoot(...)`. No citizen-supplied fields. No
// oldRoot here — the contract reads it from storage; if the OPRF service
// signed against a different one we'll trip `BadSignature` at simulate
// time and surface 409.
const EnrollBody = z.object({
    newRoot: hex32,
    newCommitments: z.array(hex32).min(1),
    signature: sig65,
});

const TxParams = z.object({
    hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
});

export interface BuildAppOptions {
    config: RelayerConfig;
    /** Override for tests; defaults to live viem clients. */
    clientsFactory?: (cfg: RelayerConfig) => Clients;
    rateLimiter?: RateLimiter;
}

export function buildApp(opts: BuildAppOptions): FastifyInstance {
    const { config } = opts;
    const factory = opts.clientsFactory ?? makeClients;
    const clients = factory(config);
    const rateLimiter =
        opts.rateLimiter ?? makeRateLimiter(config.rateLimitWindowMs);

    const app = Fastify({ logger: { level: config.isProd ? "info" : "warn" } });

    const allowAll = config.corsAllowedOrigins.includes("*");
    void app.register(fastifyCors, {
        origin: allowAll ? true : config.corsAllowedOrigins,
        methods: ["GET", "POST", "OPTIONS"],
        credentials: false,
        maxAge: 86400,
    });

    app.get("/healthz", async () => ({
        ok: true,
        chainId: config.chainId,
        petitionRegistry: config.petitionRegistry,
        enrollmentRegistry: config.enrollmentRegistry,
        relayerAddr: clients.account.address,
    }));

    app.post("/v2/enroll", async (req, reply) => {
        // Auth model: none from citizen. The attester signature inside
        // the body is the auth — `EnrollmentRegistry.updateRoot` only
        // accepts updates where `ecrecover(ethSigned, sig) == oprfAttester`.
        // The same per-IP token-bucket as `/v2/submit` is sufficient to
        // bound spam; replay of a previously-landed sig is naturally
        // rejected at simulate time (chain advances oldRoot; the next
        // recompute of `inner` no longer matches → BadSignature → 409).
        const ip = req.ip ?? "unknown";
        if (!rateLimiter.take(ip)) {
            return reply.code(429).send({
                error: "RateLimited",
                retryAfterMs: config.rateLimitWindowMs,
            });
        }

        const parsed = EnrollBody.safeParse(req.body);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }
        const body = parsed.data;

        const args = [
            body.newRoot as Hex,
            body.newCommitments as Hex[],
            body.signature as Hex,
        ] as const;

        // Simulate first so the common failure modes (replay, stale
        // oldRoot, malformed sig — all collapse into BadSignature on the
        // contract side) surface as 4xx, with no chain write.
        try {
            await clients.publicClient.simulateContract({
                address: config.enrollmentRegistry,
                abi: enrollmentRegistryAbi,
                functionName: "updateRoot",
                args: args as unknown as readonly [Hex, readonly Hex[], Hex],
                account: clients.account,
            });
        } catch (err) {
            const mapped = mapEnrollmentError(err);
            req.log.warn({ err: mapped.body }, "enroll simulate revert");
            return reply.code(mapped.status).send(mapped.body);
        }

        let txHash: Hex;
        try {
            txHash = await clients.sendTx({
                address: config.enrollmentRegistry,
                abi: enrollmentRegistryAbi,
                functionName: "updateRoot",
                args: args as unknown as readonly [Hex, readonly Hex[], Hex],
            });
        } catch (err) {
            const mapped = mapEnrollmentError(err);
            req.log.error({ err: mapped.body }, "enroll write revert");
            // Default unrecognised write-side failures to 502 + retryable
            // so the citizen-side caller can retry without bothering the
            // user — RPC blips and gas-spike rejections fall here.
            const status = mapped.status === 500 ? 502 : mapped.status;
            return reply.code(status).send({
                ...mapped.body,
                retryable: status >= 500,
            });
        }

        return reply.code(200).send({
            txHash,
            blockExplorerUrl: config.blockExplorerBase
                ? `${config.blockExplorerBase}${txHash}`
                : null,
        });
    });

    app.post("/v2/submit", async (req, reply) => {
        const ip = req.ip ?? "unknown";
        if (!rateLimiter.take(ip)) {
            return reply.code(429).send({
                error: "RateLimited",
                retryAfterMs: config.rateLimitWindowMs,
            });
        }

        const parsed = SubmitBody.safeParse(req.body);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }
        const body = parsed.data;

        // 1. Cross-field sanity vs the (small) public input array.
        //    [0] petitionId   [1] enrollmentRoot   [2] nullifier
        const piPetition = hexToBigInt(body.publicInputs[0] as Hex);
        if (piPetition.toString() !== body.petitionId) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: "publicInputs[0] != petitionId" });
        }
        if (body.publicInputs[2] !== body.nullifier) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: "publicInputs[2] != nullifier" });
        }

        // 2. Live-root pre-flight. Reads `enrollmentRoot()` from the
        //    deployed EnrollmentRegistry; bails before simulate if the
        //    citizen's path was generated under a stale root.
        let liveRoot: Hex;
        try {
            liveRoot = (await clients.publicClient.readContract({
                address: config.enrollmentRegistry,
                abi: enrollmentRegistryAbi,
                functionName: "enrollmentRoot",
                args: [],
            })) as Hex;
        } catch (err) {
            req.log.error({ err }, "enrollmentRoot read failed");
            return reply.code(502).send({
                error: "EnrollmentRegistryUnreachable",
                detail: (err as Error).message,
            });
        }
        if (
            body.publicInputs[1]?.toLowerCase() !== liveRoot.toLowerCase()
        ) {
            return reply.code(409).send({
                error: "StaleEnrollmentRoot",
                detail:
                    "publicInputs[1] does not match the live EnrollmentRegistry root — " +
                    "fetch a fresh Merkle path from /enrollment/:commitment/path on the OPRF service",
                expectedRoot: liveRoot,
                receivedRoot: body.publicInputs[1],
            });
        }

        // 3. Compose calldata.
        const args = [
            BigInt(body.petitionId),
            body.nullifier as Hex,
            body.proof as Hex,
            body.publicInputs as Hex[],
        ] as const;

        // 4. Simulate first so reverts surface as 4xx not a sent tx.
        try {
            await clients.publicClient.simulateContract({
                address: config.petitionRegistry,
                abi: petitionRegistryV2Abi,
                functionName: "signPetition",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    Hex,
                    readonly Hex[],
                ],
                account: clients.account,
            });
        } catch (err) {
            const mapped = mapContractError(err);
            // Diagnostic capture: on an EMPTY (selector 0x) signPetition revert
            // the verifier rejected the proof. Log the exact artifact so it can
            // be decoded / re-verified offline against the circuit VK.
            req.log.warn(
                {
                    err: mapped.body,
                    petitionId: String(body.petitionId),
                    nullifier: body.nullifier,
                    publicInputs: body.publicInputs,
                    liveRoot,
                    proofLen: (body.proof as string).length,
                    proofHead: (body.proof as string).slice(0, 18),
                    proofTail: (body.proof as string).slice(-18),
                },
                "simulate revert (proof artifact)",
            );
            return reply.code(mapped.status).send(mapped.body);
        }

        let txHash: Hex;
        try {
            txHash = await clients.sendTx({
                address: config.petitionRegistry,
                abi: petitionRegistryV2Abi,
                functionName: "signPetition",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    Hex,
                    readonly Hex[],
                ],
            });
        } catch (err) {
            const mapped = mapContractError(err);
            req.log.error({ err: mapped.body }, "write revert");
            return reply.code(mapped.status).send(mapped.body);
        }

        return reply.code(200).send({
            txHash,
            blockExplorerUrl: config.blockExplorerBase
                ? `${config.blockExplorerBase}${txHash}`
                : null,
        });
    });

    app.post("/v2/revoke", async (req, reply) => {
        // Mirrors /v2/submit: rate-limit → validate body → cross-field check
        // against publicInputs → live-root pre-flight → simulate → write.
        // Calls PetitionRegistryV2.revokeVote rather than signPetition; on
        // a successful revoke the contract burns the same nullifier the
        // citizen used to sign, so re-signing under the same identity is
        // not possible. Response shape per the frozen wire contract:
        //   200: { ok: true, txHash, blockExplorerUrl }
        //   4xx/5xx: { ok: false, code, status, detail? }
        const ip = req.ip ?? "unknown";
        if (!rateLimiter.take(ip)) {
            return reply.code(429).send({
                ok: false,
                code: "RateLimited",
                status: 429,
                detail: `retry after ${config.rateLimitWindowMs}ms`,
            });
        }

        const parsed = RevokeBody.safeParse(req.body);
        if (!parsed.success) {
            return reply.code(400).send({
                ok: false,
                code: "BadRequest",
                status: 400,
                detail: JSON.stringify(parsed.error.flatten()),
            });
        }
        const body = parsed.data;

        // 1. Cross-field sanity vs the public-input array.
        //    [0] petitionId   [1] enrollmentRoot   [2] nullifier
        const piPetition = hexToBigInt(body.publicInputs[0] as Hex);
        if (piPetition.toString() !== body.petitionId) {
            return reply.code(400).send({
                ok: false,
                code: "BadRequest",
                status: 400,
                detail: "publicInputs[0] != petitionId",
            });
        }
        if (body.publicInputs[2] !== body.nullifier) {
            return reply.code(400).send({
                ok: false,
                code: "BadRequest",
                status: 400,
                detail: "publicInputs[2] != nullifier",
            });
        }

        // 2. Live-root pre-flight — same rationale as /v2/submit. Bail
        //    before simulate if the citizen's path was generated under a
        //    stale enrollment root.
        let liveRoot: Hex;
        try {
            liveRoot = (await clients.publicClient.readContract({
                address: config.enrollmentRegistry,
                abi: enrollmentRegistryAbi,
                functionName: "enrollmentRoot",
                args: [],
            })) as Hex;
        } catch (err) {
            req.log.error({ err }, "enrollmentRoot read failed");
            return reply.code(502).send({
                ok: false,
                code: "EnrollmentRegistryUnreachable",
                status: 502,
                detail: (err as Error).message,
            });
        }
        if (body.publicInputs[1]?.toLowerCase() !== liveRoot.toLowerCase()) {
            return reply.code(409).send({
                ok: false,
                code: "StaleEnrollmentRoot",
                status: 409,
                detail:
                    "publicInputs[1] does not match the live EnrollmentRegistry root — " +
                    "fetch a fresh Merkle path from /enrollment/:commitment/path on the OPRF service",
            });
        }

        // 3. Compose calldata for revokeVote(petitionId, nullifier, proof, publicInputs).
        const args = [
            BigInt(body.petitionId),
            body.nullifier as Hex,
            body.proof as Hex,
            body.publicInputs as Hex[],
        ] as const;

        // 4. Simulate first so reverts surface as 4xx, not a sent tx.
        try {
            await clients.publicClient.simulateContract({
                address: config.petitionRegistry,
                abi: petitionRegistryV2Abi,
                functionName: "revokeVote",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    Hex,
                    readonly Hex[],
                ],
                account: clients.account,
            });
        } catch (err) {
            const mapped = mapContractError(err);
            req.log.warn({ err: mapped.body }, "revoke simulate revert");
            return reply.code(mapped.status).send({
                ok: false,
                code: mapped.body.error,
                status: mapped.status,
                detail: mapped.body.detail,
            });
        }

        let txHash: Hex;
        try {
            txHash = await clients.sendTx({
                address: config.petitionRegistry,
                abi: petitionRegistryV2Abi,
                functionName: "revokeVote",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    Hex,
                    readonly Hex[],
                ],
            });
        } catch (err) {
            const mapped = mapContractError(err);
            req.log.error({ err: mapped.body }, "revoke write revert");
            return reply.code(mapped.status).send({
                ok: false,
                code: mapped.body.error,
                status: mapped.status,
                detail: mapped.body.detail,
            });
        }

        return reply.code(200).send({
            ok: true,
            txHash,
            blockExplorerUrl: config.blockExplorerBase
                ? `${config.blockExplorerBase}${txHash}`
                : null,
        });
    });

    app.get("/tx/:hash", async (req, reply) => {
        const parsed = TxParams.safeParse(req.params);
        if (!parsed.success) return reply.code(400).send({ error: "BadRequest" });
        const hash = parsed.data.hash as Hex;

        let receipt: Awaited<
            ReturnType<typeof clients.publicClient.getTransactionReceipt>
        > | null = null;
        try {
            receipt = await clients.publicClient.getTransactionReceipt({ hash });
        } catch {
            try {
                const tx = await clients.publicClient.getTransaction({ hash });
                if (tx && tx.blockNumber === null) {
                    return reply.code(202).send({ status: "pending" });
                }
            } catch {
                return reply.code(404).send({ error: "TxNotFound" });
            }
            return reply.code(404).send({ error: "TxNotFound" });
        }

        if (!receipt) return reply.code(404).send({ error: "TxNotFound" });

        const wasOurTarget =
            receipt.to !== null &&
            receipt.to !== undefined &&
            getAddress(receipt.to) === getAddress(config.petitionRegistry);

        let petitionId: string | undefined;
        let signatureCount: number | undefined;
        let revoked = false;

        if (wasOurTarget) {
            for (const log of receipt.logs) {
                try {
                    const decoded = decodeEventLog({
                        abi: petitionRegistryV2Abi,
                        data: log.data,
                        topics: log.topics,
                    });
                    if (decoded.eventName === "PetitionSigned") {
                        const a = decoded.args as unknown as {
                            id: bigint;
                            nullifier: Hex;
                            newCount: number;
                        };
                        petitionId = a.id.toString();
                        signatureCount = Number(a.newCount);
                        break;
                    }
                    if (decoded.eventName === "PetitionRevoked") {
                        const a = decoded.args as unknown as {
                            id: bigint;
                            nullifier: Hex;
                            newCount: number;
                        };
                        petitionId = a.id.toString();
                        signatureCount = Number(a.newCount);
                        revoked = true;
                        break;
                    }
                } catch {
                    // not one of our events — keep looking.
                }
            }
        }

        return reply.code(200).send({
            status: receipt.status,
            blockNumber: receipt.blockNumber.toString(),
            gasUsed: receipt.gasUsed.toString(),
            petitionId: petitionId ?? null,
            signatureCount: signatureCount ?? null,
            revoked,
        });
    });

    return app;
}
