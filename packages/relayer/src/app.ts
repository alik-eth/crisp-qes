import Fastify, { type FastifyInstance } from "fastify";
import {
    type Hex,
    decodeEventLog,
    getAddress,
    hexToBigInt,
} from "viem";
import { z } from "zod";

import { petitionRegistryAbi } from "./abi.js";
import { makeClients, type Clients } from "./chain.js";
import type { RelayerConfig } from "./config.js";
import { mapContractError } from "./errors.js";
import { makeRateLimiter, type RateLimiter } from "./rateLimit.js";

const hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/, "expected 32-byte hex");
const hex = z.string().regex(/^0x[0-9a-fA-F]+$/, "expected hex string");
const decimalUint = z.string().regex(/^\d+$/, "expected decimal integer");

const SubmitBody = z.object({
    petitionId: decimalUint,
    nullifier: hex32,
    pubkeyX: hex32,
    pubkeyY: hex32,
    sigR: hex32,
    sigS: hex32,
    proof: hex,
    publicInputs: z.array(hex32).length(7),
});

const TxParams = z.object({
    hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
});

export interface BuildAppOptions {
    config: RelayerConfig;
    // Override for tests; defaults to live viem clients.
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

    app.get("/healthz", async () => ({
        ok: true,
        chainId: config.chainId,
        registry: config.registry,
        relayerAddr: clients.account.address,
    }));

    app.post("/submit", async (req, reply) => {
        const ip = req.ip ?? "unknown";
        if (!rateLimiter.take(ip)) {
            return reply
                .code(429)
                .send({ error: "RateLimited", retryAfterMs: config.rateLimitWindowMs });
        }

        const parsed = SubmitBody.safeParse(req.body);
        if (!parsed.success) {
            return reply
                .code(400)
                .send({ error: "BadRequest", detail: parsed.error.flatten() });
        }
        const body = parsed.data;

        // Cross-field sanity: publicInputs entries must equal the dedicated
        // fields (the contract checks this too, but bouncing here saves gas).
        const piPetition = hexToBigInt(body.publicInputs[0] as Hex);
        if (piPetition.toString() !== body.petitionId) {
            return reply.code(400).send({
                error: "BadRequest",
                detail: "publicInputs[0] != petitionId",
            });
        }
        if (
            body.publicInputs[1] !== body.nullifier ||
            body.publicInputs[3] !== body.pubkeyX ||
            body.publicInputs[4] !== body.pubkeyY
        ) {
            return reply.code(400).send({
                error: "BadRequest",
                detail: "publicInputs do not match (nullifier, pubkeyX, pubkeyY)",
            });
        }

        const args = [
            BigInt(body.petitionId),
            body.nullifier as Hex,
            hexToBigInt(body.pubkeyX as Hex),
            hexToBigInt(body.pubkeyY as Hex),
            hexToBigInt(body.sigR as Hex),
            hexToBigInt(body.sigS as Hex),
            body.proof as Hex,
            body.publicInputs as Hex[],
        ] as const;

        try {
            // Simulate first so reverts surface as 4xx instead of a sent tx.
            await clients.publicClient.simulateContract({
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "signPetition",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    bigint,
                    bigint,
                    bigint,
                    bigint,
                    Hex,
                    readonly Hex[],
                ],
                account: clients.account,
            });
        } catch (err) {
            const mapped = mapContractError(err);
            req.log.warn({ err: mapped.body }, "simulate revert");
            return reply.code(mapped.status).send(mapped.body);
        }

        let txHash: Hex;
        try {
            txHash = await clients.walletClient.writeContract({
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "signPetition",
                args: args as unknown as readonly [
                    bigint,
                    Hex,
                    bigint,
                    bigint,
                    bigint,
                    bigint,
                    Hex,
                    readonly Hex[],
                ],
                account: clients.account,
                chain: clients.chain,
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

    app.get("/tx/:hash", async (req, reply) => {
        const parsed = TxParams.safeParse(req.params);
        if (!parsed.success) {
            return reply.code(400).send({ error: "BadRequest" });
        }
        const hash = parsed.data.hash as Hex;

        let receipt: Awaited<
            ReturnType<typeof clients.publicClient.getTransactionReceipt>
        > | null = null;
        try {
            receipt = await clients.publicClient.getTransactionReceipt({ hash });
        } catch {
            // viem throws on "not found" / pending — try the tx itself to
            // distinguish pending from genuinely unknown.
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
            getAddress(receipt.to) === getAddress(config.registry);

        let nullifierUsedFor: string | undefined;
        let signatureCount: number | undefined;

        if (wasOurTarget) {
            for (const log of receipt.logs) {
                try {
                    const decoded = decodeEventLog({
                        abi: petitionRegistryAbi,
                        data: log.data,
                        topics: log.topics,
                    });
                    if (decoded.eventName === "PetitionSigned") {
                        const a = decoded.args as {
                            id: bigint;
                            nullifier: Hex;
                            newCount: number;
                        };
                        nullifierUsedFor = a.id.toString();
                        signatureCount = Number(a.newCount);
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
            nullifierUsedFor: nullifierUsedFor ?? null,
            signatureCount: signatureCount ?? null,
        });
    });

    return app;
}
