// Env loading + key generation.
//
// Two secrets:
//   OPRF_KEY            — 32-byte little-endian ristretto255 scalar
//   OPRF_ATTESTER_KEY   — 32-byte secp256k1 private key for root signing
//
// In dev (NODE_ENV != "production") both are auto-generated at boot if
// absent, with a stern warning so nobody accidentally ships dev keys to
// prod. In prod, both are required and validated.

import { randomBytes } from "node:crypto";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import { randomScalar } from "./oprf.js";

export interface OprfConfig {
    port: number;
    isProd: boolean;
    dbPath: string;
    oprfKey: Uint8Array;        // 32-byte LE ristretto255 scalar
    oprfPubkey: Uint8Array;     // 32-byte ristretto255 public key (set in app)
    attesterKey: `0x${string}`; // 32-byte secp256k1 priv key, 0x-prefixed
    /**
     * Chain ID the EnrollmentRegistry is deployed on. Baked into the
     * attester signature digest so a captured sig can't cross forks /
     * chains. Base Sepolia = 84532 (the v2.1 demo target).
     */
    chainId: number;
    /**
     * EnrollmentRegistry deployment address. Baked into the digest so a
     * captured sig can't cross contracts. Zero address in dev means
     * "registry not yet deployed" — the service still boots, but signed
     * root updates won't verify against a real registry until this is set.
     */
    enrollmentRegistry: `0x${string}`;
    corsAllowedOrigins: string[];
}

function encodeScalarLE(s: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let x = s;
    for (let i = 0; i < 32; i++) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

function decodeHex32(hex: string, name: string): Uint8Array {
    const h = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (!/^[0-9a-fA-F]{64}$/.test(h)) {
        throw new Error(`${name} must be 32-byte hex (got ${h.length / 2}B)`);
    }
    return hexToBytes(h);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): OprfConfig {
    const nodeEnv = env.NODE_ENV ?? "development";
    const isProd = nodeEnv === "production";

    // OPRF secret scalar k.
    let oprfKey: Uint8Array;
    if (env.OPRF_KEY) {
        oprfKey = decodeHex32(env.OPRF_KEY, "OPRF_KEY");
    } else if (isProd) {
        throw new Error("[oprf] OPRF_KEY is required in production");
    } else {
        const k = randomScalar();
        oprfKey = encodeScalarLE(k);
        // eslint-disable-next-line no-console
        console.warn(
            `[oprf] OPRF_KEY not set — generated dev key 0x${bytesToHex(oprfKey)}`,
        );
    }

    // secp256k1 attester key.
    let attesterKey: `0x${string}`;
    if (env.OPRF_ATTESTER_KEY) {
        const norm = env.OPRF_ATTESTER_KEY.startsWith("0x")
            ? env.OPRF_ATTESTER_KEY
            : `0x${env.OPRF_ATTESTER_KEY}`;
        if (!/^0x[0-9a-fA-F]{64}$/.test(norm)) {
            throw new Error("OPRF_ATTESTER_KEY must be 32-byte hex");
        }
        attesterKey = norm as `0x${string}`;
    } else if (isProd) {
        throw new Error(
            "[oprf] OPRF_ATTESTER_KEY is required in production",
        );
    } else {
        const raw = randomBytes(32);
        attesterKey = `0x${bytesToHex(raw)}` as `0x${string}`;
        // eslint-disable-next-line no-console
        console.warn(
            `[oprf] OPRF_ATTESTER_KEY not set — generated dev key ${attesterKey}`,
        );
    }

    const corsRaw =
        env.CORS_ALLOWED_ORIGINS ??
        (isProd ? "https://crisp-qes-v2-web.fly.dev" : "*");
    const corsAllowedOrigins = corsRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

    const chainId = Number(env.CHAIN_ID ?? (isProd ? 84532 : 31337));
    const rawRegistry = env.ENROLLMENT_REGISTRY ?? (isProd ? "" : "");
    let enrollmentRegistry: `0x${string}` = "0x0000000000000000000000000000000000000000";
    if (rawRegistry) {
        if (!/^0x[0-9a-fA-F]{40}$/.test(rawRegistry)) {
            throw new Error(
                "[oprf] ENROLLMENT_REGISTRY must be a 20-byte hex address",
            );
        }
        enrollmentRegistry = rawRegistry as `0x${string}`;
    } else if (!isProd) {
        // Dev fallback — signed root updates won't verify against a real
        // registry, but the service still boots so the client can iterate.
        // eslint-disable-next-line no-console
        console.warn(
            "[oprf] ENROLLMENT_REGISTRY not set — signing against zero address",
        );
    }

    return {
        port: Number(env.PORT ?? 8788),
        isProd,
        dbPath: env.DB_PATH ?? (isProd ? "/data/oprf.db" : "./oprf.db"),
        oprfKey,
        oprfPubkey: new Uint8Array(32), // filled by buildApp once curve is loaded
        attesterKey,
        chainId,
        enrollmentRegistry,
        corsAllowedOrigins,
    };
}
