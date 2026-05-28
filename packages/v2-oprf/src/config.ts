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
        throw new Error("[v2-oprf] OPRF_KEY is required in production");
    } else {
        const k = randomScalar();
        oprfKey = encodeScalarLE(k);
        // eslint-disable-next-line no-console
        console.warn(
            `[v2-oprf] OPRF_KEY not set — generated dev key 0x${bytesToHex(oprfKey)}`,
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
            "[v2-oprf] OPRF_ATTESTER_KEY is required in production",
        );
    } else {
        const raw = randomBytes(32);
        attesterKey = `0x${bytesToHex(raw)}` as `0x${string}`;
        // eslint-disable-next-line no-console
        console.warn(
            `[v2-oprf] OPRF_ATTESTER_KEY not set — generated dev key ${attesterKey}`,
        );
    }

    const corsRaw =
        env.CORS_ALLOWED_ORIGINS ??
        (isProd ? "https://crisp-qes-v2-web.fly.dev" : "*");
    const corsAllowedOrigins = corsRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

    return {
        port: Number(env.PORT ?? 8788),
        isProd,
        dbPath: env.DB_PATH ?? (isProd ? "/data/oprf.db" : "./oprf.db"),
        oprfKey,
        oprfPubkey: new Uint8Array(32), // filled by buildApp once curve is loaded
        attesterKey,
        corsAllowedOrigins,
    };
}
