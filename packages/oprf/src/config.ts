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

import { parseTrustRootEnv, type TrustedCa } from "./attestation.js";
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
     * chains. Sepolia = 11155111 (current demo target post Base-Sepolia
     * retirement); Base Sepolia = 84532 (historical).
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
    /**
     * Minimum age (completed years) the citizen must be at the moment of
     * `/oprf/blind-eval` to receive an OPRF evaluation. Read from
     * `AGE_THRESHOLD` env, default 18. Set to 0 to disable the gate
     * entirely (useful for tests + the dev profile).
     *
     * Implementation detail: when the Diia cert lacks a parseable DOB
     * attribute the service fail-opens with a warning log — see
     * `/oprf/blind-eval` in `app.ts`. v3 multi-QTSP revisits.
     */
    ageThreshold: number;
    /**
     * Diia LOTL trust roots. Populated from `OPRF_TRUST_ROOT_PEM` env
     * (base64-encoded PEM bundle). Empty array means chain verification
     * is skipped — `loadConfig` rejects this at startup unless
     * `OPRF_TRUST_ROOT_REQUIRED=false` is explicitly opted out.
     */
    trustRoots: TrustedCa[];
    /**
     * Maximum age in seconds the `.p7s` signingTime may be relative to
     * server wall clock. 0 disables the freshness check (dev/tests only).
     * Default 600s (10 min) — matches a typical citizen UX window.
     */
    signingTimeMaxAgeSec: number;
    /**
     * Maximum number of `/oprf/blind-eval` calls a single RNOKPP (subject
     * serial hash) is allowed within the current epoch (TTL =
     * `replayCacheTtlSec`). Throttle, don't ban — generous-but-finite cap
     * tolerates transient retry while flagging flooding. Default 3.
     */
    maxBlindEvalPerRnokppPerEpoch: number;
    /**
     * TTL in seconds for both the per-epoch p7s-hash replay cache (task #31)
     * and the per-RNOKPP blind-eval counter (task #32). v2 uses a single
     * long-lived epoch, so the default ~400 days subsumes the OPRF key's
     * lifetime. Operators rotate this in lockstep with `OPRF_KEY`.
     */
    replayCacheTtlSec: number;
    /**
     * Enrollment epoch string baked into the .p7s payload-binding artifact
     * (task #29). The citizen signs a JSON blob of the form
     *   {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x…"}
     * in Diia; the OPRF service reconstructs those exact bytes from the
     * request and asserts `signedAttrs.messageDigest == sha256(bytes)`. This
     * binds the citizen's QES to THIS enrollment intent + THIS blinded
     * input. Operators rotate this in lockstep with `OPRF_KEY` rotations so
     * captured signatures from a previous epoch can't be replayed. Default
     * `"v2-2026"`.
     */
    enrollmentEpoch: string;
    /**
     * When true (default), `/oprf/blind-eval` computes the expected
     * messageDigest from the request's `blindedInput` + `enrollmentEpoch`
     * and asserts the .p7s signedAttrs match. Set to false to skip the
     * binding check — useful for tests against fixtures whose binding
     * source isn't reconstructible. Env: `OPRF_ENFORCE_PAYLOAD_BINDING`.
     */
    enforcePayloadBinding: boolean;
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
        (isProd ? "https://crisp-qes-web.fly.dev" : "*");
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

    // Diia LOTL trust roots — fail-closed unless explicitly opted out.
    // The env var carries a base64-encoded PEM bundle (one or more
    // `-----BEGIN CERTIFICATE-----` blocks) so multi-cert chains pass
    // through Fly/k8s secret stores without newline drama.
    let trustRoots: TrustedCa[] = [];
    const trustRootRequired = (env.OPRF_TRUST_ROOT_REQUIRED ?? "true")
        .toLowerCase() !== "false";
    if (env.OPRF_TRUST_ROOT_PEM) {
        try {
            trustRoots = parseTrustRootEnv(env.OPRF_TRUST_ROOT_PEM);
        } catch (e) {
            throw new Error(
                `[oprf] OPRF_TRUST_ROOT_PEM failed to parse: ${(e as Error).message}`,
            );
        }
    } else if (trustRootRequired) {
        throw new Error(
            "[oprf] OPRF_TRUST_ROOT_PEM is required (fail-closed default). " +
            "Set it to a base64-encoded PEM bundle of trusted Diia CA certs, " +
            "or pass OPRF_TRUST_ROOT_REQUIRED=false for the demo/local-dev " +
            "case where chain verification is intentionally skipped.",
        );
    } else {
        // eslint-disable-next-line no-console
        console.warn(
            "[oprf] OPRF_TRUST_ROOT_PEM unset and OPRF_TRUST_ROOT_REQUIRED=false " +
            "— chain-of-trust verification is DISABLED. Do NOT use in production.",
        );
    }

    // signingTime freshness window. 0 disables (dev/tests).
    let signingTimeMaxAgeSec = 600;
    if (env.SIGNING_TIME_MAX_AGE_SEC !== undefined) {
        const n = Number(env.SIGNING_TIME_MAX_AGE_SEC);
        if (!Number.isInteger(n) || n < 0 || n > 24 * 3600) {
            throw new Error(
                `[oprf] SIGNING_TIME_MAX_AGE_SEC must be an integer in [0, 86400] (got ${env.SIGNING_TIME_MAX_AGE_SEC})`,
            );
        }
        signingTimeMaxAgeSec = n;
    }

    // Minimum citizen age (completed years). 0 disables the gate.
    let ageThreshold = 18;
    if (env.AGE_THRESHOLD !== undefined) {
        const n = Number(env.AGE_THRESHOLD);
        if (!Number.isInteger(n) || n < 0 || n > 130) {
            throw new Error(
                `[oprf] AGE_THRESHOLD must be an integer in [0, 130] (got ${env.AGE_THRESHOLD})`,
            );
        }
        ageThreshold = n;
    }

    // Per-RNOKPP blind-eval cap. 0 disables the throttle (testing only).
    let maxBlindEvalPerRnokppPerEpoch = 3;
    if (env.MAX_BLIND_EVAL_PER_RNOKPP_PER_EPOCH !== undefined) {
        const n = Number(env.MAX_BLIND_EVAL_PER_RNOKPP_PER_EPOCH);
        if (!Number.isInteger(n) || n < 0 || n > 1_000_000) {
            throw new Error(
                `[oprf] MAX_BLIND_EVAL_PER_RNOKPP_PER_EPOCH must be an integer in [0, 1000000] (got ${env.MAX_BLIND_EVAL_PER_RNOKPP_PER_EPOCH})`,
            );
        }
        maxBlindEvalPerRnokppPerEpoch = n;
    }

    // Replay cache + per-RNOKPP counter TTL. Default ~400d covers a v2 epoch.
    let replayCacheTtlSec = 86400 * 400;
    if (env.REPLAY_CACHE_TTL_SEC !== undefined) {
        const n = Number(env.REPLAY_CACHE_TTL_SEC);
        if (!Number.isInteger(n) || n <= 0 || n > 10 * 365 * 86400) {
            throw new Error(
                `[oprf] REPLAY_CACHE_TTL_SEC must be a positive integer in seconds (got ${env.REPLAY_CACHE_TTL_SEC})`,
            );
        }
        replayCacheTtlSec = n;
    }

    // Enrollment epoch — interpolated verbatim into the JSON payload-binding
    // artifact the citizen signs in Diia. Forbid control chars, space, quote,
    // backslash so reconstruction stays byte-exact across client + server.
    // `-` IS allowed so the default "v2-2026" works.
    const enrollmentEpoch = env.OPRF_ENROLLMENT_EPOCH ?? "v2-2026";
    if (
        enrollmentEpoch.length === 0 ||
        /[\x00-\x20"\\]/.test(enrollmentEpoch)
    ) {
        throw new Error(
            "[oprf] OPRF_ENROLLMENT_EPOCH must be a non-empty ASCII string " +
                "without quotes, backslashes, spaces, or control characters " +
                `(got ${JSON.stringify(enrollmentEpoch)})`,
        );
    }

    // Payload-binding enforcement. Defaults to true; operators set
    // OPRF_ENFORCE_PAYLOAD_BINDING=false only when bridging legacy clients
    // that don't yet sign over the canonical JSON binding.
    const enforcePayloadBinding =
        env.OPRF_ENFORCE_PAYLOAD_BINDING === undefined
            ? true
            : env.OPRF_ENFORCE_PAYLOAD_BINDING !== "false";

    return {
        port: Number(env.PORT ?? 8788),
        isProd,
        dbPath: env.DB_PATH ?? (isProd ? "/data/oprf.db" : "./oprf.db"),
        oprfKey,
        oprfPubkey: new Uint8Array(32), // filled by buildApp once curve is loaded
        attesterKey,
        ageThreshold,
        trustRoots,
        signingTimeMaxAgeSec,
        maxBlindEvalPerRnokppPerEpoch,
        replayCacheTtlSec,
        enrollmentEpoch,
        enforcePayloadBinding,
        chainId,
        enrollmentRegistry,
        corsAllowedOrigins,
    };
}
