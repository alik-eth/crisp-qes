// WebAuthn PRF extension wrapper.
//
// At enrollment we register a discoverable credential with the PRF
// extension; at sign time we ask the authenticator to evaluate the same
// PRF using a fixed salt. The 32-byte PRF output never leaves the
// authenticator's evaluator until the user gestures. We use it directly
// as material for an AES-GCM key that wraps the OPRF output stored in
// IndexedDB (see `encryptedStore.ts`).
//
// Salt: `sha256("crisp-qes-v2-prf-salt-v1")` (32 bytes). The salt is
// public and constant; it just keeps the PRF derivation distinct from
// any other PRF use of the same passkey.

import { sha256 } from "@noble/hashes/sha2";

const PRF_SALT_INPUT = "crisp-qes-v2-prf-salt-v1";

export function prfSalt(): Uint8Array {
    return sha256(new TextEncoder().encode(PRF_SALT_INPUT));
}

function randomBytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
}

// Wrap any Uint8Array (which TS types as `Uint8Array<ArrayBufferLike>` in
// strict lib mode) into a fresh ArrayBuffer-backed copy that the
// WebAuthn API accepts as `BufferSource` without a SharedArrayBuffer
// objection.
function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    const ab = new ArrayBuffer(bytes.byteLength);
    const out = new Uint8Array(ab);
    out.set(bytes);
    return out;
}

/**
 * Create a discoverable Passkey on this device and ask the authenticator
 * to evaluate the PRF with our fixed salt at registration time.
 *
 * Returns the new credential id (so we can later request a specific
 * authenticator) plus the 32-byte PRF output.
 *
 * Throws if the browser/authenticator doesn't support the PRF extension.
 */
export interface PrfRegisterResult {
    credentialId: Uint8Array;
    prfOutput: Uint8Array;
}

export async function registerPasskey(
    rpName: string,
    userId: Uint8Array,
    userName: string,
    userDisplayName: string,
): Promise<PrfRegisterResult> {
    const challenge = randomBytes(32);
    const cred = (await navigator.credentials.create({
        publicKey: {
            challenge: buf(challenge),
            rp: { name: rpName, id: window.location.hostname },
            user: {
                id: buf(userId),
                name: userName,
                displayName: userDisplayName,
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 }, // ES256
                { type: "public-key", alg: -257 }, // RS256
            ],
            authenticatorSelection: {
                residentKey: "required",
                userVerification: "required",
            },
            extensions: {
                // PRF eval at registration: returns the same value the
                // authenticator will return at assertion time for the
                // same salt. Some browsers don't honour eval at create
                // — in that case we issue a follow-up `get()` with the
                // same credential id, see `evaluatePrfWithCredential`.
                prf: { eval: { first: buf(prfSalt()) } },
            } as AuthenticationExtensionsClientInputs,
        },
    })) as PublicKeyCredential | null;

    if (!cred) throw new Error("credential creation returned null");

    const ext = cred.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } };
    };
    const credentialId = new Uint8Array(cred.rawId);

    if (ext.prf?.results?.first) {
        return {
            credentialId,
            prfOutput: new Uint8Array(ext.prf.results.first),
        };
    }
    // Some platforms ignore PRF eval at create; immediately call
    // navigator.credentials.get() with the same id to read the PRF.
    const prfOutput = await evaluatePrfWithCredential(credentialId);
    return { credentialId, prfOutput };
}

/**
 * Ask any discoverable Passkey on this device to evaluate the PRF.
 * Used at sign time when we don't have a stable credential id yet
 * (it's stored locally with the encrypted blob).
 */
export async function evaluatePrf(): Promise<{
    credentialId: Uint8Array;
    prfOutput: Uint8Array;
}> {
    const challenge = randomBytes(32);
    const asn = (await navigator.credentials.get({
        publicKey: {
            challenge: buf(challenge),
            userVerification: "required",
            extensions: {
                prf: { eval: { first: buf(prfSalt()) } },
            } as AuthenticationExtensionsClientInputs,
        },
    })) as PublicKeyCredential | null;
    if (!asn) throw new Error("assertion returned null");
    const ext = asn.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } };
    };
    if (!ext.prf?.results?.first) {
        throw new Error("authenticator did not return a PRF output");
    }
    return {
        credentialId: new Uint8Array(asn.rawId),
        prfOutput: new Uint8Array(ext.prf.results.first),
    };
}

/**
 * Ask a specific credential (by id) to evaluate the PRF.
 */
export async function evaluatePrfWithCredential(
    credentialId: Uint8Array,
): Promise<Uint8Array> {
    const challenge = randomBytes(32);
    const asn = (await navigator.credentials.get({
        publicKey: {
            challenge: buf(challenge),
            userVerification: "required",
            allowCredentials: [{ type: "public-key", id: buf(credentialId) }],
            extensions: {
                prf: { eval: { first: buf(prfSalt()) } },
            } as AuthenticationExtensionsClientInputs,
        },
    })) as PublicKeyCredential | null;
    if (!asn) throw new Error("assertion returned null");
    const ext = asn.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } };
    };
    if (!ext.prf?.results?.first) {
        throw new Error("authenticator did not return a PRF output");
    }
    return new Uint8Array(ext.prf.results.first);
}

/**
 * Best-effort feature probe. Real PRF support can only be confirmed
 * after a credential interaction, but we can rule out obvious "no
 * WebAuthn at all" environments early.
 */
export function probeWebauthn(): {
    available: boolean;
    reason?: string;
} {
    if (typeof window === "undefined" || !("PublicKeyCredential" in window)) {
        return { available: false, reason: "WebAuthn not available in this browser" };
    }
    if (!window.isSecureContext) {
        return { available: false, reason: "WebAuthn requires HTTPS or localhost" };
    }
    return { available: true };
}
