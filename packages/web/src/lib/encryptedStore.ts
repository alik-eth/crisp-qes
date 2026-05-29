// IndexedDB-backed encrypted store for the OPRF output `N` and the
// enrollment material derived from it.
//
// The encryption key is derived from the WebAuthn PRF output via HKDF.
// AES-GCM with a per-record random 12-byte IV; the ciphertext is the
// concatenation `iv || ct || tag` (the WebCrypto AES-GCM API folds the
// tag into the output).
//
// Schema (one row per enrollment epoch, keyed by an integer):
//   version: number      — schema version (currently 1)
//   commitment: hex32    — for display + lookup against the chain
//   leafIndex: number    — Merkle leaf index in the enrollment tree
//   credentialId: hex    — the Passkey we used to wrap this row
//   ciphertext: Uint8Array — wraps `{ enrollmentSecret, oprfOutputN,
//                            merklePath[], merklePathIndices[] }`
//                            (serialised as JSON)

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";

const DB_NAME = "crisp_qes_v2";
// v2 bump introduces the `accounts` store used by `lib/account.ts`. Both
// modules MUST agree on the version; if one opens at v1 after the other
// has already upgraded to v2, IndexedDB throws "stored database is a
// higher version than the version requested".
const DB_VERSION = 2;
const STORE = "enrollments";
const STORE_ACCOUNTS = "accounts";

export interface EnrollmentRecord {
    /** Schema version — bump when the inner payload shape changes. */
    version: number;
    /** 0x-prefixed 32-byte hex; matches the on-chain commitment. */
    commitment: `0x${string}`;
    /** Position in the OPRF Merkle tree. */
    leafIndex: number;
    /** 0x-prefixed hex of the WebAuthn credential id used to wrap this row. */
    credentialId: `0x${string}`;
    /** AES-GCM wrap of the JSON-encoded payload below. */
    ciphertext: Uint8Array;
}

export interface EnrollmentPayload {
    /** Pedersen-derived enrollment secret `s` (BN254 field, 0x-hex). */
    enrollmentSecret: `0x${string}`;
    /** 32-byte ristretto-encoded unblinded OPRF output `N`. */
    oprfOutputN: `0x${string}`;
    /** Merkle path siblings from leaf to root, TREE_DEPTH entries. */
    merklePath: `0x${string}`[];
    /** Per-level direction bits (0 = sibling-right, 1 = sibling-left). */
    merklePathIndices: (0 | 1)[];
}

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE, {
                    keyPath: "id",
                    autoIncrement: true,
                });
            }
            // Mirror the accounts-store creation in `lib/account.ts` so
            // that whichever module triggers the v1→v2 upgrade first
            // brings both stores into existence.
            if (!db.objectStoreNames.contains(STORE_ACCOUNTS)) {
                db.createObjectStore(STORE_ACCOUNTS, {
                    keyPath: "credentialId",
                });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    const ab = new ArrayBuffer(bytes.byteLength);
    const out = new Uint8Array(ab);
    out.set(bytes);
    return out;
}

async function deriveAesKey(prfOutput: Uint8Array): Promise<CryptoKey> {
    // HKDF-SHA256, salt = "crisp-qes-v2-aes", info = "enroll-wrap-v1".
    const km = hkdf(
        sha256,
        prfOutput,
        new TextEncoder().encode("crisp-qes-v2-aes"),
        new TextEncoder().encode("enroll-wrap-v1"),
        32,
    );
    return crypto.subtle.importKey("raw", buf(km), { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
    ]);
}

function toHex(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

function fromHex(h: string): Uint8Array {
    const s = h.startsWith("0x") ? h.slice(2) : h;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

export async function wrapPayload(
    payload: EnrollmentPayload,
    prfOutput: Uint8Array,
): Promise<Uint8Array> {
    const key = await deriveAesKey(prfOutput);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = new TextEncoder().encode(JSON.stringify(payload));
    const ct = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: buf(iv) },
            key,
            buf(pt),
        ),
    );
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0);
    out.set(ct, iv.length);
    return out;
}

export async function unwrapPayload(
    wrapped: Uint8Array,
    prfOutput: Uint8Array,
): Promise<EnrollmentPayload> {
    const key = await deriveAesKey(prfOutput);
    const iv = wrapped.subarray(0, 12);
    const ct = wrapped.subarray(12);
    const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: buf(iv) },
        key,
        buf(ct),
    );
    const json = new TextDecoder().decode(pt);
    return JSON.parse(json) as EnrollmentPayload;
}

export async function putEnrollment(
    rec: EnrollmentRecord,
): Promise<number> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        const req = tx.objectStore(STORE).add(rec);
        req.onsuccess = () => resolve(req.result as number);
        req.onerror = () => reject(req.error);
    });
}

export async function listEnrollments(): Promise<
    Array<EnrollmentRecord & { id: number }>
> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const req = tx.objectStore(STORE).getAll();
        req.onsuccess = () =>
            resolve(req.result as Array<EnrollmentRecord & { id: number }>);
        req.onerror = () => reject(req.error);
    });
}

export async function clearAll(): Promise<void> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        const req = tx.objectStore(STORE).clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

export const hex = { toHex, fromHex };
