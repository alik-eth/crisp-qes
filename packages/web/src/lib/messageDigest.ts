// sha256(petition_id_be32 || "::" || textHash_32) — same construction the
// signedAttrs messageDigest attribute must carry. Used to confirm the
// uploaded .p7s was generated for THIS petition.

import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes, type Hex } from "viem";

function petitionIdBytes(id: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let v = id;
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
}

const SEPARATOR = new TextEncoder().encode("::");

export function expectedMessageDigest(petitionId: bigint, textHash: Hex): Uint8Array {
    const idBytes = petitionIdBytes(petitionId);
    const textHashBytes = hexToBytes(textHash);
    const buf = new Uint8Array(idBytes.length + SEPARATOR.length + textHashBytes.length);
    buf.set(idBytes, 0);
    buf.set(SEPARATOR, idBytes.length);
    buf.set(textHashBytes, idBytes.length + SEPARATOR.length);
    return sha256(buf);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

export function bytesToHex(b: Uint8Array): string {
    return "0x" + Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
}
