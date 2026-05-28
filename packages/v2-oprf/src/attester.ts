// secp256k1 root-update attester.
//
// The OPRF service holds an attester key whose Ethereum address is
// whitelisted in EnrollmentRegistry. On every new commitment append we
// produce a recoverable ECDSA signature over the canonical "root update"
// digest below; EnrollmentRegistry's `appendCommitment` recovers the
// signer with `ecrecover` and gates the append on identity match.
//
// Canonical digest (pinned so the v2-contracts task can implement
// verification byte-for-byte):
//
//   tag  = bytes24("CRISP_QES_OPRF_ROOT_V2.1")        // 0x4352...3231
//   body = abi.encodePacked(tag, oldRoot, newRoot, uint256(leafIndex))
//   h    = keccak256(body)
//   sig  = secp256k1.sign(h, attesterKey)             // 65-byte (r, s, v)
//
// This is *not* EIP-191 wrapped: the contract recovers directly from h, so
// no "\x19Ethereum Signed Message:\n" prefix is added on either side. v2.1
// considered EIP-712 but it adds opcodes for no privacy benefit at this
// layer — the digest already includes a tag + monotone counter (leafIndex)
// so cross-context replay is impossible.

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
    type Hex,
    bytesToHex,
    hexToBytes,
    keccak256,
    pad,
    toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const ROOT_TAG = new TextEncoder().encode("CRISP_QES_OPRF_ROOT_V2.1");
if (ROOT_TAG.length !== 24) {
    // Compile-time invariant — keep the tag at 24 bytes so v2-contracts can
    // load it as a Solidity `bytes24` literal without dynamic length.
    throw new Error("ROOT_TAG must be exactly 24 bytes");
}

export interface RootUpdate {
    oldRoot: bigint;
    newRoot: bigint;
    leafIndex: number;
}

function bigintToBE32(v: bigint): Uint8Array {
    if (v < 0n) throw new Error("bigintToBE32: negative");
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

function leafIndexToBE32(n: number): Uint8Array {
    if (n < 0 || !Number.isSafeInteger(n)) {
        throw new Error("leafIndex must be a non-negative safe integer");
    }
    return bigintToBE32(BigInt(n));
}

/** Compute the 32-byte digest the EnrollmentRegistry's ecrecover will see. */
export function rootUpdateDigest(u: RootUpdate): Uint8Array {
    const body = new Uint8Array(24 + 32 + 32 + 32);
    body.set(ROOT_TAG, 0);
    body.set(bigintToBE32(u.oldRoot), 24);
    body.set(bigintToBE32(u.newRoot), 56);
    body.set(leafIndexToBE32(u.leafIndex), 88);
    return keccak_256(body);
}

export class Attester {
    private readonly privateKey: Uint8Array;
    readonly address: `0x${string}`;
    readonly publicKey: `0x${string}`;

    constructor(privateKey: Hex) {
        const stripped = privateKey.startsWith("0x")
            ? privateKey.slice(2)
            : privateKey;
        if (!/^[0-9a-fA-F]{64}$/.test(stripped)) {
            throw new Error("attester key must be 32-byte hex");
        }
        this.privateKey = hexToBytes(`0x${stripped}`);
        const acct = privateKeyToAccount(`0x${stripped}` as Hex);
        this.address = acct.address;
        // Uncompressed pubkey (65 bytes, 0x04 prefix) — handy for clients.
        this.publicKey = bytesToHex(
            secp256k1.getPublicKey(this.privateKey, false),
        );
    }

    sign(u: RootUpdate): `0x${string}` {
        const h = rootUpdateDigest(u);
        const sig = secp256k1.sign(h, this.privateKey);
        // 65-byte recoverable signature: r (32) || s (32) || v (1).
        // We follow the Ethereum convention of v ∈ {27, 28}.
        const r = pad(toHex(sig.r), { size: 32 });
        const s = pad(toHex(sig.s), { size: 32 });
        const recovery =
            typeof sig.recovery === "number" ? sig.recovery : 0;
        const v = (27 + recovery) & 0xff;
        const vHex = v.toString(16).padStart(2, "0");
        return `${r}${s.slice(2)}${vHex}` as `0x${string}`;
    }
}

/** Re-export for downstream callers that need the digest for tests. */
export { keccak256 };
