// secp256k1 root-update attester for EnrollmentRegistry.
//
// Digest format pinned by team-lead 2026-05-29 — must match the verifier
// inside EnrollmentRegistry.updateRoot byte-for-byte:
//
//   newCommitmentsHash = keccak256(abi.encodePacked(bytes32[]))
//   innerDigest = keccak256(abi.encode(
//       bytes32  oldRoot,
//       bytes32  newRoot,
//       bytes32  newCommitmentsHash,
//       uint256  chainId,
//       address  enrollmentRegistry
//   ))
//   ethSigned   = keccak256("\x19Ethereum Signed Message:\n32" || innerDigest)
//   sig         = secp256k1.sign(ethSigned, attesterKey)    // 65 B: r||s||v
//
// The EIP-191 wrap lets viem's `walletClient.signMessage({ message: { raw }})`
// produce the identical signature client-side. EIP-2 low-s is enforced by
// `@noble/curves` already (sign() returns a low-s sig by default).
//
// Replay protection:
//   * `chainId` and `enrollmentRegistry` pin to a single deployment.
//   * `oldRoot` linearises the root timeline — a captured sig can't be
//     replayed against a different "previous" root.

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
    type Hex,
    bytesToHex,
    concat,
    encodeAbiParameters,
    encodePacked,
    hexToBytes,
    keccak256,
    pad,
    toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

export interface RootUpdate {
    oldRoot: bigint;
    newRoot: bigint;
    /** Commitments appended in this update (always length 1 for the demo). */
    newCommitments: bigint[];
    chainId: number;
    /** EnrollmentRegistry deployment address. */
    enrollmentRegistry: `0x${string}`;
}

const ETH_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");

function bigintToHex32(v: bigint): `0x${string}` {
    if (v < 0n) throw new Error("bigintToHex32: negative");
    const hex = v.toString(16).padStart(64, "0");
    if (hex.length > 64) throw new Error("bigintToHex32: value exceeds 32 bytes");
    return `0x${hex}` as `0x${string}`;
}

/**
 * Hash the per-update commitments list exactly as the registry will.
 *
 *   keccak256(abi.encodePacked(newCommitments))   // tight, no length prefix
 *
 * Tight packing matches Solidity `keccak256(abi.encodePacked(bytes32[]))`,
 * which is what the team-lead spec uses; the registry implementation
 * computes the same hash from calldata.
 */
export function hashCommitmentList(newCommitments: bigint[]): `0x${string}` {
    const items = newCommitments.map(bigintToHex32);
    // encodePacked with a bytes32[] is just byte concatenation.
    return keccak256(
        encodePacked(["bytes32[]"], [items as readonly `0x${string}`[]]),
    );
}

/** Compute the inner ABI-encoded digest the citizen / registry verify. */
export function innerDigest(u: RootUpdate): `0x${string}` {
    const commitmentsHash = hashCommitmentList(u.newCommitments);
    const encoded = encodeAbiParameters(
        [
            { type: "bytes32" },
            { type: "bytes32" },
            { type: "bytes32" },
            { type: "uint256" },
            { type: "address" },
        ],
        [
            bigintToHex32(u.oldRoot),
            bigintToHex32(u.newRoot),
            commitmentsHash,
            BigInt(u.chainId),
            u.enrollmentRegistry,
        ],
    );
    return keccak256(encoded);
}

/** Apply EIP-191 personal_sign wrapping. */
export function ethSignedDigest(inner: `0x${string}`): Uint8Array {
    const innerBytes = hexToBytes(inner);
    const wrapped = concat([ETH_PREFIX, innerBytes]);
    return keccak_256(wrapped);
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
        this.publicKey = bytesToHex(
            secp256k1.getPublicKey(this.privateKey, false),
        );
    }

    /**
     * Produce the 65-byte EIP-191-wrapped signature
     * `r (32) || s (32) || v (1 ∈ {27, 28})`.
     *
     * Also returns the inner digest so the client can submit it to the
     * registry directly without recomputing.
     */
    sign(u: RootUpdate): {
        sig: `0x${string}`;
        innerDigest: `0x${string}`;
    } {
        const inner = innerDigest(u);
        const ethDigest = ethSignedDigest(inner);
        // @noble/curves returns low-s by default (EIP-2 compliant).
        const sig = secp256k1.sign(ethDigest, this.privateKey);
        const r = pad(toHex(sig.r), { size: 32 });
        const s = pad(toHex(sig.s), { size: 32 });
        const recovery =
            typeof sig.recovery === "number" ? sig.recovery : 0;
        const v = (27 + recovery) & 0xff;
        const vHex = v.toString(16).padStart(2, "0");
        return {
            sig: `${r}${s.slice(2)}${vHex}` as `0x${string}`,
            innerDigest: inner,
        };
    }
}

export { keccak256 };
