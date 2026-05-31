// secp256k1 root-update attester for the EnrollmentRegistry (v3 Grumpkin
// service, build/unaudited). Direct port of packages/oprf/src/attester.ts — the
// digest scheme is IDENTICAL because v3 commitments land in the SAME deployed
// EnrollmentRegistry as v2's, so the `updateRoot` signature the contract checks
// must be computed byte-for-byte the same way.
//
// Digest scheme (must match EnrollmentRegistry.updateRoot's verifier):
//
//   newCommitmentsHash = keccak256(abi.encodePacked(bytes32[] newCommitments))
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
// @noble/curves returns a low-s signature by default (EIP-2 compliant).

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
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

const ETH_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");

function bigintToHex32(v) {
    if (v < 0n) throw new Error("bigintToHex32: negative");
    const hex = v.toString(16).padStart(64, "0");
    if (hex.length > 64) throw new Error("bigintToHex32: value exceeds 32 bytes");
    return `0x${hex}`;
}

/**
 * keccak256(abi.encodePacked(newCommitments)) — tight packing, no length
 * prefix, matching Solidity keccak256(abi.encodePacked(bytes32[])).
 */
export function hashCommitmentList(newCommitments) {
    const items = newCommitments.map(bigintToHex32);
    return keccak256(encodePacked(["bytes32[]"], [items]));
}

/** The inner ABI-encoded digest the registry verifies. */
export function innerDigest(u) {
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

/** EIP-191 personal_sign wrapping of the inner digest. */
export function ethSignedDigest(inner) {
    return keccak_256(concat([ETH_PREFIX, hexToBytes(inner)]));
}

export class Attester {
    /** @param {string} privateKey 32-byte secp256k1 hex (0x-optional). */
    constructor(privateKey) {
        const stripped = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
        if (!/^[0-9a-fA-F]{64}$/.test(stripped)) {
            throw new Error("attester key must be 32-byte hex");
        }
        this.privateKey = hexToBytes(`0x${stripped}`);
        this.address = privateKeyToAccount(`0x${stripped}`).address;
        this.publicKey = bytesToHex(secp256k1.getPublicKey(this.privateKey, false));
    }

    /**
     * Produce the 65-byte EIP-191-wrapped signature r(32)||s(32)||v(1∈{27,28})
     * plus the inner digest for diagnostics.
     * @param {{oldRoot:bigint,newRoot:bigint,newCommitments:bigint[],chainId:number,enrollmentRegistry:`0x${string}`}} u
     */
    sign(u) {
        const inner = innerDigest(u);
        const ethDigest = ethSignedDigest(inner);
        const sig = secp256k1.sign(ethDigest, this.privateKey);
        const r = pad(toHex(sig.r), { size: 32 });
        const s = pad(toHex(sig.s), { size: 32 });
        const recovery = typeof sig.recovery === "number" ? sig.recovery : 0;
        const v = (27 + recovery) & 0xff;
        const vHex = v.toString(16).padStart(2, "0");
        return {
            sig: `${r}${s.slice(2)}${vHex}`,
            innerDigest: inner,
        };
    }
}
