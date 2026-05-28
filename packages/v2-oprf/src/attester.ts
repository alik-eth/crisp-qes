// secp256k1 root-update attester for EnrollmentRegistry.
//
// Digest format — matches the deployed contract on Base Sepolia 84532
// (EnrollmentRegistry 0x66573066…50aA, deployed by `circuit` in §31):
//
//   tag    = "CRISP_QES_OPRF_ROOT_V2.1"            // exactly 24 ASCII bytes
//   body   = abi.encodePacked(
//              bytes24(tag),                       // 24 bytes
//              bytes32(oldRoot),                   // 32
//              bytes32(newRoot),                   // 32
//              uint256(leafIndex)                  // 32
//            )
//   digest = keccak256(body)
//   sig    = secp256k1.sign(digest, attesterKey)   // 65 B: r||s||v ∈ {27,28}
//
// The contract recovers DIRECTLY from `digest` — there is NO EIP-191
// `"\x19Ethereum Signed Message:\n32"` wrap. The view function
// `EnrollmentRegistry.previewDigest(newRoot, leafIndex)` returns this
// digest off-chain for self-check; we use it in integration tests.
//
// Notes for v2.2 (mainnet hardening) — flagged by team-lead's later pin
// + circuit's deploy memo, deferred for the testnet demo:
//
//   * Add `block.chainid` and `address(this)` to the digest. Without
//     them, the SAME attester key signing on Sepolia produces signatures
//     that would replay against a mainnet registry that re-uses the
//     key. We're single-key single-chain on the testnet demo so this
//     doesn't bite, but it's the right shape for production.
//   * Wrap with EIP-191 `personal_sign` so viem's
//     `walletClient.signMessage({ message: { raw } })` produces the
//     identical signature client-side. Today we keep raw-ecrecover for
//     symmetry with the contract.
//
// Both items are 2-line changes either side and intentionally NOT done
// here — the contract is the immutable source of truth.

import { secp256k1 } from "@noble/curves/secp256k1";
import {
    type Hex,
    bytesToHex,
    encodePacked,
    hexToBytes,
    keccak256,
    pad,
    toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

/** 24-byte ASCII tag — must match the contract's bytes24 literal. */
export const ROOT_TAG = new TextEncoder().encode("CRISP_QES_OPRF_ROOT_V2.1");
if (ROOT_TAG.length !== 24) {
    throw new Error("ROOT_TAG must be exactly 24 bytes");
}

export interface RootUpdate {
    oldRoot: bigint;
    newRoot: bigint;
    leafIndex: number;
}

function bigintToHex32(v: bigint): `0x${string}` {
    if (v < 0n) throw new Error("bigintToHex32: negative");
    const hex = v.toString(16).padStart(64, "0");
    if (hex.length > 64) throw new Error("bigintToHex32: value exceeds 32 bytes");
    return `0x${hex}` as `0x${string}`;
}

/**
 * Reconstruct the 32-byte digest the contract's `ecrecover` will see.
 *
 * Implemented with viem's `encodePacked` so the byte layout matches
 * `abi.encodePacked(bytes24, bytes32, bytes32, uint256)` exactly — we
 * sanity-test this against the contract's `previewDigest` view in the
 * integration step.
 */
export function rootUpdateDigest(u: RootUpdate): Uint8Array {
    const packed = encodePacked(
        ["bytes24", "bytes32", "bytes32", "uint256"],
        [
            bytesToHex(ROOT_TAG) as `0x${string}`,
            bigintToHex32(u.oldRoot),
            bigintToHex32(u.newRoot),
            BigInt(u.leafIndex),
        ],
    );
    return hexToBytes(keccak256(packed));
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
     * Produce the 65-byte recoverable signature
     * `r (32) || s (32) || v (1 ∈ {27, 28})` the contract expects.
     *
     * Returns the inner digest alongside so the client can submit it to
     * the registry without recomputing.
     */
    sign(u: RootUpdate): { sig: `0x${string}`; digest: `0x${string}` } {
        const d = rootUpdateDigest(u);
        // @noble/curves returns low-s by default (EIP-2 compliant).
        const sig = secp256k1.sign(d, this.privateKey);
        const r = pad(toHex(sig.r), { size: 32 });
        const s = pad(toHex(sig.s), { size: 32 });
        const recovery =
            typeof sig.recovery === "number" ? sig.recovery : 0;
        const v = (27 + recovery) & 0xff;
        const vHex = v.toString(16).padStart(2, "0");
        return {
            sig: `${r}${s.slice(2)}${vHex}` as `0x${string}`,
            digest: bytesToHex(d) as `0x${string}`,
        };
    }
}

export { keccak256 };
