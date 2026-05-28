// Verifies the attester's EIP-191-wrapped secp256k1 signature recovers
// the attester's own Ethereum address — i.e. EnrollmentRegistry.updateRoot's
// `ecrecover` will succeed against the address pinned at deploy time.
//
// We use viem's `verifyMessage({ raw, signature, address })` which mirrors
// the EIP-191 personal_sign verification path inside OpenZeppelin's
// `ECDSA.recover`. If this passes, the contract path passes too.

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { bytesToHex, recoverMessageAddress } from "viem";

import { Attester, innerDigest, hashCommitmentList } from "../src/attester.js";

const REGISTRY = "0x1234567890abcdef1234567890abcdef12345678" as const;
const CHAIN_ID = 84532;

function fakeRoot(): bigint {
    return BigInt(bytesToHex(randomBytes(32)));
}

describe("Attester EIP-191 signature", () => {
    it("recovers the attester address via viem.verifyMessage", async () => {
        const key = bytesToHex(randomBytes(32)) as `0x${string}`;
        const a = new Attester(key);

        const update = {
            oldRoot: 0n,
            newRoot: fakeRoot(),
            newCommitments: [fakeRoot()],
            chainId: CHAIN_ID,
            enrollmentRegistry: REGISTRY,
        };

        const { sig, innerDigest: inner } = a.sign(update);
        expect(inner).toBe(innerDigest(update));

        const recovered = await recoverMessageAddress({
            message: { raw: inner },
            signature: sig,
        });
        expect(recovered.toLowerCase()).toBe(a.address.toLowerCase());
    });

    it("changing the commitment list invalidates the recovered address", async () => {
        const key = bytesToHex(randomBytes(32)) as `0x${string}`;
        const a = new Attester(key);

        const c1 = fakeRoot();
        const c2 = fakeRoot();
        const { sig } = a.sign({
            oldRoot: 0n,
            newRoot: fakeRoot(),
            newCommitments: [c1],
            chainId: CHAIN_ID,
            enrollmentRegistry: REGISTRY,
        });

        // Recover against a digest computed over a *different* commitment
        // list — must yield a different address.
        const otherInner = innerDigest({
            oldRoot: 0n,
            newRoot: fakeRoot(), // also different
            newCommitments: [c2],
            chainId: CHAIN_ID,
            enrollmentRegistry: REGISTRY,
        });
        const recovered = await recoverMessageAddress({
            message: { raw: otherInner },
            signature: sig,
        });
        expect(recovered.toLowerCase()).not.toBe(a.address.toLowerCase());
    });

    it("hashCommitmentList is order-sensitive", () => {
        const a = 0x1111n;
        const b = 0x2222n;
        expect(hashCommitmentList([a, b])).not.toBe(hashCommitmentList([b, a]));
    });
});
