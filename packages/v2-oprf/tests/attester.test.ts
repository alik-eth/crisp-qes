// Verifies the attester's raw-ecrecover signature recovers the attester's
// Ethereum address — i.e. EnrollmentRegistry's `ecrecover(digest, v, r, s)`
// succeeds against the deployed-address pin.
//
// We use viem's `recoverAddress({ hash, signature })`, which is the JS
// equivalent of Solidity's raw `ecrecover` — NO EIP-191 wrapping. If this
// passes here, the contract path passes too.

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { bytesToHex, recoverAddress } from "viem";

import {
    Attester,
    ROOT_TAG,
    rootUpdateDigest,
} from "../src/attester.js";

function fakeRoot(): bigint {
    return BigInt(bytesToHex(randomBytes(32)));
}

describe("Attester raw-digest signature (bytes24 DOMAIN scheme)", () => {
    it("ROOT_TAG is exactly 24 bytes and matches the spec", () => {
        expect(ROOT_TAG.length).toBe(24);
        expect(new TextDecoder().decode(ROOT_TAG)).toBe(
            "CRISP_QES_OPRF_ROOT_V2.1",
        );
    });

    it("recovers the attester address via viem.recoverAddress (raw ecrecover)", async () => {
        const key = bytesToHex(randomBytes(32));
        const a = new Attester(key);

        const update = {
            oldRoot: 0n,
            newRoot: fakeRoot(),
            leafIndex: 0,
        };

        const { sig, digest } = a.sign(update);
        // Sanity: the digest the attester returns must equal what an
        // independent reconstruction produces (matches contract's
        // previewDigest view).
        expect(digest).toBe(bytesToHex(rootUpdateDigest(update)));

        const recovered = await recoverAddress({
            hash: digest,
            signature: sig,
        });
        expect(recovered.toLowerCase()).toBe(a.address.toLowerCase());
    });

    it("changing leafIndex invalidates the recovered address", async () => {
        const key = bytesToHex(randomBytes(32));
        const a = new Attester(key);
        const newRoot = fakeRoot();
        const { sig } = a.sign({ oldRoot: 0n, newRoot, leafIndex: 0 });

        // Recover against a digest for a different leafIndex — must yield
        // a different address.
        const wrongDigest = bytesToHex(
            rootUpdateDigest({ oldRoot: 0n, newRoot, leafIndex: 1 }),
        );
        const recovered = await recoverAddress({
            hash: wrongDigest,
            signature: sig,
        });
        expect(recovered.toLowerCase()).not.toBe(a.address.toLowerCase());
    });
});
