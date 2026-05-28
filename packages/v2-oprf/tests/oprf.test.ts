// OPRF math correctness: client-server round trip + DLEQ verification.
//
// We replay RFC 9497 §3.3.3 client-side `Blind` / `Finalize` using helpers
// exported from `src/oprf.ts`. The contract under test is that a client
// who blinds X = H(input), receives Y = k*M with a DLEQ proof, can:
//   1) verify the proof under the server's K_pub;
//   2) unblind to get N = k*X;
//   3) get the same N as the deterministic, single-key F_k(input).

import { describe, expect, it } from "vitest";

import {
    blind,
    blindEvaluate,
    derivePublicKey,
    hashToGroup,
    randomScalar,
    ristretto255,
    unblind,
    verifyProof,
} from "../src/oprf.js";

const FN = ristretto255.Point.Fn;

describe("OPRF over ristretto255-SHA512 (RFC 9497)", () => {
    it("BlindEvaluate + DLEQ proof verifies", () => {
        const k = randomScalar();
        const Kpub = derivePublicKey(k);
        const input = new TextEncoder().encode("TINUA-3627506575");
        const { r, M } = blind(input);

        const { Y, proof } = blindEvaluate(M, k, Kpub);
        expect(verifyProof(Kpub, M, Y, proof)).toBe(true);

        // Unblind and compare to a direct F_k(input) computation.
        const N = unblind(r, Y);
        const X = hashToGroup(input);
        const Nref = X.multiply(k).toBytes();
        expect(Buffer.from(N).toString("hex")).toEqual(
            Buffer.from(Nref).toString("hex"),
        );
    });

    it("DLEQ proof rejects a tampered Y", () => {
        const k = randomScalar();
        const Kpub = derivePublicKey(k);
        const { M } = blind(new TextEncoder().encode("attacker-input"));
        const { Y, proof } = blindEvaluate(M, k, Kpub);

        // Flip a single bit in Y — must invalidate the proof.
        const tampered = new Uint8Array(Y);
        tampered[0] ^= 0x01;
        expect(verifyProof(Kpub, M, tampered, proof)).toBe(false);
    });

    it("DLEQ proof rejects a wrong public key", () => {
        const k = randomScalar();
        const wrongKpub = derivePublicKey(FN.add(k, 1n));
        const { M } = blind(new TextEncoder().encode("input-2"));
        const { Y, proof } = blindEvaluate(M, k, derivePublicKey(k));
        expect(verifyProof(wrongKpub, M, Y, proof)).toBe(false);
    });

    it("F_k is deterministic across blindings", () => {
        // Two independent blindings of the same input must unblind to the
        // same N — this is the property that makes the on-chain commitment
        // collide on duplicate enrollments (Sybil resistance).
        const k = randomScalar();
        const Kpub = derivePublicKey(k);
        const input = new TextEncoder().encode("RNOKPP=12345");

        const b1 = blind(input);
        const b2 = blind(input);
        const e1 = blindEvaluate(b1.M, k, Kpub);
        const e2 = blindEvaluate(b2.M, k, Kpub);
        const N1 = unblind(b1.r, e1.Y);
        const N2 = unblind(b2.r, e2.Y);
        expect(Buffer.from(N1).toString("hex")).toEqual(
            Buffer.from(N2).toString("hex"),
        );
    });

    it("F_k(input1) != F_k(input2) for distinct inputs", () => {
        const k = randomScalar();
        const Kpub = derivePublicKey(k);
        const e1 = (() => {
            const { r, M } = blind(new TextEncoder().encode("a"));
            return unblind(r, blindEvaluate(M, k, Kpub).Y);
        })();
        const e2 = (() => {
            const { r, M } = blind(new TextEncoder().encode("b"));
            return unblind(r, blindEvaluate(M, k, Kpub).Y);
        })();
        expect(Buffer.from(e1).toString("hex")).not.toEqual(
            Buffer.from(e2).toString("hex"),
        );
    });
});
