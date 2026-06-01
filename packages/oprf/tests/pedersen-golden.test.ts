// Pedersen golden-vector cross-version pin (adversarial review FIX-B #8).
//
// PROBLEM: the off-chain hashers (this package + packages/web) run @aztec/bb.js
// 4.x, while the proving circuit + SDK run bb.js 3.0.0-nightly.20260102. If the
// two bb.js majors ever disagreed on the Pedersen-on-BN254 construction, the
// off-chain `s` / `nullifier` / Merkle root would silently diverge from what the
// circuit computes — every vote would fail verification with no compile error.
//
// FIX: pin the three off-chain Pedersen products to KNOWN-GOOD values that were
// generated with the *circuit's* bb.js (3.0.0-nightly.20260102) — see
// scripts/crisp-fhe/gen-pedersen-golden.mjs for the generator. Running this test
// (under the off-chain 4.x bb.js this package depends on) asserts that 4.x
// reproduces the 3.x values byte-for-byte. As of 2026-06-01 they AGREE; this
// test pins that agreement forever, so a future bb.js bump that changes the
// construction fails loudly here instead of in production.
//
// The three products mirror exactly what the v2.1 circuit computes
// (crisp_qes/src/{main,merkle}.nr):
//   s         = pedersen_hash([N_hi, N_lo], 0)
//   nullifier = pedersen_hash([s, petition_id, DOMAIN_PETITION_V2], 0)
//   node      = pedersen_hash_with_separator([left, right], MERKLE_NODE_DOMAIN=0)

import { describe, expect, it } from "vitest";
import { pedersenHashFields, splitOprfOutput } from "../src/pedersen.js";

// ASCII "v2-pen-no1" packed into a Field — matches DOMAIN_PETITION_V2 in
// crisp_qes/src/main.nr and packages/web/src/lib/pedersen.ts.
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;

const hx = (v: bigint): string => `0x${v.toString(16).padStart(64, "0")}`;

// ---------------------------------------------------------------------------
// Fixed inputs. N is a deterministic 32-byte buffer (NOT random) so the golden
// values are reproducible. Do NOT change these without regenerating the goldens
// with scripts/crisp-fhe/gen-pedersen-golden.mjs (which uses the circuit's bb.js).
// ---------------------------------------------------------------------------
const N = new Uint8Array(32);
for (let i = 0; i < 32; i++) N[i] = (i * 7 + 3) & 0xff;

const PETITION_ID = 42n;

// Merkle: depth-2 tree, leaves [0x1111, 0x2222, 0x3333, 0] (4th slot zero-pad).
const MERKLE_LEAVES = [0x1111n, 0x2222n, 0x3333n, 0n] as const;

// ---------------------------------------------------------------------------
// GOLDEN VALUES — generated with @aztec/bb.js 3.0.0-nightly.20260102 (the
// circuit + SDK bb.js). The off-chain 4.x bb.js MUST reproduce these.
// ---------------------------------------------------------------------------
const GOLDEN = {
    N_hi: "0x00000000000000000000000000000000030a11181f262d343b424950575e656c",
    N_lo: "0x00000000000000000000000000000000737a81888f969da4abb2b9c0c7ced5dc",
    s: "0x1694e19447e654f7f1dad7374aae5494b3e574037d5b5f6cbc23cf6b345589d4",
    nullifier:
        "0x1d475823e20b4f757d9394ff10c652843337d6c9f8cc204dcdb085d09841cf4d",
    merkleNode_1111_2222:
        "0x2f984d1814a491e799265b0b1f14a3a0284c036691cb29a022fde3e2ec031754",
    merkleRoot:
        "0x2105ea4699272f9c16ee714be851d35a361829452260220edd3347dd95ad0dd0",
} as const;

describe("pedersen golden vectors (off-chain 4.x vs circuit 3.x)", () => {
    it("splitOprfOutput limbs match the circuit's N_hi / N_lo", () => {
        const { hi, lo } = splitOprfOutput(N);
        expect(hx(hi)).toBe(GOLDEN.N_hi);
        expect(hx(lo)).toBe(GOLDEN.N_lo);
    });

    it("s = pedersen([N_hi, N_lo], 0) matches the circuit", async () => {
        const { hi, lo } = splitOprfOutput(N);
        const s = await pedersenHashFields([hi, lo], 0);
        expect(hx(s)).toBe(GOLDEN.s);
    });

    it("nullifier = pedersen([s, petition_id, DOMAIN], 0) matches the circuit", async () => {
        const s = BigInt(GOLDEN.s);
        const nullifier = await pedersenHashFields(
            [s, PETITION_ID, DOMAIN_PETITION_V2],
            0,
        );
        expect(hx(nullifier)).toBe(GOLDEN.nullifier);
    });

    it("Merkle node = pedersen([l, r], 0) matches the circuit", async () => {
        const node = await pedersenHashFields([0x1111n, 0x2222n], 0);
        expect(hx(node)).toBe(GOLDEN.merkleNode_1111_2222);
    });

    it("depth-2 Merkle root matches the circuit", async () => {
        const [a, b, c, d] = MERKLE_LEAVES;
        const l01 = await pedersenHashFields([a, b], 0);
        const l23 = await pedersenHashFields([c, d], 0);
        const root = await pedersenHashFields([l01, l23], 0);
        expect(hx(root)).toBe(GOLDEN.merkleRoot);
    });
});
