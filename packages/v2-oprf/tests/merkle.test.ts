// Pedersen-Merkle index correctness.
//
// We don't reimplement the Pedersen primitive here; we verify that the
// path returned by `MerkleIndex.append` recomputes to the new root using
// the same `pedersenHashFields` the index uses internally — i.e. that
// the server's path is what the circuit will accept.

import { describe, expect, it } from "vitest";
import { MerkleIndex, TREE_DEPTH } from "../src/merkle.js";
import { pedersenHashFields } from "../src/pedersen.js";

async function walk(
    leaf: bigint,
    path: bigint[],
    indices: (0 | 1)[],
): Promise<bigint> {
    let cur = leaf;
    for (let i = 0; i < path.length; i++) {
        const sibling = path[i]!;
        const isRight = indices[i] === 1;
        const [l, r] = isRight ? [sibling, cur] : [cur, sibling];
        cur = await pedersenHashFields([l, r], 0);
    }
    return cur;
}

describe("MerkleIndex", () => {
    it("empty tree has the canonical zero root", async () => {
        const idx = await MerkleIndex.fromLeaves([]);
        const snap = idx.snapshot();
        expect(snap.leafCount).toBe(0);
        // Non-zero, since the zero-subtree at depth D is the iterated
        // pedersen of zero.
        expect(snap.root).not.toBe(0n);
    });

    it("appended path recomputes to the new root", async () => {
        const idx = await MerkleIndex.fromLeaves([]);
        const leaf =
            0x000000000000000000000000000000000000000000000000000000000000c0deen;
        const out = await idx.append(leaf);

        expect(out.leafIndex).toBe(0);
        expect(out.path.length).toBe(TREE_DEPTH);
        expect(out.indices.length).toBe(TREE_DEPTH);

        const recomputed = await walk(leaf, out.path, out.indices);
        expect(recomputed).toBe(out.newRoot);
    });

    it("subsequent appends keep both paths valid", async () => {
        const idx = await MerkleIndex.fromLeaves([]);
        const a = 0x1111n;
        const b = 0x2222n;

        const r1 = await idx.append(a);
        const r2 = await idx.append(b);

        // Second leaf's claim against the new root.
        const checkB = await walk(b, r2.path, r2.indices);
        expect(checkB).toBe(r2.newRoot);

        // First leaf's path against the *new* root, via proofAt.
        const p1 = await idx.proofAt(0);
        const checkA = await walk(a, p1.path, p1.indices);
        expect(checkA).toBe(r2.newRoot);

        expect(r1.newRoot).not.toBe(r2.newRoot);
    });
});
