// Incremental Pedersen-Merkle tree mirroring the v2 EnrollmentRegistry.
//
// We use `@crisp-qes/lotl-flattener`'s `buildTree` / `proveInclusion` /
// `zeroHashes` so the byte-for-byte tree shape matches the v2 circuit's
// `compute_root` walker (`packages/circuit/src/merkle.nr`):
//
//     node = pedersen_hash([left, right], MERKLE_NODE_DOMAIN = 0)
//
// TREE_DEPTH = 20 — pinned by v2 circuit; supports 2^20 ≈ 10⁶ enrollments,
// which is two orders of magnitude past the demo size and exactly the
// spec's "1 M citizens" target.

import {
    buildTree,
    proveInclusion,
    zeroHashes,
} from "@crisp-qes/lotl-flattener";

// `InclusionProof` is internal to lotl-flattener; mirror its shape so we
// don't have to re-export it from there.
interface InclusionProof {
    path: bigint[];
    indices: number[];
}

export const TREE_DEPTH = 20;

export interface MerkleSnapshot {
    root: bigint;
    leafCount: number;
}

export interface AppendResult extends MerkleSnapshot {
    leafIndex: number;
    oldRoot: bigint;
    newRoot: bigint;
    /** Inclusion proof of the newly-appended leaf in the *new* tree. */
    path: bigint[];
    indices: (0 | 1)[];
}

export interface InclusionResult {
    leafIndex: number;
    path: bigint[];
    indices: (0 | 1)[];
    root: bigint;
}

/**
 * In-memory Pedersen-Merkle index over the enrolled-commitment list.
 *
 * The store is initialised from the SQLite-persisted commitment array on
 * boot (cheap: a 1 M-leaf tree builds in well under a second on a modest
 * VM, and the demo stays at tens of leaves). For v2.1-prod we'll switch to
 * an incremental subtree-cache to avoid rebuilding the whole layers array
 * on every append; for the demo we just rebuild — readability over perf.
 */
export class MerkleIndex {
    private layers: bigint[][] = [];
    private root: bigint = 0n;
    private leafCount = 0;

    private constructor() {}

    /** Build from an ordered array of leaves (one per enrolled commitment). */
    static async fromLeaves(leaves: bigint[]): Promise<MerkleIndex> {
        const idx = new MerkleIndex();
        await idx.rebuild(leaves);
        return idx;
    }

    private async rebuild(leaves: bigint[]): Promise<void> {
        const built = await buildTree(leaves, TREE_DEPTH);
        this.layers = built.layers;
        this.root = built.root;
        this.leafCount = leaves.length;
        // `buildTree` initialises an empty `layers[0]` for empty inputs;
        // canonicalise to the all-zeros root in that case so callers see
        // the same hash as a freshly-deployed registry.
        if (leaves.length === 0) {
            const zeros = await zeroHashes(TREE_DEPTH);
            this.root = zeros[TREE_DEPTH] ?? 0n;
        }
    }

    /**
     * Append a new leaf and return:
     *   - the leaf's index,
     *   - the old root (pre-append),
     *   - the new root (post-append),
     *   - the inclusion proof of the new leaf in the new tree.
     */
    async append(leaf: bigint): Promise<AppendResult> {
        const oldRoot = this.root;
        // Recompute layers with the new leaf appended. The current
        // `buildTree` mutates nothing of ours, so this is safe.
        const allLeaves = (this.layers[0] ?? []).slice();
        allLeaves.push(leaf);
        await this.rebuild(allLeaves);

        const leafIndex = this.leafCount - 1;
        const { path, indices }: InclusionProof = await proveInclusion(
            this.layers,
            leafIndex,
        );
        return {
            leafIndex,
            oldRoot,
            newRoot: this.root,
            root: this.root,
            leafCount: this.leafCount,
            path,
            indices: indices.map((i) => (i === 1 ? 1 : 0)),
        };
    }

    /** Inclusion proof for an already-enrolled commitment. */
    async proofAt(leafIndex: number): Promise<InclusionResult> {
        if (leafIndex < 0 || leafIndex >= this.leafCount) {
            throw new RangeError(
                `leafIndex ${leafIndex} out of range [0, ${this.leafCount})`,
            );
        }
        const { path, indices } = await proveInclusion(this.layers, leafIndex);
        return {
            leafIndex,
            path,
            indices: indices.map((i) => (i === 1 ? 1 : 0)),
            root: this.root,
        };
    }

    snapshot(): MerkleSnapshot {
        return { root: this.root, leafCount: this.leafCount };
    }
}
