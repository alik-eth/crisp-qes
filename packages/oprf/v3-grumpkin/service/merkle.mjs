// Depth-20 Pedersen-Merkle store for the v3 Grumpkin enrollment registry
// (build, unaudited — does NOT touch the live v2 service).
//
// This is the v3 analogue of packages/oprf/src/merkle.ts, but standalone:
// instead of importing @crisp-qes/lotl-flattener it hashes nodes directly with
// @aztec/bb.js's `BarretenbergSync.pedersenHash` — the SAME primitive lib.mjs
// already uses for the DLEQ challenge + commitment, and the SAME one the Noir
// circuits' `std::hash::pedersen_hash` builtin computes. So the tree shape is
// byte-for-byte identical to the v2 EnrollmentRegistry and its circuit walker:
//
//     node      = pedersen_hash_with_separator([left, right], 0)   // Grumpkin
//     zero[0]   = 0
//     zero[i]   = pedersen_hash([zero[i-1], zero[i-1]], 0)
//     genesis   = zero[20]
//             = 0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84
//
// VERIFIED at module-load-equivalent time (see register-test.mjs): the depth-20
// all-zeros root computed here equals the canonical genesis above, so a v3 leaf
// appended to a fresh tree produces an `oldRoot == genesis` that the deployed
// EnrollmentRegistry (seeded with the same genesis) accepts.
//
// Persistence: IN-MEMORY only (demo). Commitments live in `this.leaves`; on a
// restart the tree is empty again. Production would persist the leaf array (it
// is the only state needed — the tree is a pure function of it) and rebuild on
// boot, exactly as v2's app.ts does from SQLite via `commitmentsToLeaves`.

import { BarretenbergSync } from "@aztec/bb.js";

export const TREE_DEPTH = 20;
export const MERKLE_NODE_DOMAIN = 0;

// Canonical depth-20 Pedersen zero-tree root the EnrollmentRegistry is seeded
// with. Asserted against the freshly-computed zeroHashes()[20] in init().
export const GENESIS_ROOT =
    0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84n;

let _bbSync = null;
async function bb() {
    if (!_bbSync) _bbSync = await BarretenbergSync.initSingleton();
    return _bbSync;
}

const FR_MAX = 1n << 254n;

function toBE32(v) {
    if (v < 0n) throw new Error("merkle: negative field element");
    if (v >= FR_MAX) throw new Error("merkle: field element exceeds Fr range");
    const o = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        o[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return o;
}

function beToBigInt(b) {
    let acc = 0n;
    for (let i = 0; i < b.length; i++) acc = (acc << 8n) | BigInt(b[i]);
    return acc;
}

/** node = pedersen_hash_with_separator([l, r], 0) on Grumpkin (via bb.js). */
async function hash2(l, r) {
    const api = await bb();
    const { hash } = api.pedersenHash({
        inputs: [toBE32(l), toBE32(r)],
        hashIndex: MERKLE_NODE_DOMAIN,
    });
    return beToBigInt(hash);
}

/** zero[0..depth] subtree roots. */
async function zeroHashes(depth) {
    const zeros = new Array(depth + 1);
    zeros[0] = 0n;
    for (let i = 1; i <= depth; i++) zeros[i] = await hash2(zeros[i - 1], zeros[i - 1]);
    return zeros;
}

export function bigintToHex32(v) {
    if (v < 0n) throw new Error("bigintToHex32: negative");
    const hex = v.toString(16);
    if (hex.length > 64) throw new Error("bigintToHex32: value exceeds 32 bytes");
    return `0x${hex.padStart(64, "0")}`;
}

/**
 * In-memory depth-20 Pedersen-Merkle index over enrolled commitments.
 *
 * Mirrors v2 MerkleIndex: build-from-leaves + append + proofAt, returning the
 * inclusion proof as (path[], indices[]) where indices[level] is 0 if the
 * current node is the LEFT child (sibling on the right) and 1 if it is the
 * RIGHT child — the convention the Noir Merkle recompute helper consumes.
 */
export class MerkleIndex {
    /** @private */
    constructor() {
        /** @type {bigint[]} */
        this.leaves = [];
        /** @type {bigint[]} */
        this._zeros = [];
        this.root = GENESIS_ROOT;
        // root(hex) -> leafCount, so we can serve a path against a HISTORICAL
        // root. An FHE round pins a snapshot root; voters must prove membership
        // against THAT snapshot (not the live tree, which may have grown), and
        // the broadcast forces enrollment_root == the pinned root. See
        // proofAtCount() / leafCountForRoot().
        /** @type {Map<string, number>} */
        this.rootHistory = new Map();
    }

    /** Build from an ordered array of leaves (one per enrolled commitment). */
    static async fromLeaves(leaves = []) {
        const idx = new MerkleIndex();
        idx._zeros = await zeroHashes(TREE_DEPTH);
        // Fail-closed self-check: our zero-tree root must equal the canonical
        // genesis the deployed registry was seeded with, else every attesterSig
        // we produce would be rejected on-chain.
        if (idx._zeros[TREE_DEPTH] !== GENESIS_ROOT) {
            throw new Error(
                "merkle: depth-20 zero-tree root != canonical genesis " +
                    `(got ${bigintToHex32(idx._zeros[TREE_DEPTH])})`,
            );
        }
        idx.leaves = leaves.slice();
        // Record root -> leafCount for every prefix so a historical root (an FHE
        // round snapshot) resolves to the leaf count it was taken at. genesis=0.
        idx.rootHistory.set(bigintToHex32(idx._zeros[TREE_DEPTH]), 0);
        for (let n = 1; n <= idx.leaves.length; n++) {
            const r = await idx._computeRoot(idx.leaves.slice(0, n));
            idx.rootHistory.set(bigintToHex32(r), n);
        }
        idx.root = await idx._computeRoot();
        return idx;
    }

    /** @private compute the root over `leaves` (defaults to this.leaves). */
    async _computeRoot(leaves = this.leaves) {
        if (leaves.length === 0) return this._zeros[TREE_DEPTH];
        let level = leaves.slice();
        for (let d = 0; d < TREE_DEPTH; d++) {
            const next = [];
            for (let i = 0; i < level.length; i += 2) {
                const left = level[i];
                const right = i + 1 < level.length ? level[i + 1] : this._zeros[d];
                next.push(await hash2(left, right));
            }
            level = next;
        }
        return level[0];
    }

    /** @private inclusion proof (path + indices) for a leaf index within `leaves`. */
    async _proof(leafIndex, leaves = this.leaves) {
        const path = new Array(TREE_DEPTH);
        const indices = new Array(TREE_DEPTH);
        let level = leaves.slice();
        let i = leafIndex;
        for (let d = 0; d < TREE_DEPTH; d++) {
            const isRight = i % 2 === 1;
            const sibIdx = isRight ? i - 1 : i + 1;
            const sibling = sibIdx < level.length ? level[sibIdx] : this._zeros[d];
            path[d] = sibling;
            indices[d] = isRight ? 1 : 0;
            // build the next level for the following iteration
            const next = [];
            for (let j = 0; j < level.length; j += 2) {
                const left = level[j];
                const right = j + 1 < level.length ? level[j + 1] : this._zeros[d];
                next.push(await hash2(left, right));
            }
            level = next;
            i = i >> 1;
        }
        return { path, indices };
    }

    /**
     * Append a leaf; return {leafIndex, oldRoot, newRoot, path, indices}. The
     * inclusion proof is for the newly-appended leaf in the NEW tree.
     */
    async append(leaf) {
        const oldRoot = this.root;
        const leafIndex = this.leaves.length;
        this.leaves.push(leaf);
        this.root = await this._computeRoot();
        this.rootHistory.set(bigintToHex32(this.root), this.leaves.length);
        const { path, indices } = await this._proof(leafIndex);
        return {
            leafIndex,
            oldRoot,
            newRoot: this.root,
            path,
            indices,
            leafCount: this.leaves.length,
        };
    }

    /** Inclusion proof for an already-enrolled leaf index. */
    async proofAt(leafIndex) {
        if (leafIndex < 0 || leafIndex >= this.leaves.length) {
            throw new RangeError(
                `leafIndex ${leafIndex} out of range [0, ${this.leaves.length})`,
            );
        }
        const { path, indices } = await this._proof(leafIndex);
        return { leafIndex, path, indices, root: this.root };
    }

    /** Leaf count a (hex) root was taken at, or undefined if unknown. */
    leafCountForRoot(rootHex) {
        return this.rootHistory.get(rootHex.toLowerCase());
    }

    /**
     * Inclusion proof for `leafIndex` against the tree of the FIRST `leafCount`
     * leaves (a historical snapshot). The returned root is that snapshot's root,
     * so the path verifies against an FHE round's PINNED root even if the live
     * tree has since grown. `leafIndex` must be < `leafCount`.
     */
    async proofAtCount(leafIndex, leafCount) {
        if (leafCount < 0 || leafCount > this.leaves.length) {
            throw new RangeError(`leafCount ${leafCount} out of range [0, ${this.leaves.length}]`);
        }
        if (leafIndex < 0 || leafIndex >= leafCount) {
            throw new RangeError(`leafIndex ${leafIndex} not in snapshot of ${leafCount} leaves`);
        }
        const prefix = this.leaves.slice(0, leafCount);
        const { path, indices } = await this._proof(leafIndex, prefix);
        const root = await this._computeRoot(prefix);
        return { leafIndex, path, indices, root, leafCount };
    }

    snapshot() {
        return { root: this.root, leafCount: this.leaves.length };
    }
}

/**
 * Recompute a root from a leaf, path and indices — the same walk the on-chain
 * circuit performs. Exported so tests can independently verify a returned
 * merklePath reproduces newRoot without trusting the producing tree.
 */
export async function rootFromPath(leaf, path, indices) {
    let node = leaf;
    for (let d = 0; d < path.length; d++) {
        const sibling = path[d];
        // indices[d] == 0 => node is LEFT child; 1 => node is RIGHT child.
        node = indices[d] === 1 ? await hash2(sibling, node) : await hash2(node, sibling);
    }
    return node;
}
