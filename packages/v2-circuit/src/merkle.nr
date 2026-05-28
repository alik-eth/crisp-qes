// Pedersen-Merkle membership walker for v2 enrollment trees.
//
// Mirrors the MVP `packages/circuit/src/merkle.nr` exactly so that the
// v2 enrollment tree and the v1 trust tree share the same node-hash
// construction:
//
//   node = pedersen_hash_with_separator([left, right], MERKLE_NODE_DOMAIN)
//
// `indices[i]` is the position of the current node at level `i`:
//   indices[i] = 0 -> current is the left child,  sibling is on the right
//   indices[i] = 1 -> current is the right child, sibling is on the left
// This matches the JS `proveInclusion` output:
//   `indices[level] = isRight ? 1 : 0`.

use std::hash::pedersen_hash_with_separator;

pub global MERKLE_NODE_DOMAIN: u32 = 0;

/// Walk a Pedersen-Merkle path from `leaf` up `DEPTH` levels and return the
/// computed root. Indices are u1 (0/1) to match the public-facing wire
/// format the v2 SDK + flattener emit; we cast to bool internally so the
/// branch lowers cleanly.
pub fn compute_root<let DEPTH: u32>(
    leaf: Field,
    path: [Field; DEPTH],
    indices: [u1; DEPTH],
) -> Field {
    let mut cur = leaf;
    for i in 0..DEPTH {
        let sibling = path[i];
        // Compare-with-zero instead of cast: nargo beta.16 rejects
        // `u1 as bool`.
        let is_right = indices[i] != 0;
        let (left, right) = if is_right { (sibling, cur) } else { (cur, sibling) };
        cur = pedersen_hash_with_separator([left, right], MERKLE_NODE_DOMAIN);
    }
    cur
}
