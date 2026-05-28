// Pedersen-Merkle membership walker.
//
// Mirrors `packages/lotl-flattener/src/tree/merkle.ts`:
//   node = pedersen_hash_with_separator([left, right], MERKLE_NODE_DOMAIN)
//
// `indices[i]` is the position of the *current* node at level `i`:
//   indices[i] = false -> current is the left child,  sibling is on the right
//   indices[i] = true  -> current is the right child, sibling is on the left
// This matches the JS `proveInclusion` output:
//   `indices[level] = isRight ? 1 : 0`.

use std::hash::pedersen_hash_with_separator;

pub global MERKLE_NODE_DOMAIN: u32 = 0;

/// Walk a Pedersen-Merkle path from `leaf` up `DEPTH` levels and return the
/// computed root.
pub fn compute_root<let DEPTH: u32>(
    leaf: Field,
    path: [Field; DEPTH],
    indices: [bool; DEPTH],
) -> Field {
    let mut cur = leaf;
    for i in 0..DEPTH {
        let sibling = path[i];
        let (left, right) = if indices[i] { (sibling, cur) } else { (cur, sibling) };
        cur = pedersen_hash_with_separator([left, right], MERKLE_NODE_DOMAIN);
    }
    cur
}
