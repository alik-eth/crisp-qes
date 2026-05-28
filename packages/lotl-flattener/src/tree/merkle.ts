// Binary Pedersen Merkle tree on BN254.
//
// The on-chain `PetitionRegistry.trustRoot` is a Pedersen-Merkle commitment
// over the Diia trusted CA list (CRISP-QES spec §2.1). The Noir circuit
// proves Merkle membership of a citizen's leaf-cert SPKI commitment by
// recomputing the path using the same hash. Construction:
//
//   node = pedersenHash([left, right], MERKLE_NODE_DOMAIN)
//   zero[0] = 0
//   zero[i] = pedersenHash([zero[i-1], zero[i-1]], MERKLE_NODE_DOMAIN)
//
// Leaves shorter than 2^depth are padded with the zero subtree at each level.

import { pedersenHashFields } from "../ca/pedersen.js";

export const MERKLE_NODE_DOMAIN = 0;

async function hash2(l: bigint, r: bigint): Promise<bigint> {
  return pedersenHashFields([l, r], MERKLE_NODE_DOMAIN);
}

export async function zeroHashes(depth: number): Promise<bigint[]> {
  const zeros: bigint[] = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) {
    zeros[i] = await hash2(zeros[i - 1]!, zeros[i - 1]!);
  }
  return zeros;
}

export interface BuiltTree {
  root: bigint;
  layers: bigint[][];
}

export async function buildTree(leaves: bigint[], depth: number): Promise<BuiltTree> {
  if (depth < 0 || !Number.isInteger(depth)) {
    throw new Error("depth must be a non-negative integer");
  }
  const capacity = 2 ** depth;
  if (leaves.length > capacity) {
    throw new Error(
      `leaf count ${leaves.length} exceeds tree capacity ${capacity} for depth ${depth}`,
    );
  }
  const zeros = await zeroHashes(depth);
  const layers: bigint[][] = new Array(depth + 1);
  layers[0] = leaves.slice();

  for (let level = 0; level < depth; level++) {
    const cur = layers[level]!;
    const nextLen = Math.ceil(cur.length / 2);
    const next: bigint[] = new Array(nextLen);
    for (let i = 0; i < nextLen; i++) {
      const left = cur[2 * i] ?? zeros[level]!;
      const right = cur[2 * i + 1] ?? zeros[level]!;
      next[i] = await hash2(left, right);
    }
    layers[level + 1] = next;
  }

  const top = layers[depth]!;
  const root = top.length === 1 ? top[0]! : zeros[depth]!;
  return { root, layers };
}

export interface InclusionProof {
  path: bigint[];
  indices: number[];
}

export async function proveInclusion(
  layers: bigint[][],
  index: number,
): Promise<InclusionProof> {
  const depth = layers.length - 1;
  if (depth < 0) throw new Error("layers must contain at least the leaf level");
  if (!Number.isInteger(index) || index < 0) {
    throw new Error("index must be a non-negative integer");
  }
  const zeros = await zeroHashes(depth);
  const path: bigint[] = new Array(depth);
  const indices: number[] = new Array(depth);
  let i = index;
  for (let level = 0; level < depth; level++) {
    const layer = layers[level]!;
    const isRight = i % 2 === 1;
    const siblingIdx = isRight ? i - 1 : i + 1;
    const sibling = layer[siblingIdx];
    path[level] = sibling ?? zeros[level]!;
    // 0 = current node is left (sibling on right); 1 = current is right
    // (sibling on left). This matches the convention the Noir Merkle
    // recompute helper consumes.
    indices[level] = isRight ? 1 : 0;
    i = i >> 1;
  }
  return { path, indices };
}
