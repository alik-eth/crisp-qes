// Pedersen-on-BN254 primitive wrapper.
//
// Per CRISP-QES spec sec 3, the trust-root commitment family is Pedersen on
// BN254 (Grumpkin Pedersen, the same construction exposed by Noir's
// std::hash::pedersen_hash). We pin to @aztec/bb.js for the wasm impl so the
// flattener, the SDK witness builder, and the Noir circuit all agree on the
// same field arithmetic byte-for-byte.
//
// API used (verified in node_modules/@aztec/bb.js@4.0.0-nightly.*):
//   BarretenbergSync.initSingleton() / .getSingleton()
//   sync.pedersenHash({ inputs: Uint8Array[], hashIndex }): { hash: Uint8Array }
//   sync.pedersenHashBuffer({ input: Uint8Array, hashIndex }): { hash: Uint8Array }
//
// Field elements are encoded as 32-byte big-endian Uint8Arrays at the bb.js
// boundary. `Fr` is no longer exported from the package root in 4.x; raw
// buffers are the canonical production representation.

import { BarretenbergSync } from "@aztec/bb.js";

let initP: Promise<BarretenbergSync> | null = null;

async function getApi(): Promise<BarretenbergSync> {
  if (initP === null) {
    initP = BarretenbergSync.initSingleton();
  }
  return initP;
}

// Safe upper bound for inputs. The BN254 scalar prime is < 2^254, so any
// non-negative bigint that fits in 254 bits is a valid Field element.
const FR_MAX = 1n << 254n;

function bigintToBE32(v: bigint): Uint8Array {
  if (v < 0n) throw new Error("pedersen: negative field elements unsupported");
  if (v >= FR_MAX) throw new Error("pedersen: input exceeds Fr range");
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function bytesBEToBigInt(b: Uint8Array): bigint {
  let acc = 0n;
  for (let i = 0; i < b.length; i++) acc = (acc << 8n) | BigInt(b[i]!);
  return acc;
}

/**
 * Pedersen hash of a sequence of field elements on BN254.
 * Domain separation is delegated to `hashIndex` (matching the Noir builtin
 * `std::hash::pedersen_hash_with_separator`).
 */
export async function pedersenHashFields(
  inputs: readonly bigint[],
  hashIndex = 0,
): Promise<bigint> {
  const api = await getApi();
  const buffers = inputs.map(bigintToBE32);
  const { hash } = api.pedersenHash({ inputs: buffers, hashIndex });
  return bytesBEToBigInt(hash);
}

/**
 * Pedersen hash of an arbitrary byte buffer. Backed by bb.js
 * `pedersen_hash_buffer`, which internally chunks bytes into BN254 field
 * elements using barretenberg's canonical packing. We use this for the
 * per-CA SPKI commitment so consumers don't need to re-implement chunking.
 */
export async function pedersenHashBuffer(
  input: Uint8Array,
  hashIndex = 0,
): Promise<bigint> {
  const api = await getApi();
  const { hash } = api.pedersenHashBuffer({ input, hashIndex });
  return bytesBEToBigInt(hash);
}
