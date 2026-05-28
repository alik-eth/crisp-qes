// Pedersen-on-BN254 primitive wrapper.
//
// Per CRISP-QES spec §3, the trust-root commitment family is Pedersen on
// BN254 (Grumpkin Pedersen, the same construction exposed by Noir's
// std::hash::pedersen_hash). We pin to @aztec/bb.js for the wasm impl so the
// flattener, the SDK witness builder, and the Noir circuit all agree on the
// same field arithmetic byte-for-byte.
//
// API used (verified in node_modules/@aztec/bb.js@1.2.x):
//   BarretenbergSync.initSingleton() / .getSingleton()
//   sync.pedersenHash(inputs: Fr[], hashIndex: number): Fr
//   sync.pedersenHashBuffer(input: Uint8Array, hashIndex: number): Fr
//   Fr from '@aztec/bb.js' — bigint-or-buffer wrapper with .toBuffer()/toString()

import { BarretenbergSync, Fr } from "@aztec/bb.js";

let initP: Promise<BarretenbergSync> | null = null;

async function getApi(): Promise<BarretenbergSync> {
  if (initP === null) {
    initP = BarretenbergSync.initSingleton();
  }
  return initP;
}

const FR_MAX = (1n << 254n); // safe upper bound — BN254 modulus is < 2^254

function frToBigInt(fr: Fr): bigint {
  // Fr.toString() returns 0x-prefixed hex per bb.js convention.
  const s = fr.toString();
  return BigInt(s);
}

function bigintToFr(v: bigint): Fr {
  if (v < 0n) throw new Error("pedersen: negative field elements unsupported");
  if (v >= FR_MAX) throw new Error("pedersen: input exceeds Fr range");
  return new Fr(v);
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
  const frs = inputs.map(bigintToFr);
  const out = api.pedersenHash(frs, hashIndex);
  return frToBigInt(out);
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
  const out = api.pedersenHashBuffer(input, hashIndex);
  return frToBigInt(out);
}
