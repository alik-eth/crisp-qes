// SPKI commitment — the per-CA Merkle leaf for the CRISP-QES trust root.
//
// Construction (frozen for this MVP, must agree byte-for-byte with the Noir
// circuit's in-circuit SPKI commit at `packages/circuit/src/spki.nr`):
//
//   1. Zero-pad the SPKI DER to exactly SPKI_MAX_BYTES (1024) bytes.
//   2. Split the padded buffer into SPKI_NUM_CHUNKS = 34 chunks:
//        - SPKI_FULL_CHUNKS = 33 chunks of SPKI_CHUNK_BYTES = 31 contiguous bytes
//        - 1 trailing chunk consisting of the single byte at index 1023
//      (33 * 31 + 1 = 1024).
//   3. Big-endian-pack each chunk into a BN254 field element. The trailing
//      chunk is just the raw byte value at offset 1023.
//   4. spkiCommit = pedersenHash(fields, hashIndex = SPKI_COMMIT_DOMAIN = 1)
//      where `pedersenHash` is bb.js's *Field-array* Pedersen hash (the same
//      construction Noir exposes via `std::hash::pedersen_hash_with_separator`).
//
// Why not `pedersenHashBuffer`? Noir's stdlib has no `pedersen_hash_buffer`
// in beta — only the Field-array variant. bb.js's `pedersen_hash_buffer`
// uses an opaque internal chunking that does NOT match what the circuit can
// constrain in Noir. The circuit pins the chunking above (see
// `packages/circuit/src/spki.nr`); this file mirrors it on the TS side.
//
// If you touch any of {SPKI_MAX_BYTES, SPKI_NUM_CHUNKS, SPKI_FULL_CHUNKS,
// SPKI_CHUNK_BYTES, SPKI_COMMIT_DOMAIN, big-endian packing}, you MUST update
// `packages/circuit/src/spki.nr` in lock-step and regenerate the verifier.
// Drift = the circuit silently rejects every valid signer.

import { pedersenHashFields } from "./pedersen.js";

export const SPKI_COMMIT_DOMAIN = 1;

/**
 * Soft upper bound on SPKI size. RSA-4096 SPKI ~ 550 bytes; we leave headroom
 * up to ~RSA-8192 for future-proofing. The flattener errors out beyond this
 * so an unexpected algorithm/key size is caught at trust-list build time
 * rather than at circuit witness time. Must match `SPKI_MAX_BYTES` in
 * `packages/circuit/src/spki.nr`.
 */
export const MAX_SPKI_BYTES = 1024;

// Mirror of the circuit's chunking constants. See module header.
const SPKI_CHUNK_BYTES = 31;
const SPKI_FULL_CHUNKS = 33;
const SPKI_NUM_CHUNKS = 34; // 33 full + 1 trailing single-byte chunk

/** Big-endian pack `chunk.length` bytes (caller guarantees ≤ 31) into a BN254 field. */
function packBE(chunk: Uint8Array): bigint {
  let acc = 0n;
  for (let i = 0; i < chunk.length; i++) {
    acc = (acc << 8n) | BigInt(chunk[i]!);
  }
  return acc;
}

export async function spkiCommit(spkiDer: Uint8Array): Promise<bigint> {
  if (spkiDer.length === 0) {
    throw new Error("spkiCommit: empty SPKI");
  }
  if (spkiDer.length > MAX_SPKI_BYTES) {
    throw new Error(
      `spkiCommit: SPKI length ${spkiDer.length} exceeds MAX_SPKI_BYTES ${MAX_SPKI_BYTES}`,
    );
  }

  // Zero-pad to exactly MAX_SPKI_BYTES. `Uint8Array` is zero-initialised.
  const padded = new Uint8Array(MAX_SPKI_BYTES);
  padded.set(spkiDer, 0);

  const fields: bigint[] = new Array(SPKI_NUM_CHUNKS);
  for (let c = 0; c < SPKI_FULL_CHUNKS; c++) {
    const start = c * SPKI_CHUNK_BYTES;
    fields[c] = packBE(padded.subarray(start, start + SPKI_CHUNK_BYTES));
  }
  // Trailing chunk: the lone byte at index 1023 (mirrors circuit's
  // `fields[33] = spki_bytes[1023] as Field;`).
  fields[SPKI_FULL_CHUNKS] = BigInt(padded[MAX_SPKI_BYTES - 1]!);

  return pedersenHashFields(fields, SPKI_COMMIT_DOMAIN);
}
