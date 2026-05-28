// SPKI commitment — the per-CA Merkle leaf for the CRISP-QES trust root.
//
// Construction (frozen for this MVP):
//
//   spkiCommit = pedersenHashBuffer(spkiDer, SPKI_COMMIT_DOMAIN)
//
// where `spkiDer` is the canonical DER bytes of the SubjectPublicKeyInfo
// extracted from a trusted CA certificate. The hash family is Pedersen on
// BN254 (see ./pedersen.ts).
//
// Domain index: 1 (reserved 0 for the Merkle inner-node hash, see ../tree/merkle.ts).
//
// The Noir circuit will mirror this leaf commitment when it proves a
// citizen's leaf cert chains to `trustRoot`. Drift between the two = the
// circuit silently rejects every valid signer.

import { pedersenHashBuffer } from "./pedersen.js";

export const SPKI_COMMIT_DOMAIN = 1;

/**
 * Soft upper bound on SPKI size. RSA-4096 SPKI ~ 550 bytes; we leave headroom
 * up to ~RSA-8192 for future-proofing. The flattener errors out beyond this
 * so an unexpected algorithm/key size is caught at trust-list build time
 * rather than at circuit witness time.
 */
export const MAX_SPKI_BYTES = 1024;

export async function spkiCommit(spkiDer: Uint8Array): Promise<bigint> {
  if (spkiDer.length === 0) {
    throw new Error("spkiCommit: empty SPKI");
  }
  if (spkiDer.length > MAX_SPKI_BYTES) {
    throw new Error(
      `spkiCommit: SPKI length ${spkiDer.length} exceeds MAX_SPKI_BYTES ${MAX_SPKI_BYTES}`,
    );
  }
  return pedersenHashBuffer(spkiDer, SPKI_COMMIT_DOMAIN);
}
