// Extract canonical DER bytes of a certificate's SubjectPublicKeyInfo.
//
// Algorithm-agnostic: the flattener commits trust-list leaves via
// `spkiCommit(spki)`, which is just `pedersenHashBuffer` over the raw SPKI
// bytes. Every QES-issuing CA in the trust list — ECDSA-P256, RSA-2048
// through RSA-4096, EdDSA, etc. — round-trips through the same path with no
// per-algorithm branching.

import { X509Certificate } from "node:crypto";
import { MAX_SPKI_BYTES } from "./spkiCommit.js";

export function extractSpki(certDer: Uint8Array): Uint8Array {
  const cert = new X509Certificate(Buffer.from(certDer));
  const spkiBuf = cert.publicKey.export({ type: "spki", format: "der" });
  if (!Buffer.isBuffer(spkiBuf)) {
    throw new Error("extractSpki: expected DER Buffer from publicKey.export");
  }
  const spki = new Uint8Array(spkiBuf);
  if (spki.length > MAX_SPKI_BYTES) {
    throw new Error(
      `extractSpki: SPKI length ${spki.length} exceeds MAX_SPKI_BYTES ${MAX_SPKI_BYTES}`,
    );
  }
  return spki;
}
