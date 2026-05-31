# Multi-country enrollment via per-country circuits — design

**Date:** 2026-05-31
**Status:** design / roadmap (not yet implemented)
**Context:** generalizes the Ukraine-only v3 operator-blind enrollment to other
eIDAS QES jurisdictions.
**Relates to:** task #39 (v3 operator-blind enrollment); supersedes nothing.

## 1. Motivation

The live system enrolls citizens from a **Diia (Ukraine) QES** only. But the
whole thing is built on **eIDAS QES / CAdES** — an EU-wide standard:

- The signature container is **CAdES-BES `.p7s`** (CMS `SignedData`), identical
  across EU/EEA QTSPs.
- Trusted issuer CAs are published in the **EU LOTL** (List of Trusted Lists) —
  one machine-readable source for all member states (we already have
  `packages/lotl-flattener`).
- Subject national IDs follow ETSI EN 319 412-1 **`PNO<CC>-<id>`** semantics.
  Ukraine's `TINUA-<RNOKPP>` is exactly that pattern (TIN, country UA).

So the *framework* is pan-European; only the cert parsing + verification is
country-specific. This doc proposes adding countries as **independent
per-country circuits** rather than one generic, runtime-parameterized circuit.

## 2. How a certificate is checked today (baseline)

Two layers, Ukraine-specific:

1. **Client parse** (`@crisp-qes/sdk` `parseP7s`): extracts leaf P-256 pubkey,
   `signedAttrs`, the ECDSA signature over them, the PKCS#9 `messageDigest`, the
   subject `serialNumber` (`TINUA-<RNOKPP>`), and DOB.
2. **In-circuit** (`enroll_commit_v2`, operator-blind ZK proof): proves, without
   revealing the cert —
   - ECDSA-P256 over `sha256(signedAttrs)` (hashed in-circuit) verifies;
   - the DER run `06 03 55 04 05 │ 13 10 │ "TINUA-" │ <10 digits>` is asserted
     and the 10 RNOKPP digits feed hash-to-curve;
   - DOB ≥ 18 vs public `today`;
   - the `messageDigest` is returned and the service binds it to
     `sha256(session challenge)`.

**Gaps (open, EXPERIMENTAL/UNAUDITED):**
- **No PKI chain-of-trust.** Only the *leaf* signature is checked; nothing proves
  the leaf was issued by a trusted Ukrainian QTSP. `tinuaPrefixOk` is a string
  check, not crypto.
- **No `cert[]`↔`pubkey` binding** — the ECDSA pubkey isn't proven to be the
  cert's SPKI.

The OPRF / nullifier / recovery / petition machinery is **identity-agnostic** —
it only needs *some* unique national ID to bind. All country-specific logic
lives in cert parsing + in-circuit verification.

## 3. Architecture: one circuit per country

Ship a distinct circuit per jurisdiction — `enroll_commit_ua`,
`enroll_commit_de`, … — each hardcoding that country's:

- **subject-ID pattern** — DER OID + prefix + ID length/charset (`PNO<CC>-` per
  ETSI), feeding the country's national ID to hash-to-curve;
- **DOB handling** — extract + age-check, *or omit entirely* for QES that carry
  no birth date ("dob or no dob");
- **signature algorithm** — P-256 / brainpool / RSA (see §6);
- **trust roots** — only that country's QTSP CA root(s).

Each circuit → its own verification key → its own on-chain `UltraVerifier`. The
service routes by country (cert-detected or user-selected) to the right circuit
+ verifier.

**Why per-country beats one generic circuit:**
- Smaller, branch-free circuits → cheaper to prove and **far easier to audit**
  (each country's exact cert quirks are explicit, not runtime config).
- **Independent rollout** — adding a country can't regress existing ones; each
  has its own VK/verifier and audit.
- **Tiny trust check** — pin only that country's handful of QTSP roots instead of
  the full EU LOTL (hundreds of CAs). Cheaper in-circuit, simpler to reason about.

## 4. Identity scoping — "one eID = one identity, per country"

Accepted model: a person holding eIDs in two countries = **two distinct
identities** (cross-border Sybil is not prevented; it's inherent to "one eID =
one identity"). Make this concrete by **domain-separating the OPRF/commitment by
country code** so the same ID digits in UA vs DE map to different OPRF outputs:

- fold `CC` into the hash-to-curve input (domain separation), or run a
  per-country OPRF epoch/tag;
- either **one enrollment tree with country-tagged leaves**, or **a tree per
  country** (`EnrollmentRegistry` per country).

Petition eligibility then scopes to "enrolled in country X", or stays global
(design choice — a global petition could accept any country's enrollment).

## 5. The "country pack" interface

A country = a self-contained bundle:

```
packages/.../country/<cc>/
  parser config   — OID, ID prefix/length, DOB OID (or none), sig algo
  circuit         — enroll_commit_<cc> (Noir): ID pattern, DOB?/no-DOB,
                    sig verify, issuer→root trust check (§6)
  verifier        — UltraVerifier_<cc> on-chain (its VK)
  roots           — that country's QTSP CA root pubkey(s) / root-set commitment
service routing   — detect/select country → circuit URL + verifier + OPRF tag
```

Adding a country = add a pack; the core (OPRF node, nullifier, recovery, relayer,
petitions) is untouched.

## 6. In-circuit trust-root verification (the meaty shared upgrade)

This is **new work — not built even for Ukraine yet** — and it closes both the
chain-of-trust and `cert↔pubkey` gaps. Per-country it is cheap because the root
set is tiny.

Design:
- The circuit takes the **leaf TBSCertificate** (or its hash) and the **issuer's
  signature** over it as witnesses.
- It verifies that issuer signature against an **issuer public key**, and asserts
  the issuer key ∈ the country's **pinned root set** — a compile-time constant
  for a single-root country, or a **small Merkle root of that country's CAs**
  (produced by `lotl-flattener`) with an inclusion proof for the larger ones.
- It binds the leaf's SPKI (the ECDSA pubkey used in §2) to the TBS bytes, so the
  signature-verifying key is provably the cert's key (closes `cert↔pubkey`).

Cost: **one extra in-circuit signature verification** (issuer→leaf) plus a
root-membership check. With a per-country root set (often 1–few CAs), the
membership check is trivial; the dominant new cost is the issuer-signature verify
(same algorithm tier as §7).

## 7. Signature-algorithm tiers (the real gate)

Per-country circuits **isolate** the algorithm problem but don't dissolve it:

- **P-256 (works today):** `std::ecdsa_secp256r1`. Leaf verify ≈ 3.8M gas
  on-chain; in-circuit cost is known. A P-256 + same-format country is a small
  lift. (Issuer→leaf in §6 adds a second P-256 verify.)
- **brainpoolP256r1 / other short-Weierstrass:** feasible but needs the curve in
  the proving stack; moderate.
- **RSA-2048/4096 (most EU QES):** RSA verification in-circuit is impractical in
  Noir. Options for RSA countries: (a) a heavier/different proof system, or
  (b) verify the cert **off-chain in the OPRF gate** (the old v2 model) — trading
  some operator-blindness for that jurisdiction. This is the architectural
  decision point for broad coverage, and it can be made **per country** rather
  than globally.

## 8. Effort tiers / roadmap

1. **Trust-root verification for UA (§6)** — do this first; it hardens the live
   system regardless of multi-country, and it's the template every pack reuses.
   **STATUS: UNBLOCKED (2026-05-31)** — the real Diia trust material was sourced
   from public records and the approach is confirmed tractable (P-256, not DSTU).
   **Resolved facts:**
   - Chain is **Central CA (Min. of Digital Transformation) → "DIIA" QTSP CA →
     citizen leaf**, every link **`ecdsa-with-SHA256` (P-256)** — verifiable
     in-circuit with the existing `std::ecdsa_secp256r1` gadget. (Ukraine's CA
     ecosystem also offers DSTU 4145-2002 / RSA hierarchies — the Diia.Підпис
     **ECDSA** hierarchy is the one we use; avoid the DSTU/RSA branches.)
   - **Pin set** = the "DIIA" Qualified Trust Services Provider CA P-256 pubkeys
     (public; from `http://ca.diia.gov.ua/uploads/certificates/diia_ecdsa.p7b`):
     `UA-43395033-2311` = (x `8500048265e919c1738e873572c1f6443895a0c03985fc71bd96a6f62a53bcc8`,
     y `69d23ca6e6a2a7dc443bbb2a0b914ee35f1c74e282ecd8e6c5287c7a3d4aee10`);
     `UA-43395033-2503` = (x `c8b3546f4a34c021a31b3578057d1de304cbf1743a391b2032cd5b7d37184148`,
     y `c2440ea2fba10872b0bc90a92371ad50f59d0e9c0216ed52fd259b8a8cc9ee54`).
     These are rotations of the same issuer → pin a **set** of allowed CA keys;
     exclude the OCSP-/TSA-server certs (not leaf issuers). Pin the **QTSP CA**
     directly (issuer of leaves); optionally chain one more to the Central CA
     root later.
   - **Validation sample on hand**: a real Diia citizen leaf (ECDSA-P256, subject
     `serialNumber=TINUA-<RNOKPP>`) `verify`s OK against the fetched `-2311` CA.
     leafTbsBytes ≈ 1203 B; RNOKPP at subjectSerialOffset, leaf pubkey at
     leafPubkeyOffset — both inside the signed TBS.
   **Remaining design decisions (no longer blockers):**
   - **CA-key rotation governance**: the pin set changes as Diia rotates CA keys
     (new certs appear in `diia_ecdsa.p7b`). Make the pinned set an
     **admin-settable on-chain commitment** (Merkle root of allowed CA keys) the
     circuit reads, rather than a recompile-to-rotate constant.
   - **Prove-cost check** (see below).
   **Original prerequisites (now satisfied):**
   - The **real Diia QTSP CA public key(s)** that issue citizen QES certs —
     pinned in-circuit. Source: **Ukraine's national Trusted List** (Ministry of
     Digital Transformation / ЦЗО — *not* the EU LOTL; Ukraine publishes its own
     eIDAS-style TSL). Need the specific CA that signs Diia citizen certs.
   - **A representative real citizen `.p7s`** to confirm the actual chain shape
     (does a citizen cert bundle the intermediate? our admin/test fixture does
     NOT — `intermediatePubkey: null`) and the issuer's **signature algorithm**
     (test fixture's `leafCertSignature` is ECDSA-P256; confirm real citizen
     certs match — if the real issuer signs with RSA, this jumps to the §7 RSA
     track). Real citizen certs are PII — handle out-of-band.
   - Confirm offsets on a real cert: `leafTbsBytes` (~1203 B on the fixture),
     `subjectSerialOffset` (RNOKPP), `leafPubkeyOffset` (leaf SPKI) — the circuit
     binds RNOKPP + leaf pubkey to the *signed* leaf TBS and verifies
     `ECDSA(pinned_CA_pubkey, leafCertSignature, sha256(leafTbsBytes))`.
   - **Prove-cost check** once unblocked: a 2nd in-circuit ECDSA-P256 +
     `sha256_var(leafTbsBytes)` (~19–24 blocks) on top of today's 2^19 circuit —
     measure gate count; may approach/exceed 2^19→2^20 and the in-browser prove
     budget (esp. iOS 832 MiB / the <1 GB target). Decide platform impact then.
2. **Second P-256 country pack** — parameterize the ID pattern + DOB?/no-DOB,
   add its root set, new circuit + verifier + OPRF country tag. Proves the
   country-pack path end to end. (Weekend-scale once §6 exists.)
3. **OPRF/identity country-scoping (§4)** — domain separation + tree strategy.
4. **RSA track (§7)** — research/eng decision: in-ZK RSA vs off-chain-gate per
   RSA country.

## 9. Open questions

- One enrollment tree (country-tagged) vs a registry per country? (Gas, recovery,
  and root-management trade-offs.)
- Petition scope: per-country vs global-with-country-eligibility.
- Root-set freshness: QTSP roots rotate; pinned constants need a governed update
  path (admin-settable root commitment vs recompiled circuit).
- Privacy: revealing which **country** a user enrolled from is unavoidable (the
  circuit/verifier differ); acceptable, but worth stating.

## 10. Summary

The eIDAS/CAdES envelope + EU LOTL make this pan-European by construction; the
OPRF/nullifier core is country-agnostic. Per-country circuits give isolation,
auditability, and a tiny per-country trust check. The shared upgrade everyone
needs is **in-circuit issuer→root verification (§6)** — worth building for UA
now. The hard frontier is **RSA-in-ZK (§7)**, decidable per country, not globally.
