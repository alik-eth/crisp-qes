# v3 operator-blind enrollment — Phase-0 spike results

Task #39. Goal: before building the enrollment circuit, measure the cost of
the hard gadgets and decide go/no-go. Tooling: nargo 1.0.0-beta.19, bb
4.0.0-nightly.20260120, UltraHonk gate counts via `bb gates`. Spike package:
`packages/v3-enroll-spike/`.

## Measured (real UltraHonk circuit_size)

| Gadget | gates | notes |
|---|---|---|
| ECDSA-P256 verify (1×) | **72,331** | `std::ecdsa_secp256r1::verify_signature` blackbox. Diia leaf certs are P-256/SHA-256 (confirmed in `oprf/attestation.ts`). Cheap. |
| SHA-256, per 64-byte block | **~4,117** | from 16 chained `sha256_compression` = 65,870 gates. (Note: sha256 is **not** in beta.19 stdlib — only the compression blackbox; need to chain it or pull an external lib.) |
| Native embedded-curve (Grumpkin) variable-base scalar mult | **3,564** | `multi_scalar_mul`. This is the blinding op `M = r·P` **if the curve is SNARK-friendly**. |

Derived: hashing a ~1.5 KB leaf TBS (~24 blocks) ≈ **~100k** gates; signedAttrs
(~5 blocks) ≈ **~20k**.

## The decisive result (risk #1)

The blinding binding `M = r·H2C(RNOKPP)` is the dominant risk **only because of
the curve**. The operation itself is 3,564 gates on the native embedded curve.
ristretto255 (Curve25519) is non-native to BN254 — no stdlib support — so
proving it requires foreign-field EC arithmetic. A full non-native variable-base
scalar mult on 25519 is **estimated 10⁵–10⁶+ gates** (literature / zkPassport-
class; not yet measured here), i.e. 100–1000× the native cost and likely the
single largest term in the whole circuit.

**So the cost of operator-blind enrollment hinges entirely on the OPRF curve.**

## Two budgets

**Scenario A — keep RFC-9497 ristretto255, prove blinding non-natively:**

| term | gates |
|---|---|
| ristretto255 H2C + scalar mult (non-native) | ~10⁶ (est, dominant) |
| ECDSA-P256 | 72k |
| SHA-256 (cert + signedAttrs) | ~120k |
| DER field extraction + Merkle membership | ~100k (est) |
| **total** | **~1.3M+ → heavy prove, large memory, likely mobile-infeasible** |

**Scenario B — co-design OPRF over a SNARK-friendly curve (embedded Grumpkin / a BN254-cycle curve):**

| term | gates |
|---|---|
| blinding binding (native) | ~3.5k |
| ECDSA-P256 | 72k |
| SHA-256 (cert + signedAttrs) | ~120k |
| DER field extraction + Merkle membership | ~100k (est) |
| **total** | **~300k → same order as the sign circuit, provable, plausibly mobile** |

## Recommendation

Go — **via Scenario B.** Operator-blind enrollment is feasible as a ~300k-gate
one-time circuit *if* the OPRF runs over a SNARK-friendly curve. The ECDSA/
SHA/DER costs are all moderate; none is a blocker.

Tradeoff to own: leaving ristretto255 means the OPRF is no longer the RFC-9497
standardized ciphersuite. 2HashDH works over any prime-order group, and Grumpkin
(prime order, scalar field = BN254 base field) is a candidate — but it needs (a)
a defined hash-to-curve and (b) a security review of the OPRF over that curve.
This composes fine with threshold OPRF (§2): DKG works on any prime-order group.

## Remaining Phase-0 work (if pursued)

1. Empirically measure non-native 25519 scalar mult (pull noir-bignum) to
   replace the 10⁶ estimate with a real number — confirms the A-vs-B gap.
2. Prototype 2HashDH over Grumpkin + a Grumpkin hash-to-curve; security review.
3. DER field-extraction gadget (RNOKPP at OID 2.5.4.5, DOB in
   SubjectDirectoryAttributes) — measure real cost, replace the ~100k estimate.
4. Compose full circuit; benchmark browser + iOS prove time/memory against the
   384 MiB cap (see `bench/v2-mem-floor.mjs`) — enroll circuit is ~10× the sign
   circuit, so on-device enrollment feasibility is the open UX question.
