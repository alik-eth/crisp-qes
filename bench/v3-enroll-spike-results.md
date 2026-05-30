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
| DER field extraction (1 field, 1.5 KB buffer, witnessed offset) | **6,756** | OID match + tag/len + 10-byte read + digit validation. Dynamic reads are at `offset + const` → bb handles cheaply. ~14k for RNOKPP + DOB. Far below the initial ~100k guess. |

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

**Scenario B — co-design OPRF over a SNARK-friendly curve (embedded Grumpkin / a BN254-cycle curve):** — CHOSEN, budget refined with measured DER:

| term | gates | status |
|---|---|---|
| blinding scalar mult (native Grumpkin) | 3,564 | measured |
| ECDSA-P256 verify | 72,331 | measured |
| SHA-256 (cert TBS ~24 blk + signedAttrs ~5 blk) | ~120k | derived (4.1k/blk) — **dominant term** |
| DER extraction (RNOKPP + DOB) | ~14k | measured (6.7k/field) |
| Merkle membership (trust-root, few hops) | ~5k | from v2 sign circuit |
| Grumpkin hash-to-curve `H2C(RNOKPP)` | ~10–30k (est) | **only unmeasured term + the security-review item** |
| **total** | **~225–245k → SHA-dominated, browser-provable** | iOS bench TBD |

The cost is now dominated by SHA-256 — a known, optimizable quantity (zk-email
techniques) — not by anything exotic. The only unmeasured term is the Grumpkin
hash-to-curve, which is also the RFC-9380/security-review item.

## Recommendation

Go — **via Scenario B.** Operator-blind enrollment is feasible as a ~300k-gate
one-time circuit *if* the OPRF runs over a SNARK-friendly curve. The ECDSA/
SHA/DER costs are all moderate; none is a blocker.

Tradeoff to own: leaving ristretto255 means the OPRF is no longer the RFC-9497
standardized ciphersuite. 2HashDH works over any prime-order group, and Grumpkin
(prime order, scalar field = BN254 base field) is a candidate — but it needs (a)
a defined hash-to-curve and (b) a security review of the OPRF over that curve.
This composes fine with threshold OPRF (§2): DKG works on any prime-order group.

## Curve decision: Grumpkin (validated)

Chosen the SNARK-friendly path (Scenario B). PoC `packages/oprf/grumpkin-oprf-poc.mjs`
implements 2HashDH VOPRF over **Grumpkin** and validates the protocol end-to-end
(not just the in-circuit cost):

```
PASS  determinism: same RNOKPP + same k -> same OPRF output (Sybil property)
PASS  unblind correctness: r^-1 * (k*r*P) == k*P
PASS  distinctness: different RNOKPP -> different output
PASS  DLEQ verifies for honest eval
PASS  DLEQ rejects tampered eval (wrong key)
```

Grumpkin = `y^2 = x^3 - 17` over F_p (p = BN254 scalar field); group order n =
BN254 base field; **cofactor 1**. The cofactor-1 property is a real bonus:
ristretto255 exists only to give cofactor-8 Curve25519 a prime-order abstraction
— Grumpkin is natively prime-order, so the OPRF construction drops the
subgroup-clearing/encoding subtleties entirely. ~127-bit DL security (on par
with ristretto255). Native in Noir as the embedded curve -> the in-circuit
blinding binding stays at the measured 3.5k gates.

Standing caveat (the price of leaving RFC-9497): the PoC's hash-to-curve is
try-and-increment; a production build needs RFC-9380 SSWU for Grumpkin + a
security review of the non-standard ciphersuite. Composes with threshold OPRF
(DKG works on any prime-order group).

## Remaining Phase-0 work (if pursued)

1. Empirically measure non-native 25519 scalar mult (pull noir-bignum) to
   replace the 10⁶ estimate with a real number — confirms the A-vs-B gap.
2. Prototype 2HashDH over Grumpkin + a Grumpkin hash-to-curve; security review.
3. DER field-extraction gadget (RNOKPP at OID 2.5.4.5, DOB in
   SubjectDirectoryAttributes) — measure real cost, replace the ~100k estimate.
4. Compose full circuit; benchmark browser + iOS prove time/memory against the
   384 MiB cap (see `bench/v2-mem-floor.mjs`) — enroll circuit is ~10× the sign
   circuit, so on-device enrollment feasibility is the open UX question.
