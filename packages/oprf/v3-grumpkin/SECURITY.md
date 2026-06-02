# CRISP-QES v3 — Grumpkin VOPRF: Security Notes

> ## ⚠️ EXPERIMENTAL / UNAUDITED — DO NOT USE FOR REAL IDENTITIES OR FUNDS
>
> This package implements a **non-standard** verifiable OPRF ciphersuite over the
> **Grumpkin** curve, plus the Noir circuits that consume it. It has **NOT** been
> externally audited. The hash-to-curve suite is **bespoke** (there is no RFC-9380
> registered suite for Grumpkin, hence **no official third-party test vectors**).
> A first-pass internal self-audit found **at least one real soundness gap**
> (see *Known soundness concerns*, item C-1). Treat everything here as a
> research/demo build. Do not rely on any privacy or integrity property until an
> independent cryptographic review and a cross-implementation validation against
> RFC-9380 official vectors have been completed.

---

## 1. What this is

A privacy-preserving, anti-Sybil identity primitive for petition signatures:

- A Ukrainian **Diia QES** P-256 certificate proves a real, unique person (RNOKPP =
  taxpayer id) who is **≥ 18**.
- A **VOPRF** turns the RNOKPP into a stable pseudonym **N = k·H2C(RNOKPP)** without
  the OPRF operator ever learning the RNOKPP (operator-blind), and without the
  client learning the OPRF key `k`.
- A **Pedersen** commitment / nullifier over `N` is published on-chain; the same
  person always maps to the same nullifier (one-person-one-signature) while
  different petitions / contexts can be separated by the OPRF key.

The curve is **Grumpkin** (`y² = x³ − 17`, `a = 0`, `b = −17`, cofactor 1), chosen
because it is *exactly* Noir's embedded curve, so JS witnesses and in-circuit
`embedded_curve_ops` interoperate with no re-encoding.

- Base field `P = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
  (= BN254 scalar field).
- Group order `N = 21888242871839275222246405745257275088696311157297823662689037894645226208583`
  (= BN254 base field).
- Generator `G = (1, 0x2cf1…f272c)`, verified on-curve, order `N`, cofactor 1.

Hash-to-curve: RFC-9380 `expand_message_xmd(SHA-256)` → `hash_to_field(count=2,
L=48)` → two **Simplified SWU is not used**; instead the **Shallue–van de
Woestijne (SvdW)** map with `Z = 1`, summed (`H2C = map(u0) + map(u1)`), giving a
random-oracle (`_RO_`) suite. DST =
`"CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_"` (42 bytes).

DLEQ: **Chaum–Pedersen** proof that `log_G(Kpub) == log_M(Y)`, Fiat–Shamir
challenge = Noir `pedersen_hash` of the transcript
`[G, Kpub, M, Y, a1, a2]`.

---

## 2. What each proof is intended to guarantee

| Circuit | Public output | Intended guarantee |
|---|---|---|
| `qes_frontend` | `rnokpp_field` | A valid P-256 QES signature over `signedAttrs`; a 10-digit RNOKPP at a witnessed DER offset behind OID 2.5.4.5; DOB proves age ≥ 18 vs a public `today`. |
| `enroll_commit` (Phase 1) | `(M, rnokpp_commit)` | Same as front-end **plus** `M = r·H2C(RNOKPP)` (SvdW in-circuit), with witnessed `(u0,u1)` *bound* to the extracted RNOKPP via an in-circuit `pedersen([rnokpp_field])`. The RNOKPP→(u0,u1) `expand_message_xmd` step is **witnessed, not proven** here. |
| `enroll_commit_v2` (Phase 2) | `M` | Same as Phase 1 but `expand_message_xmd(SHA-256)` (the 3 SHA blocks → `u0,u1`) is computed **fully in-circuit**; no Pedersen binding needed. |
| `oprf_commitment` | _RETIRED_ | Was a standalone SvdW + blinded-MSM check (`M = r·(P0+P1)`). Retired; its hash-to-curve is now the pinned `grumpkin_voprf::h2c` library module (SvdW constants are lib globals, so the F3 non-canonical-suite forgery is unexpressible). |
| `oprf_nullifier` | `pedersen([N.x,N.y])` | Verifies the DLEQ for the node response `Y`, unblinds `N = rinv·Y` bound to `r` via the group equation `r·N == Y`, outputs the nullifier commitment. |

The threshold OPRF prototype (`threshold/threshold-oprf.mjs`) shows that `k` can
be Shamir-shared so **no single node ever holds or reconstructs `k`**; any `t`
nodes recombine partials `B_i = k_i·M` by Lagrange-in-the-exponent.

---

## 3. Cryptographic assumptions

- **Grumpkin discrete log** (~127-bit security; `N` is ~254 bits). The OPRF
  pseudo-randomness and the DLEQ soundness rest on DL/CDH being hard here. Note
  this is **below** the 128-bit comfort line and the curve is far less studied
  than secp256k1 / P-256.
- **Pedersen hash (Noir `pedersen_hash`)** — collision resistance / binding,
  used for the nullifier commitment, the RNOKPP→(u0,u1) binding, and as the
  Fiat–Shamir challenge. Its preimage/collision resistance over Grumpkin is the
  binding assumption for the nullifier.
- **SHA-256** — collision/preimage resistance for `expand_message_xmd` and the
  ECDSA message digest.
- **UltraHonk / KZG trusted setup** (Barretenberg `bb`). A universal SRS is
  assumed honestly generated; a compromised/biased setup breaks proof soundness.
- **ECDSA-P256** unforgeability for the QES signature, plus the **Diia PKI** root
  of trust (out of scope of this package; here certs are *synthetic*).
- **Fiat–Shamir in the ROM** — the `pedersen_hash` challenge is modeled as a
  random oracle.
- **Non-standard SvdW/Grumpkin H2C** — assumed to be a secure random-oracle map.
  This is the **weakest-reviewed** assumption: there is no registered suite and
  no official cross-implementation vectors. **Needs external review + validation
  against an independent RFC-9380 implementation.**

---

## 4. Operator-blind property + what the threshold OPRF adds

- **Operator-blind:** the OPRF node only ever sees `M = r·H2C(RNOKPP)` for a
  client-chosen blind `r`, and returns `Y = k·M`. Under DDH the node learns
  nothing about `H2C(RNOKPP)` or the RNOKPP. The DLEQ proof lets the client
  verify `Y = k·M` for the *committed* key `Kpub = k·G` without trusting the node.
- **Threshold (no single keyholder):** `k` is Shamir-shared across `n` nodes;
  any `t` produce partials `B_i = k_i·M` and the client recombines to `Y = k·M`
  via Lagrange-in-the-exponent. `k` is never assembled. This removes the
  single-point-of-compromise: an attacker must corrupt ≥ `t` nodes to recover
  `k` (which would let them de-anonymize via offline dictionary over RNOKPP) or
  to silently change the pseudonym mapping.

---

## 5. Known soundness concerns (from the first-pass self-audit)

> This list is **not** exhaustive and is **no substitute** for an external audit.

### C-1 (FIXED — was a real soundness/forgery bug): DLEQ challenge limbs were not bound to `c_expected`
`circuits/oprf_nullifier/src/main.nr`

> **RESOLVED.** The circuit now (a) range-checks all scalar limbs to 128 bits
> (`assert_max_bit_size::<128>()`) and (b) binds the MSM challenge scalar to the
> in-circuit Fiat–Shamir hash: `assert(c_lo + c_hi * 2^128 == ch)` where
> `ch = pedersen(transcript)`. Empirically confirmed: the forgery witness below
> (arbitrary `c`, `c_expected := ch`, fake `Y ≠ k·M`) now fails `nargo execute`
> at the binding assert; the honest path still proves+verifies (28,688 gates).
> Regression probe: `forge-nullifier-witness.mjs`. Original analysis preserved
> below for the record.

The challenge scalar used in the algebraic relation is built from **private**
limbs `c = Scalar { lo: c_lo, hi: c_hi }` (lines 41, 45–46) and feeds the MSMs
`a1 = z·G − c·Kpub`, `a2 = z·M − c·Y`. The Fiat–Shamir check (line 50) asserts
`pedersen(transcript) == c_expected`, where `c_expected` is a **separate public
Field** input. **Nothing constrains `c_lo + c_hi·2^128 == c_expected`.**

A malicious prover can therefore choose `z` and `c` (limbs) *freely*, compute
`a1, a2` from them, and then simply set the public input `c_expected :=
pedersen([G,Kpub,M,Y,a1,a2])`. The assertion at line 50 holds **by construction**,
with **no knowledge of any discrete log**. This decouples the Fiat–Shamir
challenge from the challenge actually used in the relation, which is exactly the
binding that makes Chaum–Pedersen sound — so a DLEQ can be forged for an
**arbitrary `Y` ≠ k·M**. (Verified by simulation: an attacker-chosen `Y*` not
equal to `k·M` satisfies all DLEQ asserts.) Because the honest witness generator
sets `c_lo,c_hi` = limbs of `c` and `c_expected = c`, the gap is invisible in
normal testing.

**Fix:** constrain the limbs to the public challenge in-circuit, e.g.
`assert(c_lo + c_hi * 2.pow_32(128) == c_expected);` and range-check
`c_lo, c_hi < 2^128`. Equivalently, derive the limbs from `c_expected`
in-circuit rather than taking them as independent witness.

### C-2 (NOTE): `oprf_nullifier` does not bind `M`/`r` to the identity
`circuits/oprf_nullifier/src/main.nr:52–60`

The unblind binds `(r, rinv)` via the group equation `r·(rinv·Y) == Y` (line 57),
which is sound (`r·rinv ≡ 1 mod N` whenever `Y ≠ O`, so `N = rinv·Y` is the
consistent unblind). **However** `r` here is an unconstrained private witness and
`M` is treated as a free public point: this circuit never checks `M = r·H2C(id)`
or that `M` came from `enroll_commit`. The identity→`M` binding lives entirely in
`enroll_commit`/`_v2`; the two circuits must be **composed** (the same `M`
threaded through, ideally via a shared commitment) or a prover can run
`oprf_nullifier` on any `M` of their choosing. This is by design for the phased
build but is a **deployment-level binding requirement**, not a proven property of
this circuit alone. Combined with C-1, the nullifier output of this circuit is
attacker-controllable in isolation.

### C-3 (NOTE): low-`s` / ECDSA malleability not enforced
`circuits/{qes_frontend,enroll_commit,enroll_commit_v2}/src/main.nr` (ECDSA calls)

`std::ecdsa_secp256r1::verify_signature` accepts both `(r, s)` and `(r, N−s)`;
there is **no low-`s` normalization**. The proof outputs (RNOKPP, nullifier)
depend on cert *contents*, not the signature encoding, so this does **not** by
itself change the identity. But a proof is **not uniquely bound to one signature
encoding** — relevant if any off-chain replay/dedup ever keys on the signature
bytes. Recommend asserting `s ≤ N/2` (low-`s`) for defense in depth.

### Constraints checked and found PASS

- **(a) `is_square` / ZETA binding** — `assert_is_square`
  (`lib-noir/grumpkin_voprf/src/h2c.nr`, used by `enroll_commit_v2`):
  `e ∈ {0,1}` enforced; `e=1 ⇒ w²=gx`, `e=0 ⇒ w²=gx·ZETA`. Since `ZETA = 5` is a
  verified quadratic **non-residue** mod `P`, a square `gx` cannot satisfy the
  `e=0` branch (`gx·ZETA` is a non-residue → no `w`) and a non-square cannot
  satisfy `e=1`. So `e` is **forced** to the true Legendre symbol; a prover
  cannot flip it. **PASS.** Minor edge: `gx = 0` satisfies both branches, but
  that only occurs when `x` is a root of the curve poly (`y=0`), both branches
  then yield the same valid on-curve point — not exploitable.
- **(b) Fiat–Shamir recomputed in-circuit** — `oprf_nullifier/src/main.nr:49`:
  the challenge **is** recomputed in-circuit via `pedersen_hash` over the
  recomputed `a1,a2` and asserted equal. The recomputation is correct; the gap
  is purely the **limb↔`c_expected` binding** of C-1, not a "trusted challenge".
- **(c) `r^-1` group-equation inverse binding** — `oprf_nullifier/src/main.nr:55–57`:
  sound as described in C-2 (forces `N = rinv·Y` consistently).
- **(d) `sgn0` well-constrained** — `sgn0(x) = x.to_le_bits()[0]`
  (`lib-noir/grumpkin_voprf/src/h2c.nr`, etc.). The final `y` is forced: `assert(sqrt_x²
  == gx)` pins `|y|`, and `y_final` is `cmov`-selected so `sgn0(y_final) ==
  sgn0(u)` **regardless of which square root the prover supplies** for `sqrt_x`.
  So `y` is fully determined by `(gx, sgn0(u))`. **PASS** (assuming Noir's
  `to_le_bits` yields the canonical `< P` decomposition, which it constrains).
- **SvdW x-selection** — `cmov(x3,x1,e1)` then `cmov(·,x2,e2·(1−e1))` selects
  `x1` if `g(x1)` square, else `x2` if `g(x2)` square, else `x3`; the final
  `assert(sqrt_x² == g(x))` rejects any branch where the selected `x` is not a
  valid abscissa, and the SvdW theorem guarantees at least one is. `x` is
  **deterministic** given `u`. **PASS.**
- **`tv1*tv2*inv_t == 1`** (`*:30`/`*:82`) correctly binds `inv_t` as the inverse,
  rejecting the `u` values where `tv1*tv2 = 0` (the SvdW exceptional set). **PASS.**

### Self-audit cross-checks that PASS (off-circuit, in `vectors.test.mjs`)

- Grumpkin params (`P`, `N`, `b=−17`, cofactor 1, generator on-curve & order `N`).
- SvdW constants `c1..c4` independently re-derived from `Z=1` == lib's.
- `find_z_svdw` conditions for `Z=1`: `g(Z)≠0`; `h(Z)` nonzero square;
  `is_square(g(Z))`.
- `hashToField2` == an independent strict RFC-9380 `expand_message_xmd(SHA-256)`
  reimplementation; the in-circuit `enroll_commit_v2` DST bytes match the lib DST.
- `hashToCurve` outputs on-curve, deterministic, distinct, pinned.
- Full OPRF roundtrip `N == k·H(m)`; DLEQ honest-verifies and **tampered-`Y`
  rejects** (off-circuit Chaum–Pedersen relation).

---

## 6. Other known gaps

- **No external audit.** First-pass internal review only.
- **Non-standard ciphersuite, no official vectors.** The Grumpkin SvdW `_RO_`
  suite must be validated against an independent RFC-9380 implementation and
  reviewed by cryptographers before any production use.
- **Witnessed `signedAttrs` SHA-256.** All cert circuits take `msghash =
  sha256(signedAttrs)` as a **witnessed** input; the `signedAttrs → hash`
  chaining is not proven (Phase-2 work). A prover controls `msghash` modulo the
  ECDSA check, so the link from the *actual signed attributes* to the verified
  digest is **not** in-circuit.
- **Witnessed DER offsets.** `rnokpp_oid_off` / `dob_off` are witnessed; the
  circuit checks the bytes *at* those offsets match the expected OID/tag pattern
  but does not prove they are the *only* / *canonical* such fields in the DER.
- **Phase-1 `enroll_commit` witnesses `(u0,u1)`** and binds them only via a
  Pedersen commitment to `rnokpp_field`; the `expand_message_xmd` derivation is
  not proven there (it is in `enroll_commit_v2`).
- **DKG is trusted-dealer in the prototype.** `threshold/threshold-oprf.mjs`
  models the additive DKG structure but omits Feldman/Pedersen commitments, the
  complaint/verification rounds, and a broadcast channel; it also exposes the
  implied `k` for test comparison (a live DKG must never do so). The threshold
  partials also lack per-share DLEQ proofs in this prototype.
- **Modulo bias in `randScalar`** is negligible (384-bit reduction) but not
  rejection-sampled.
- **Curve security margin** ~127-bit, below the 128-bit target.

---

## 7. Recommended pre-production checklist

1. Fix **C-1** (bind DLEQ challenge limbs to `c_expected` + range-check) and add
   a negative test that a mismatched `(c_lo,c_hi, c_expected)` is rejected.
2. Compose `enroll_commit`/`_v2` ↔ `oprf_nullifier` so `M` (and thus the
   identity) is bound end-to-end (address **C-2**); or fold them into one proof.
3. Enforce low-`s` ECDSA (**C-3**).
4. Prove `signedAttrs → msghash` in-circuit; validate the full Diia cert chain.
5. Cross-validate the H2C suite against an independent RFC-9380 implementation;
   publish official-format test vectors.
6. Replace the trusted-dealer DKG with a verifiable DKG + per-share DLEQ.
7. **Commission an external cryptographic + circuit audit.**
