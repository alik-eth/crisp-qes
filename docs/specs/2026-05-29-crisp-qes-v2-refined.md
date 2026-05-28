# CRISP-QES v2 — refined design

Status: design draft, supersedes § 6 of
`docs/specs/2026-05-19-crisp-qes-pivot-design.md` ("v2 roadmap").
Owner: Oleksandr Vovkotrub. Reviewers: TBD.

## 0. Why refine

The original v2 sketch (May 19) assumed FHE could carry both
*enrollment-side uniqueness checks* (FHE-PSI over enrolled tax-IDs)
and *tally-side aggregation*. This document narrows the FHE surface to
match what production threshold-FHE actually delivers today:

> "FHE is currently restricted to vote-tally-shaped workloads — narrow
> well-shaped homomorphic operations (addition, threshold comparison),
> not arbitrary computation." — Vitalik Buterin, ~mid-2026.

Set-membership / collision checks across an enrollment set are
arbitrary computation, not vote tally. Pushing them through FHE-PSI
would either scale linearly per enrollment (untenable past ~10⁴
citizens) or push the design into research-grade FHE-PSI protocols.

This v2.1 design drops FHE from the enrollment path entirely and
keeps it where it earns its keep: the tally + threshold check.

## 1. Architecture at a glance

Three layers, each using the production-ready primitive for its job:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1 — Enrollment (once per citizen)                     │
│ primitive: threshold OPRF over ciphernode committee         │
│ produces: enrollment_secret + commitment ∈ enrollment_tree  │
│ input:    Diia QES (RNOKPP attestation)                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2 — Signature (per petition, in browser)              │
│ primitive: Noir ZK proof (Plonkish, UltraHonk)              │
│ proves:   membership in enrollment_tree + nullifier         │
│ consumes: enrollment_secret (from Passkey PRF or mnemonic)  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3 — Tally + threshold (per petition, FHE)             │
│ primitive: threshold-FHE (BFV / CKKS, Interfold's CRISP)    │
│ aggregates ciphertext signatures → encrypted count          │
│ decrypts only the threshold predicate, never per-citizen    │
└─────────────────────────────────────────────────────────────┘
```

Diia QES enters the system **once**, at enrollment. After that, a
citizen signs petitions in seconds, in the browser, with no Diia app
interaction at all.

## 2. Layer 1 — Enrollment via threshold OPRF

### 2.1 Goal

Given a citizen with a valid Diia QES, produce a deterministic
pseudorandom commitment over their RNOKPP that:

- nobody (citizen, ciphernode operator, on-chain observer) can use to
  recover RNOKPP;
- collides iff two enrollments share the same RNOKPP (so Sybil is
  detectable);
- survives Diia QES reissuance (the commitment is over RNOKPP, not
  over the cert pubkey).

### 2.2 Protocol sketch

OPRF instantiation: 2HashDH (Jarecki et al.), threshold-shared via
TSS over the OPRF key. Each ciphernode holds a Shamir share of `k`.

```
citizen:
  r ← random scalar in q
  X = Hash_to_curve(RNOKPP)
  M = r · X                                        (blinded input)
  attestation = Diia_QES_over(M ‖ enrollment_intent ‖ epoch)
  send (M, attestation) to all n ciphernodes

each ciphernode i ∈ {1..n}:
  verify Diia QES on the bundle (off-chain, cheap)
  Y_i = k_i · M                                    (OPRF share)
  π_i = DLEQ_prove(K_pub,i = k_i · G,  Y_i = k_i · M)
  return (i, Y_i, π_i)

citizen:
  verify each DLEQ proof π_i                       (rejects rogue k_i)
  collect ≥ t valid shares
  Y    = LagrangeCombine({(i, Y_i)})               (= k · M)
  N    = r⁻¹ · Y                                   (= k · X = F_k(RNOKPP))
  N_hi = high 128 bits of canonical(N), BE
  N_lo = low  128 bits of canonical(N), BE
  s    = pedersen_hash([N_hi, N_lo], hashIndex=0)
```

`s` is **both** the citizen's `enrollment_secret` **and** the on-chain
Merkle leaf — there is no extra `Hash(s)` or `pedersen([leaf])`
wrapper above `s`. Earlier drafts of this spec used a separate
`commitment = Hash(N)` value; the web client, OPRF backend, and Noir
circuit collapsed those to a single value on 2026-05-29 to eliminate
the dual-hashing inconsistency. The wire endpoint `/oprf/register`
still accepts a parameter named `commitment` for back-compat; the
value passed is `s`.

### 2.3 Uniqueness check

Each ciphernode keeps the running set `S_i = {commitments seen so
far}`. Before signing a share, ciphernode i:

- recomputes its share `Y_i'` and the citizen-side combiner
  proof-of-correct-combination (Schnorr σ proof);
- on receipt of the resulting commitment from the citizen, attests
  whether it had seen this commitment before in `S_i`.

If a quorum reports "already seen" → reject. Otherwise the citizen
posts `commitment` on-chain (Layer 1 contract), and ciphernodes append
it to `S_i` and to the on-chain enrollment Merkle tree.

> **Subtlety:** the citizen sees the unblinded commitment first, so a
> malicious citizen could attempt to enroll twice and only post the
> second. Defence: the ciphernode quorum's last-step attestation must
> sign over `(commitment, epoch, has_been_seen?)`; on-chain enroller
> contract gates appends on a fresh non-collision attestation. The
> ciphernode protocol also runs a periodic "audit sweep" to surface
> dropped enrollments.

### 2.4 Threat model

| Actor          | Sees                                | Does not see              |
| -------------- | ----------------------------------- | ------------------------- |
| Ciphernode i   | blinded input `M`, Diia QES         | RNOKPP, commitment        |
| Threshold (≥t) | Aggregate count, collision evidence | RNOKPP                    |
| On-chain       | `commitment`, `enrollment_root`     | RNOKPP, Diia cert, mapping commitment ↔ citizen |
| Citizen        | own `enrollment_secret`             | k, k_i, others' RNOKPPs   |
| Eavesdropper   | OPRF transcript                     | Anything plaintext        |

### 2.5 Service-key binding (defence against MITM substitution)

The DLEQ proof from §2.2 binds the returned `Y` to the same `k` that
produced the service's published `K_pub` — but only if the client
verifies against a `K_pub` it trusts. A MITM attacker who can swap
`K_pub` *and* `Y` for a pair derived from their own `k*` would pass
DLEQ verification while learning a per-citizen `N` they can correlate
later. Pinning `K_pub` to an authoritative source closes this.

| Variant | Binding mechanism | Trust anchor |
| ------- | ----------------- | ------------ |
| **v2.1 (shipped)** | `K_pub` is **build-time-pinned** in the `v2-web` bundle via the `VITE_OPRF_PUBKEY` env var; client hard-fails on `/healthz` mismatch. | The Fly deployment (same TLS + COOP/COEP boundary as the rest of the SPA). |
| **v2.2 (Phase-3)** | `K_pub` (and `K_pub,i` for the threshold variant) moves on-chain into `EnrollmentRegistry` as an admin-settable storage slot. Client reads it from the contract at boot. | The contract admin key, eventually a DAO multisig as the ciphernode committee onboards independent operators. |

Bundle-pinning is the right v2.1 answer because the trust anchor is
already the Fly deploy — the same boundary that delivers the rest of
the client. Moving to an on-chain registry is part of the same
ciphernode-productionisation increment as threshold-OPRF rollout.

### 2.6 Performance budget

| Op                            | Target                |
| ----------------------------- | --------------------- |
| Citizen-side enrollment cost  | < 2 s end-to-end      |
| Ciphernode OPRF share         | < 50 ms               |
| Threshold combine             | < 100 ms              |
| Enrollment-tree append (gas)  | ≤ 100 k gas / append  |

For 1 M enrolled citizens at this gas budget, lifetime contract cost
is ~10¹¹ gas, ~10 ETH at Base mainnet prices — tractable.

## 3. Layer 2 — Signature

### 3.1 Goal

Citizen with `enrollment_secret` signs petition `id` such that:

- ZK proof shows `commit(s) ∈ enrollment_tree`;
- `nullifier = H(s, id, DOMAIN)` is fresh per petition, unique per
  citizen-per-petition, unlinkable across petitions;
- proof verifiable on-chain via the existing Noir → Solidity verifier
  pipeline.

### 3.2 Noir circuit shape

```noir
fn main(
    enrollment_secret:        Field,    // private  = s from §2.2
    merkle_path:              [Field; D], // private
    merkle_path_indices:      [Field; D], // private
    petition_id:              pub Field,
    enrollment_root:          pub Field,
    nullifier:                pub Field,
) {
    // `s` is itself the Merkle leaf — no extra pedersen([leaf]) wrapper.
    // This matches the re-pinning made on 2026-05-29 (see §2.2).
    let leaf = enrollment_secret;
    let recomputed_root = merkle_verify(leaf, merkle_path, merkle_path_indices);
    assert(recomputed_root == enrollment_root);

    let computed_null = pedersen_hash(
        [enrollment_secret, petition_id, DOMAIN_PETITION_V2], 0,
    );
    assert(computed_null == nullifier);
}
```

Public inputs: 3 (petition_id, enrollment_root, nullifier).
Private inputs: 1 + 2D fields.

### 3.3 Performance projection vs MVP

| Surface              | MVP circuit            | v2 circuit (this design) |
| -------------------- | ---------------------- | ------------------------ |
| Public inputs        | 15                     | 3                        |
| Constraint count     | ~10⁵ (CAdES + ECDSA)   | ~10³ (Merkle + 2 hashes) |
| Native prove time    | ~14.5 s                | ~1–2 s (projected)       |
| Browser prove time   | ~77 s                  | ~5–10 s (projected)      |
| Proof size           | 10,176 B               | ~10,000 B (constant)     |
| Verifier gas         | 4.24 M                 | ~3.5–3.8 M (projected)   |

**Crucially:** the slow path of MVP — CAdES `signedAttrs` walk, P-256
ECDSA verify, SPKI commit — is *entirely gone*. All the heavy lifting
moved to enrollment time, which is amortised once per citizen.

### 3.4 Storage of `enrollment_secret`

Primary: **WebAuthn PRF extension** (Passkey).

- At enrollment, the browser registers a discoverable credential bound
  to the v2 site's origin. The PRF extension derives a deterministic
  per-credential secret from a fixed salt — never leaves the
  authenticator. The OPRF output is *unwrapped* by this PRF-derived
  key and stored encrypted in IndexedDB.
- At signature time, browser asks the authenticator to evaluate the
  PRF, unwraps the OPRF output, computes the proof.
- Recovery: built-in. Apple Passwords / Google Password Manager sync
  the credential across devices via OS-level encrypted backup.
  Citizens don't see the seed.

Disaster-recovery backup: **BIP-39 mnemonic**, shown once at
enrollment.

- Mnemonic deterministically re-derives the same enrollment secret
  (HKDF over the seed). Citizen writes it down or saves to a password
  manager. Without this, a lost device + lost iCloud/Google account =
  lost identity.
- The mnemonic and the Passkey share the same downstream secret, so
  using either path produces the same on-chain commitment.

Browser support (target Q3 2026):

| Browser  | PRF | Sync           |
| -------- | --- | -------------- |
| Chrome   | ✓   | Google Pwd Mgr |
| Safari   | ✓   | iCloud Keychain|
| Firefox  | ✓   | Mozilla Sync   |
| Edge     | ✓   | Microsoft Pwd  |

Why **not** an EIP-1193 wallet here: requiring MetaMask / WalletConnect
for a national civic tool excludes the broader citizen base. Wallet
custody is an optional advanced path for crypto-natives; Passkey is
the default.

Why **not** plain localStorage: phishing-readable, lost on Ctrl-Shift-Del,
no syncable backup. Unacceptable for a civic-grade tool.

### 3.5 Recovery flows

| Scenario                                  | Recovery path                              |
| ----------------------------------------- | ------------------------------------------ |
| Lost phone, signed into Google/iCloud     | New device → Passkey syncs in              |
| Lost phone, no cloud sync                 | BIP-39 mnemonic → import to new device     |
| Lost phone, no mnemonic                   | Re-enroll under new commitment (the old commitment becomes inactive after K epochs; epoch transition is on-chain) |
| Compromised device (key stolen)           | Citizen revokes enrollment via signed revocation transaction; re-enrolls in next epoch |

The "re-enroll under new commitment" path **does not** reintroduce
the cert-renewal Sybil hole, because the OPRF is deterministic on
RNOKPP: a second enrollment for the same RNOKPP would collide with the
old commitment and be rejected. Recovery requires the ciphernode
committee to roll the old commitment forward into a successor
commitment, with attestation, under an epoch transition.

## 4. Layer 3 — Tally + threshold via FHE

### 4.1 Goal

Aggregate per-petition signatures (each carrying a 1-bit ciphertext
"I support / I oppose / abstain") under threshold-FHE such that:

- nobody, including the ciphernode committee, sees per-citizen votes;
- the committee can decrypt only the *threshold predicate* (e.g.
  "count > 25 000" → reveal `true`, "count ≤ 25 000" → reveal
  nothing else) and an opt-in aggregate count;
- per-petition unlinkability is preserved (nullifier blinds the
  signature, FHE blinds the vote).

### 4.2 Why FHE works here

This is the exact shape Vitalik's bar accepts:

- Per-signature ciphertext is 1 bit (or 2 bits for yes/no/abstain).
- The committee never runs arbitrary computation under FHE — only
  *additive aggregation* of bit ciphertexts and a final
  *comparison* against a public threshold.
- Both operations have efficient FHE primitives in BFV/CKKS schemes.
- Interfold (formerly Enclave) has already deployed this exact shape via CRISP — reusing their
  infrastructure, not inventing it.

### 4.3 Voting modes

| Mode                | Layer 2 output            | Layer 3 op             | Decryption        |
| ------------------- | ------------------------- | ---------------------- | ----------------- |
| Petition signature  | ZK proof + nullifier      | Counter ++             | Aggregate count   |
| Yes / no            | Above + Enc(0 or 1)       | Sum, compare to threshold | Threshold predicate |
| Yes / no / abstain  | Above + Enc(00 / 01 / 10) | Sum 2-bit, compare     | Threshold predicate |

Citizens choose the ballot mode at creation time (creator on
PetitionRegistry sets a `mode` flag).

### 4.4 Decryption events

- **Threshold-only**: ciphernode quorum publishes `true` / `false`
  for "did this petition cross threshold X?". Per-citizen votes are
  never decrypted. Default for sensitive issues.
- **Full count**: ciphernode quorum publishes the integer aggregate
  count. Default for public petitions where transparency matters more
  than per-issue privacy.
- **Never-decrypt**: signature exists, count is sealed forever. For
  truly secret straw polls.

Mode is selected by the petition creator and fixed at creation. Cannot
be upgraded mid-petition.

## 5. What this changes vs. MVP

| Property                          | MVP                       | v2.1                                      |
| --------------------------------- | ------------------------- | ----------------------------------------- |
| Diia QES at signature time        | required                  | not required (used once at enrollment)    |
| Browser-side prove time           | ~77 s                     | ~5–10 s (projected)                       |
| Cert-renewal Sybil resistance     | ✗ broken                  | ✓ closed (commitment = OPRF over RNOKPP)  |
| Cross-petition unlinkability      | ✓ per-petition            | ✓ per-petition                            |
| Coercion resistance               | ✗                         | ✗ (deferred to v2.2)                      |
| Tally privacy                     | ✗ (counts are public)     | ✓ optional threshold-only decryption      |
| Ballot modes                      | signature only            | signature / yes-no / yes-no-abstain       |
| Operator trust                    | none required             | t-of-n ciphernode honesty (typical 5-of-7) |
| Onboarding friction               | none (sign immediately)   | one-time enrollment (~ 2 s + Passkey reg) |

## 6. What this changes vs. spec § 6

| Original § 6 claim                                       | v2.1 refinement                                             |
| -------------------------------------------------------- | ----------------------------------------------------------- |
| "FHE-checked tax-ID uniqueness at enrollment"            | OPRF-checked uniqueness at enrollment                       |
| "Ciphernode committee runs FHE-PSI"                      | Ciphernode committee runs threshold OPRF + threshold-FHE tally |
| "Browser prove time inherited from MVP (~80 s)"          | Browser prove time drops to single-digit seconds            |
| "Diia QES required per signature"                        | Diia QES required **once** per citizen at enrollment        |
| "Cert renewal breaks Sybil"                              | Closed completely (commitment ≠ pubkey)                     |
| "CRISP integration: enrollment + tally"                  | CRISP integration: tally only                               |
| "JCJ fake-credentials branch from v2 day 1"              | JCJ deferred to v2.2                                        |

The original § 6 is preserved as historical context but should be
treated as superseded by this document for all design decisions from
2026-05-29 onward.

## 7. Out of scope for v2.1 — deferred to v2.2

> **v2.1 ships with a single-node OPRF service operated by the project
> team.** This is a deliberate scoping decision — the cryptographic
> interface (RFC 9497 2HashDH ristretto255-SHA512) is identical to the
> threshold variant, so the migration is a keygen ceremony + Shamir
> share storage at each ciphernode, with no wire-format changes for
> clients. Phase-3 productionisation (multi-operator ciphernode
> committee) is the follow-on grant ask. See §2.2 for the protocol
> sketch (which describes the threshold form already) and §2.5 for the
> service-key binding path from build-time pinning to on-chain registry.

- **Threshold OPRF productionisation**: keygen ceremony, Shamir share
  distribution to a 5-of-7 ciphernode committee, on-chain `K_pub`
  registry (§2.5 v2.2 row). The v2.1 protocol sketch in §2.2 already
  describes the threshold variant — v2.1 simply runs it with n=t=1.
- **JCJ fake-credentials coercion resistance**: citizen registers
  real + fake secrets; ciphernode FHE filters fakes at tally time. This
  is the most research-grade piece and lands as its own increment once
  v2.1 is in production.
- **Recursive proof composition** (RISC Zero wrapper around the Noir
  proof). Useful for tally proofs over many petitions; not load-bearing
  for v2.1.
- **Per-citizen reputation / weighted voting** based on prior
  participation. Layer atop the existing nullifier scheme.

## 8. Out of scope for v2 entirely — Phase 3

- Multi-QTSP / multi-country (RSA-PSS support in-circuit, per-country
  trust roots, eIDAS LOTL integration beyond Diia).
- Mobile native apps (browser PWA is the v2 target).
- Petition discovery / search / classification UI.
- DAO governance over ciphernode committee membership.

## 9. Phase-2 grant scope mapping

The Mindigital × Binance × Lviv IT Cluster × Web3 Institute grant
(Web3 Resilience Lab, $25 k cap, deadline 2026-05-31) is sized for
"validation of v2.1 architecture + ciphernode partnership"; full
production deployment is the follow-on Phase 2 grant ask.

Within the $25 k envelope, plausible deliverables:

| Deliverable                                                | Weeks |
| ---------------------------------------------------------- | ----- |
| Layer 2 circuit (Noir): enrollment Merkle + nullifier      | 2     |
| Layer 2 web SPA: Passkey enrollment + signature flow       | 3     |
| Layer 1 OPRF prototype (single-node, not threshold)        | 2     |
| Layer 3 stub: tally counter (no FHE yet, just transparent) | 1     |
| Integration testnet deployment on Base Sepolia             | 1     |
| Documentation + Interfold partnership scoping memo         | 1     |

Total: ~10 weeks of focused work for a 2-person student team.
Threshold-OPRF and FHE-tally are demonstrated as design but not
production-implemented within this grant.

### 9.1 Two committees, two cryptographic primitives — why this is the honest framing

The Phase-2 architecture splits across **two independent ciphernode
committees**, each running the production-ready primitive for its
specific job:

| Committee  | Primitive                                              | Operation                                                              | Status at grant ship                              | Operated by                              |
| ---------- | ------------------------------------------------------ | ---------------------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------- |
| Enrollment | threshold OPRF (2HashDH over ristretto255, RFC 9497)   | Set-membership uniqueness check on RNOKPP-derived commit               | Single-node demo at grant ship; threshold post-grant | This project (we run it)                |
| Tally      | threshold BFV-FHE (Interfold's existing E3 committee)  | Encrypted additive aggregation + threshold-predicate decryption        | Plug-in target; integration follows CRISP client SDK | Interfold (we are a downstream consumer) |

Both committees implement the same logical guarantee — *"no single
operator sees the citizen's private input"* — but using the primitive
that's actually production-ready for its specific operation. **OPRF is
not a fallback for FHE; it is the right tool for the enrollment job.**
The case:

- **Enrollment requires set-membership / collision checking over
  arbitrary scalar inputs.** Vitalik's mid-2026 framing of the
  threshold-FHE production envelope — quoted in §0 — explicitly
  excludes this shape. Forcing it through FHE-PSI either scales
  linearly per enrollment (untenable past ~10⁴ citizens) or pushes us
  into research-grade FHE-PSI protocols not yet in production at any
  committee.
- **OPRF (2HashDH) fits this shape natively.** Two scalar
  multiplications per share, a Lagrange combine, a hash — all sub-50
  ms operations at production scale. RFC 9497 is stable.
  Threshold-share over the OPRF key via Shamir is well-understood. The
  protocol *naturally* surfaces collisions: two enrollments for the
  same RNOKPP produce the same `F_k(RNOKPP)`, detected by
  ciphernode-quorum attestation (§2.3).
- **Tally is the operation FHE was built for, and Interfold has
  already deployed it via CRISP.** Per-petition signatures carry 1- or
  2-bit ciphertexts. Aggregation is additive. The output is a
  threshold predicate. This is the exact CRISP shape — we ride on
  Interfold's existing committee as a downstream consumer, not as a
  new infrastructure ask.

**The partnership ask to Interfold is therefore scoped and honest:**
we are a downstream consumer of their existing BFV tally committee for
Layer 3. We are *not* asking them to build us a new primitive, operate
our enrollment committee, or extend their stack. The integration
surface is their CRISP client SDK; the partnership memo (deliverable
in §9 above) is the scoping conversation, not an infrastructure build.

**OPRF → FHE migration** is captured as Phase-3 research: if and when
Interfold ships sub-second threshold-FHE equality checks at our
enrollment scale (production-ready FHE-PSI), the enrollment committee
could migrate from OPRF to FHE without any user-visible change. Until
then, OPRF is the production-deployable primitive, and v2.1 ships
behind it.

## 10. Open research questions

1. **OPRF choice**: 2HashDH (used here) vs. JKKX vs. SPRINT. 2HashDH
   is well-understood and easiest to threshold-share; SPRINT has
   better post-quantum properties.
2. **Enrollment-epoch length**: how often to rotate the OPRF key?
   Shorter epochs = better forward secrecy but more re-enrollment
   pain. Suggest 12 months for v2.1.
3. **Ciphernode committee bootstrapping**: how does the first
   committee get selected? Likely: Interfold's existing operator set
   plus 2–3 Ukrainian civic-tech orgs. Needs partnership memos.
4. **Passkey PRF salt management**: each origin needs a stable salt,
   but the salt should not be globally guessable. Recommend a per-user
   salt fetched on first registration.
5. **Recovery committee for lost mnemonic + lost Passkey + lost cloud
   account**: is there an out for citizens in this state? Probably yes,
   via re-enrollment with proof of Diia QES + waiting an epoch.

## 11. Status

- Draft: 2026-05-29.
- Reviewers needed: Interfold team (formerly Enclave) (for FHE-tally feasibility),
  Iryna Vovkotrub (for legal framing under Ukrainian data-protection
  law), independent crypto reviewer (for OPRF + Passkey-PRF
  composition).
- Next gate: Phase-2 grant proposal cites this document as the
  technical foundation for the funded scope.
