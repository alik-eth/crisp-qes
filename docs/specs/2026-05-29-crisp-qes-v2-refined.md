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
│ primitive: threshold-FHE (BFV / CKKS, CRISP/Enclave stack)  │
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
  return (i, Y_i)

citizen:
  collect ≥ t shares (Y_i)
  Y = LagrangeCombine({(i, Y_i)})                  (= k · M)
  N = r⁻¹ · Y                                      (= k · X = F_k(RNOKPP))
  commitment = Hash(N)
```

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

### 2.5 Performance budget

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
    enrollment_secret:        Field,    // private
    merkle_path:              [Field; D], // private
    merkle_path_indices:      [Field; D], // private
    petition_id:              pub Field,
    enrollment_root:          pub Field,
    nullifier:                pub Field,
) {
    let leaf = pedersen_hash([enrollment_secret]);
    let recomputed_root = merkle_verify(leaf, merkle_path, merkle_path_indices);
    assert(recomputed_root == enrollment_root);

    let computed_null = pedersen_hash([enrollment_secret, petition_id, DOMAIN_PETITION_V2]);
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
- CRISP / Enclave already deployed this exact shape — reusing their
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
| Documentation + Enclave partnership scoping memo           | 1     |

Total: ~10 weeks of focused work for a 2-person student team.
Threshold-OPRF and FHE-tally are demonstrated as design but not
production-implemented within this grant.

## 10. Open research questions

1. **OPRF choice**: 2HashDH (used here) vs. JKKX vs. SPRINT. 2HashDH
   is well-understood and easiest to threshold-share; SPRINT has
   better post-quantum properties.
2. **Enrollment-epoch length**: how often to rotate the OPRF key?
   Shorter epochs = better forward secrecy but more re-enrollment
   pain. Suggest 12 months for v2.1.
3. **Ciphernode committee bootstrapping**: how does the first
   committee get selected? Likely: Enclave's existing operator set
   plus 2–3 Ukrainian civic-tech orgs. Needs partnership memos.
4. **Passkey PRF salt management**: each origin needs a stable salt,
   but the salt should not be globally guessable. Recommend a per-user
   salt fetched on first registration.
5. **Recovery committee for lost mnemonic + lost Passkey + lost cloud
   account**: is there an out for citizens in this state? Probably yes,
   via re-enrollment with proof of Diia QES + waiting an epoch.

## 11. Status

- Draft: 2026-05-29.
- Reviewers needed: Enclave / CRISP team (for FHE-tally feasibility),
  Iryna Vovkotrub (for legal framing under Ukrainian data-protection
  law), independent crypto reviewer (for OPRF + Passkey-PRF
  composition).
- Next gate: Phase-2 grant proposal cites this document as the
  technical foundation for the funded scope.
