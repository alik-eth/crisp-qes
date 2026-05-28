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

This v2 design drops FHE from the enrollment path entirely and
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

Note: there is an implicit identity throughout this document —
`s ≡ commitment ≡ enrollment_secret` — all three names refer to the
same field element `s = pedersen([N_hi, N_lo], hashIndex=0)`. The
"enrollment_secret" name is used citizen-side, "commitment" is used
when referring to the on-chain Merkle leaf, "s" is used in the
protocol math; they are one value.

The threat surface differs materially between the **v2 single-node
demo** (what ships at grant time) and the **v3 threshold rollout**
(what the grant funds). The table below covers both; see §2.5 for the
single-node-specific brute-force exposure that the threshold variant
closes.

| Actor                                | Sees                                | Does not see              |
| ------------------------------------ | ----------------------------------- | ------------------------- |
| Ciphernode i (v3 threshold)        | blinded input `M`, Diia QES         | RNOKPP, commitment, `N`   |
| **OPRF service (v2 single-node)**  | **`M`, Diia QES, `N`, `commitment`, `k`** | **RNOKPP (but see §2.5: brute-forceable from `N` + `k`)** |
| Threshold (≥t, v3)                 | Aggregate count, collision evidence | RNOKPP                    |
| On-chain                             | `commitment`, `enrollment_root`     | RNOKPP, Diia cert, mapping commitment ↔ citizen |
| Citizen                              | own `enrollment_secret`             | k, k_i, others' RNOKPPs   |
| Eavesdropper                         | OPRF transcript                     | Anything plaintext        |

### 2.5 Service-key binding (defence against MITM substitution)

The DLEQ proof from §2.2 binds the returned `Y` to the same `k` that
produced the service's published `K_pub` — but only if the client
verifies against a `K_pub` it trusts. A MITM attacker who can swap
`K_pub` *and* `Y` for a pair derived from their own `k*` would pass
DLEQ verification while learning a per-citizen `N` they can correlate
later. Pinning `K_pub` to an authoritative source closes this.

| Variant | Binding mechanism | Trust anchor |
| ------- | ----------------- | ------------ |
| **v2 (shipped)** | `K_pub` is **build-time-pinned** in the `v2-web` bundle via the `VITE_OPRF_PUBKEY` env var; client hard-fails on `/healthz` mismatch. | The Fly deployment (same TLS + COOP/COEP boundary as the rest of the SPA). |
| **v3 (v3)** | `K_pub` (and `K_pub,i` for the threshold variant) moves on-chain into `EnrollmentRegistry` as an admin-settable storage slot. Client reads it from the contract at boot. | The contract admin key, eventually a DAO multisig as the ciphernode committee onboards independent operators. |

Bundle-pinning is the right v2 answer because the trust anchor is
already the Fly deploy — the same boundary that delivers the rest of
the client. Moving to an on-chain registry is part of the same
ciphernode-productionisation increment as threshold-OPRF rollout.

#### 2.5.1 v2 single-node brute-force exposure (honest disclosure)

The shipping v2 demo runs a **single** OPRF node — that node holds
`k` directly (no Shamir share), and the `/oprf/register` endpoint
accepts the unblinded OPRF output `N` from the citizen so the service
can sanity-check `s = pedersen([N_hi, N_lo], 0)` before appending to
the enrollment tree. The check defends against rogue clients posting
arbitrary tree leaves, but it has a real privacy cost:

> A malicious single-node operator who holds `k` and observes `N`
> can recover the citizen's RNOKPP by offline brute force.
> `N = k · Hash_to_curve(RNOKPP)`; the operator enumerates the
> ~10¹⁰ RNOKPP space, computes `k · Hash_to_curve(candidate)` for
> each, and matches against stored `N`. On commodity GPU hardware
> this is hours-to-days for the full UA citizen base, and fully
> parallelisable.

**This exposure is intrinsic to single-node OPRF, not a defect of
the v2 implementation.** It is the reason v3 ships threshold-OPRF
with `k` distributed as Shamir shares across a 5-of-7 ciphernode
committee — no single operator ever holds `k`, so no single operator
can run the brute-force. The grant scope (§9) funds exactly this
transition.

Operational mitigations in the v2 demo window:

- the OPRF service is operated by the project team only, on a single
  Fly app, with no third-party access to `k`;
- the service is explicitly framed in the README and proposal as a
  **demo of the protocol**, not a production deployment;
- pilot deployments before v3 ships SHOULD restrict `/oprf/register`
  to a closed cohort and disclose this property to participants.

#### 2.5.2 v3 architectural fix (preferred, deferred)

The cleaner long-term fix is to **drop `N` from the `/oprf/register`
payload entirely** and replace the server-side `s = pedersen([N_hi,
N_lo], 0)` consistency check with a **citizen-side ZK proof** that
`s` is consistent with the OPRF transcript `(M, Y, K_pub)` — i.e. that
the citizen knows an `N` such that `M = N · h(RNOKPP)⁻¹ · G`,
`Y = k · M` (verified by DLEQ), and `s = pedersen([N_hi, N_lo], 0)`,
without revealing `N`. Combined with threshold-OPRF, this gives a
service that learns **only** `(M, Diia QES, s)` — never `N`, never
`k` in the clear. Scoped for v3 alongside threshold rollout.

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

### 3.3 Performance

| Surface              | v2 circuit                            |
| -------------------- | ------------------------------------- |
| Public inputs        | 3                                     |
| Constraint count     | ~10³ (Merkle + 2 hashes)              |
| Native prove time    | ~1–2 s (measured: 823 ms on commodity hardware) |
| Browser prove time   | ~5–10 s (projected)                   |
| Proof size           | ~10,000 B (constant)                  |
| Verifier gas         | ~3.5–3.8 M (projected)                |

All heavy verification (Diia QES validation, RNOKPP attestation,
CAdES walk, P-256 ECDSA) happens at enrollment time and is amortised
once per citizen identity. Per-signature cost is purely the Merkle +
nullifier proof.

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

Disaster-recovery backup: **none — mnemonic deleted.** Earlier v2
drafts shipped a non-functional BIP-39 mnemonic backup placeholder.
It has been removed from the UI and the codebase. The structural
reason: `s = pedersen([N_hi, N_lo], 0)` where `N = k ·
Hash_to_curve(RNOKPP)` is the OPRF output, and any mnemonic-based
representation of `N` either fails structurally (HKDF is one-way) or
fails as a UX recovery primitive for civic-tech users (sub-30%
write-down/recall rate, becomes a non-rotatable bearer credential).
See `/tmp/recovery-design.md` for the full analysis.

**v2 recovery: three tiers, all client-side, zero protocol change.**

#### Tier 1 — Cloud-synced Passkey (primary)

Apple iCloud Keychain / Google Password Manager / Mozilla Sync
back up the discoverable credential (including its PRF capability)
across devices signed into the same account. Covers the ~80% case
where a citizen loses one device but is signed in elsewhere. Already
shipping; not changed.

#### Tier 2 — Multi-Passkey enrollment ceremony (secondary)

At enrollment, after the first Passkey is created and the on-chain
commitment lands, the UI prompts the citizen to register a second
device (laptop biometric, USB security key, or another phone). The
same `N` is wrapped under the second Passkey's PRF output and stored
as an additional `EnrollmentRecord` row in IndexedDB. The store
schema in `packages/web/src/lib/encryptedStore.ts` already supports
multiple rows per citizen. Optional skip with disclosure.

#### Tier 3 — QES-anchored recovery (tertiary)

If a citizen lands on a fresh device with no Passkey and no cloud
sync, but still has Diia QES, they enter the recovery flow:

1. Citizen completes the QES verification (download binding → Diia
   sign → upload `.p7s`), same shape as enrollment.
2. Client runs `/oprf/blind-eval` with fresh blinding `r'` over
   RNOKPP. *(Critical: blind-eval only — never `/oprf/register`,
   which has a uniqueness check.)*
3. Client unblinds the response to `N`. By OPRF determinism, this
   is the **same** `N` as the original enrollment: same `RNOKPP` +
   same `k` → same `N`, regardless of fresh blinding.
4. Client computes `s = pedersen([N_hi, N_lo], 0)`.
5. Client queries `EnrollmentRegistry` events for the matching `s`
   to find the leaf index.
6. Client rebuilds the Merkle path from on-chain leaves.
7. Client creates a new Passkey on the new device, wraps the
   recovered `N` + Merkle path under it, stores in IndexedDB.

The OPRF service operator sees a `blind-eval` call indistinguishable
from any other. No service change, no contract change.

#### Recovery floor

Triple-loss (no Passkey, no cloud sync, no Diia QES) in v2 has no
recovery path within the v2 epoch. The citizen waits for the v3
epoch transition to re-enroll with a fresh / re-issued Diia QES
(v3 spec §6 epoch-rotated enrollment). This is the same floor as
any QES-anchored civic-identity system — the system inherits the
state's ID-recovery process as its ultimate floor.

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

| Loss scenario                                       | v2 recovery path                                                 |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| Lost phone, signed into iCloud / Google             | Passkey syncs in on next device (Tier 1)                         |
| Lost phone, has a secondary registered Passkey      | Secondary Passkey unwraps `N` from IndexedDB (Tier 2)            |
| Lost all Passkeys, has Diia QES                     | QES-anchored recovery: fresh `/oprf/blind-eval` → re-derive `N` (Tier 3) |
| Lost all Passkeys, lost Diia, can re-issue Diia     | Re-issue Diia via state recovery channels → Tier 3 recovery       |
| Triple-loss with no Diia recourse                   | Wait for v3 epoch rotation (§v3 spec §6) — re-enroll under fresh QES next epoch |
| Compromised device (key stolen)                     | Citizen revokes enrollment via signed revocation; re-enrolls in next epoch |

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

## 5. v2 properties

| Property                          | v2                                          |
| --------------------------------- | ------------------------------------------- |
| Diia QES at signature time        | not required (used once at enrollment)      |
| Browser-side prove time           | ~5–10 s (projected; ~823 ms native measured) |
| Cert-renewal Sybil resistance     | ✓ closed (commitment = OPRF over RNOKPP)    |
| Cross-petition unlinkability      | ✓ per-petition                              |
| Coercion resistance               | ✗ (deferred to v3)                          |
| Tally privacy                     | ✓ optional threshold-only decryption        |
| Ballot modes                      | signature / yes-no / yes-no-abstain         |
| Operator trust                    | t-of-n ciphernode honesty (typical 5-of-7; single-node in v2 demo, threshold in v3) |
| Onboarding friction               | one-time enrollment (~ 2 s + Passkey reg)   |

## 6. What this changes vs. spec § 6

| Original § 6 claim                                       | v2 refinement                                             |
| -------------------------------------------------------- | ----------------------------------------------------------- |
| "FHE-checked tax-ID uniqueness at enrollment"            | OPRF-checked uniqueness at enrollment                       |
| "Ciphernode committee runs FHE-PSI"                      | Ciphernode committee runs threshold OPRF + threshold-FHE tally |
| "Browser prove time inherited from earlier circuit"      | Browser prove time drops to single-digit seconds (new minimal-circuit shape) |
| "Diia QES required per signature"                        | Diia QES required **once** per citizen at enrollment        |
| "Cert renewal breaks Sybil"                              | Closed completely (commitment ≠ pubkey)                     |
| "CRISP integration: enrollment + tally"                  | CRISP integration: tally only                               |
| "JCJ fake-credentials branch from v2 day 1"              | JCJ deferred to v3                                        |

The original § 6 is preserved as historical context but should be
treated as superseded by this document for all design decisions from
2026-05-29 onward.

## 7. Out of scope for v2 — deferred to v3

> **v2 ships with a single-node OPRF service operated by the project
> team.** This is a deliberate scoping decision — the cryptographic
> interface (RFC 9497 2HashDH ristretto255-SHA512) is identical to the
> threshold variant, so the migration is a keygen ceremony + Shamir
> share storage at each ciphernode, with no wire-format changes for
> clients. v3 productionisation (multi-operator ciphernode
> committee) is the follow-on grant ask. See §2.2 for the protocol
> sketch (which describes the threshold form already) and §2.5 for the
> service-key binding path from build-time pinning to on-chain registry.

- **Threshold OPRF productionisation**: keygen ceremony, Shamir share
  distribution to a 5-of-7 ciphernode committee, on-chain `K_pub`
  registry (§2.5 v3 row). The v2 protocol sketch in §2.2 already
  describes the threshold variant — v2 simply runs it with n=t=1.
- **JCJ fake-credentials coercion resistance**: citizen registers
  real + fake secrets; ciphernode FHE filters fakes at tally time. This
  is the most research-grade piece and lands as its own increment once
  v2 is in production.
- **Recursive proof composition** (RISC Zero wrapper around the Noir
  proof). Useful for tally proofs over many petitions; not load-bearing
  for v2.
- **Per-citizen reputation / weighted voting** based on prior
  participation. Layer atop the existing nullifier scheme.

## 8. Out of scope for v2 entirely — v3

- Multi-QTSP / multi-country (RSA-PSS support in-circuit, per-country
  trust roots, eIDAS LOTL integration beyond Diia).
- Mobile native apps (browser PWA is the v2 target).
- Petition discovery / search / classification UI.
- DAO governance over ciphernode committee membership.

## 9. v3 grant scope mapping

The Mindigital × Binance × Lviv IT Cluster × Web3 Institute grant
(Web3 Resilience Lab, $25 k cap, deadline 2026-05-31) is sized for
"validation of v2 architecture + ciphernode partnership"; full
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

The v3 architecture splits across **two independent ciphernode
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

**OPRF → FHE migration** is captured as v3 research: if and when
Interfold ships sub-second threshold-FHE equality checks at our
enrollment scale (production-ready FHE-PSI), the enrollment committee
could migrate from OPRF to FHE without any user-visible change. Until
then, OPRF is the production-deployable primitive, and v2 ships
behind it.

## 10. Open research questions

1. **OPRF choice**: 2HashDH (used here) vs. JKKX vs. SPRINT. 2HashDH
   is well-understood and easiest to threshold-share; SPRINT has
   better post-quantum properties.
2. **Enrollment-epoch length**: how often to rotate the OPRF key?
   Shorter epochs = better forward secrecy but more re-enrollment
   pain. Suggest 12 months for v2.
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
- Next gate: v3 grant proposal cites this document as the
  technical foundation for the funded scope.
