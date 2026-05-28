# CRISP-QES v3 — funded scope

Status: design draft. Follow-on to `docs/specs/2026-05-29-crisp-qes-v2-refined.md` (spec commit `2261714`).
Owner: Oleksandr Vovkotrub. Reviewers: TBD.

## 0. Why v3

v2 is live end-to-end on Base Sepolia: live demo signature
`0xc80557d7c25c9c5b8ae4b770d4eda8690566092bd412d33e372a69526ec42dfb`,
~823 ms native prove, full stack on Fly (`crisp-qes-v2-web.fly.dev`,
`crisp-qes-v2-oprf.fly.dev`, `crisp-qes-v2-relayer.fly.dev`),
contracts on Base Sepolia.

v2 ships with honest, documented limitations:

- **Single-node OPRF** — the service operator can brute-force the
  RNOKPP space offline from `N + k` (spec v2 §2.5.1).
- **Mnemonic recovery inactive** — `HKDF(N)` is one-way; mnemonic
  alone can't re-derive `s` (spec v2 §3.4).
- **K_pub bundle-pinned, not on-chain** — trust anchor is the Fly
  deployment, not a contract (spec v2 §2.5 v2 row).
- **`/oprf/register` accepts unblinded `N`** — needed for the
  server-side consistency check; widens the brute-force surface
  (spec v2 §2.5.2).
- **UA-only, Diia-only** — single QTSP, single country, no age tier.

v3 is the production-hardening + reach-expansion increment that
closes each of those. This document is the funded scope.

## 1. Architecture deltas at a glance

| Increment                                  | Closes                                 | Spec §  |
| ------------------------------------------ | -------------------------------------- | ------- |
| Threshold OPRF (5-of-7 ciphernode)         | Single-node brute-force exposure       | §2      |
| Mnemonic activation                        | Inactive recovery path                 | §3      |
| On-chain `K_pub` registry                  | Bundle-pinning trust anchor            | §4      |
| `/oprf/register` ZK consistency proof      | Unblinded `N` on the wire              | §5      |
| Epoch-rotated enrollment                   | Tree-size unbounded, no GC, cert revocation propagation | §6 |
| Multi-QTSP (within UA)                     | Diia-only restriction                  | §7      |
| Multi-country (eIDAS expansion)            | UA-only restriction                    | §8      |
| Age verification                           | No age-gated petitions                 | §9      |

§ 10 covers sequencing + milestone gating. § 11 lists open research
questions held over to a hypothetical v4.

## 2. Threshold OPRF

### 2.1 Goal

No single operator ever holds the OPRF key `k`. The brute-force
attack disclosed in spec v2 §2.5.1 becomes structurally impossible:
deanonymisation requires colluding `t` of `n` ciphernode operators.

### 2.2 Mechanism

Standard threshold OPRF over Ristretto255 (RFC 9497 + Shamir over
the scalar field of the prime-order group):

- **Key generation:** distributed key generation (DKG) over the
  committee. Pedersen DKG (Gennaro–Jarecki–Krawczyk–Rabin) for
  robustness against a malicious minority. Each ciphernode `i`
  ends with a Shamir share `k_i`; the implicit secret is the
  Lagrange-interpolated `k`. Public commitment `K_pub = k · G` is
  derivable from the polynomial commitments without ever
  materialising `k`.
- **OPRF evaluation (per enrollment):** citizen sends blinded
  input `M` to each ciphernode; ciphernode `i` computes
  `Y_i = k_i · M` and a DLEQ proof binding `Y_i` to the published
  `K_pub,i = k_i · G`; citizen verifies each `π_i`, collects ≥ `t`
  valid shares, Lagrange-combines to `Y = k · M`, unblinds to `N`.
- **Audit + revocation:** committee membership is on-chain
  (§4 on-chain `K_pub` registry); revocation = remove the
  `K_pub,i` from the registry, citizens re-quorum without the
  removed share. Honest committee can replace a misbehaving
  operator without forcing all citizens to re-enroll (the OPRF
  output `Y` is the same as long as the threshold `t` is met).

### 2.3 Parameters

- Initial committee: `n = 7`, `t = 5` (majority honest assumption,
  one-fault tolerance after replacement).
- Share refresh cadence: yearly (composes with §6 epoch rotation).
- Each share lives in a hardened operator-side enclave (HSM or TEE)
  with a signed audit log of all share uses.

### 2.4 Engineering scope

- New `packages/v3-oprf-node/` — single ciphernode binary.
  Fastify endpoints same shape as v2 (`/oprf/blind-eval`,
  `/oprf/register`) but returns its own `Y_i + π_i` not a combined
  `Y`.
- New `packages/v3-oprf-combiner/` (citizen-side library) —
  shares `Y_i` collection + Lagrange combine + multi-DLEQ
  verification. Folded into `packages/v3-web/`.
- New `packages/v3-dkg/` — DKG ceremony tooling for committee
  bootstrap + share-refresh. CLI-driven, non-interactive on the
  network (each operator runs the binary, exchanges commitments,
  outputs their share).
- Contract change: `EnrollmentRegistry` admin slot becomes a
  multi-key slot (one `K_pub,i` per ciphernode), with an
  on-chain attester role per ciphernode. §4 below.

### 2.5 Costs + risks

- Citizen-side enrollment latency: ~`n` parallel HTTPs +
  `n` DLEQ verifications + 1 Lagrange combine.
  Conservatively ~500 ms total over a healthy WAN. Fine.
- Committee bootstrap: one DKG ceremony per `k` (yearly with
  §6). Ceremony is the critical-trust event of v3 — every
  committee member must run the binary in their own
  environment, no shared infrastructure.
- Failure mode: a colluding `t`-subset can re-execute the
  brute-force attack. Mitigation = diverse committee
  jurisdiction + reputation + on-chain slashing if misbehaviour
  is provable.

## 3. Recovery design (v3)

### 3.1 Goal

Zero-friction recovery for a fresh device, no mnemonic, no
auxiliary secret material. Citizen with a valid Diia QES can always
recover their identity; multi-device redundancy is offered at
enrollment as a proactive option.

### 3.2 The structural insight

The system has exactly one durable secret per citizen:
`N = k · Hash_to_curve(RNOKPP)`. By OPRF determinism, the same
`RNOKPP` (asserted via fresh Diia QES) and the same `k` (held by
the ciphernode quorum) always produce the same `N` — regardless of
fresh blinding `r'`. So recovery doesn't need a separate
secret-material layer; it leans on the QES anchor + OPRF
determinism that the protocol already provides.

Earlier drafts of this section proposed a BIP-39 mnemonic recovery
path (Path A "mnemonic 2FA" + Path B "raw N encoded in mnemonic").
Both were dropped after design review. The mnemonic was solving a
problem the QES already solves, and Path B specifically introduced
a non-rotatable bearer credential with sub-30% civic-tech recall
rates. See [[recovery-design-memo]] at `/tmp/recovery-design.md`
for the full analysis, or v3 spec §11 for the postmortem.

### 3.3 QES-anchored quorum re-derivation (tertiary recovery)

The v3 version of v2 spec §3.4 Tier 3, with the threshold quorum
in place of the single-node:

1. Citizen completes Diia QES verification on a fresh device.
2. Client runs `/oprf/blind-eval` against ≥ `t` of `n` ciphernodes
   with fresh blinding `r'`.
3. Each ciphernode returns `Y_i` + DLEQ proof `π_i`.
4. Client Lagrange-combines + unblinds to `N` — same `N` as the
   citizen's original enrollment.
5. Client computes `s = pedersen([N_hi, N_lo], 0)`, queries
   `EnrollmentRegistry` events for the leaf index, rebuilds the
   Merkle path.
6. Client creates a new Passkey on the new device, wraps `N` +
   Merkle path under it, stores in IndexedDB.

**Protocol change vs v3 §2:** none beyond what the threshold-OPRF
spec already provides. Recovery uses the same `/oprf/blind-eval`
endpoint as enrollment; ciphernodes can't distinguish.

### 3.4 Multi-Passkey ceremony (secondary recovery)

Carry forward from v2 spec §3.4 Tier 2: at enrollment, after the
first Passkey is created and the on-chain commitment lands, prompt
the citizen to register a second device. The same `N` is wrapped
under the second Passkey's PRF output as an additional
`EnrollmentRecord` row.

Already supported by the v2 `encryptedStore` schema; no v3 protocol
change required.

### 3.5 Engineering scope

- **Citizen-side recovery flow** in `packages/web/` (post v2 → v3
  evolution): repurpose the v2 `Recover.tsx` flow to use the
  threshold quorum instead of single-node OPRF. Existing client-side
  components (binding, upload, blind-eval) are reusable.
- **No new contract.** The `RecoveryRegistry` proposed in earlier
  drafts is dropped — there is no on-chain mnemonic commitment to
  store.
- **No new ciphernode endpoint.** `/oprf/blind-eval` already supports
  recovery (any citizen with a valid QES can call it; the share
  it returns is determined by the citizen's RNOKPP).

### 3.6 Recovery floor: §6 epoch rotation

If a citizen loses **everything** — all Passkeys, all cloud accounts,
and the underlying Diia identity (rare: permanent state-credential
loss with re-issuance under a new RNOKPP) — the recovery path is
the next epoch transition: re-enroll under fresh Diia QES, new
`s_year` issued, old leaf orphaned. See §6 for the epoch rotation
mechanism.

This is the natural recovery floor of any QES-anchored civic-identity
system and needs no extra protocol mechanism.

## 4. On-chain `K_pub` registry

### 4.1 Goal

MITM-substitution defence (v2 §2.5) moves from "trust the Fly
deploy" to "trust the EnrollmentRegistry admin slot, eventually
a DAO multisig."

### 4.2 Mechanism

Extend `EnrollmentRegistry`:

```solidity
mapping(uint8 => bytes32) public ciphernodePubKey;     // K_pub,i per node
uint8 public threshold;                                 // = t
uint8 public quorumSize;                                // = n

function setCiphernode(uint8 idx, bytes32 kPubI) external onlyAdmin;
function removeCiphernode(uint8 idx) external onlyAdmin;
function setThresholdParams(uint8 t, uint8 n) external onlyAdmin;
```

Client reads the registry at boot; if `K_pub,i` mismatches what
a ciphernode advertises in `/healthz`, client hard-fails before
ever sending `M`. DLEQ verification then closes the loop.

### 4.3 Admin transition

- v3 ship-day: admin = single project key (same as v2's
  `attesterAddr`).
- v3 + 6 months: admin transitions to 3-of-5 multisig (project
  team + Iryna + 2 independent reviewers).
- v3 + 12 months: admin transitions to ciphernode-committee
  DAO multisig (one signer per ciphernode operator).

Each transition is on-chain + auditable.

## 5. `/oprf/register` consistency ZK proof

### 5.1 Goal

Drop `N` (and any other unblinded value) from the wire to the
ciphernode service. The server-side sanity check
`s = pedersen([N_hi, N_lo], 0)` becomes a citizen-side ZK
attestation that doesn't reveal `N`.

### 5.2 Proof statement

Citizen proves, with public inputs `(M, K_pub, s)`:

> "I know `r`, `N` such that:
>   - `M = r · Hash_to_curve(RNOKPP)`  (blinding correctness, with private RNOKPP)
>   - `Y = k · M` is a valid OPRF output for `K_pub` (witnessed by the DLEQ proof, public)
>   - `N = r⁻¹ · Y`
>   - `s = pedersen([N_hi, N_lo], 0)`"

`RNOKPP` and `N` are private. `M`, `K_pub`, `s` are public.

### 5.3 Circuit shape

Noir, similar to v2 signature circuit but with Ristretto255
arithmetic. Open question: Ristretto255 in Noir is not a
first-class primitive — needs either an embedded-curve approach
(if proof of `M` correctness can be done over a related curve)
or accept the cost of in-circuit Ristretto255 (~10⁴ constraints).

Likely ~10⁵ constraint count, browser prove time ~10–30 s.
Acceptable as a one-time enrollment cost.

### 5.4 Engineering scope

- New circuit `packages/v3-enroll-circuit/`.
- Update OPRF service: replace `s = pedersen(N)` check with proof
  verification.
- Wire ABI change for `/oprf/register`: send `{commitment,
  enrollProof, dleqProofs[]}`, no `unblindedOutput`.

## 6. Epoch-rotated enrollment

### 6.1 Goal

The `EnrollmentRegistry` Merkle tree grows unbounded; over a
multi-year deployment it would hit Solidity/EVM gas + storage
practical limits. Also: certificate revocation in QTSP land
doesn't propagate automatically — a revoked Diia cert remains
"enrolled" forever in v2.

Both close cleanly with time-based mass key rotation.

### 6.2 Mechanism

- OPRF key rotates yearly: `k_2026, k_2027, ...`.
- Each year has its own enrollment tree
  `EnrollmentRegistry_year`, derived from `k_year`.
- Petitions tag the epoch they belong to (`epoch_id` in petition
  creation); signatures must use enrollment from the matching
  epoch.
- Old epoch trees become read-only after a grace period
  (epoch-K petitions close), eventually sunsetted from the active
  query path.
- Citizen re-enrolls yearly via fresh Diia QES → new `s_year` per
  epoch. Cross-epoch unlinkability becomes a *feature* (no
  reidentification across years).
- Revoked Diia certs naturally drop out at the next epoch.

### 6.3 Why this fits

| Solves                                | Mechanism                          |
| ------------------------------------- | ---------------------------------- |
| Triple-loss recovery                  | Next epoch = fresh start, by design |
| Tree size bound                       | Each epoch ~ UA adult pop (~30 M)  |
| Cert-revocation propagation           | Yearly re-credentialing            |
| Cross-epoch unlinkability             | New `k_year` → new `s_year`        |
| Threshold-OPRF rotation cadence       | Same as §2 share refresh           |
| Legal alignment (UA)                  | Maps onto passport (10 yr) / DL (5 yr) / voter rolls (per-election) |

### 6.4 Honest tradeoffs

- Active citizens re-enroll yearly (~2 s + Passkey reauth).
  Friction is real but matches lived experience of state
  re-credentialing.
- Mid-epoch petitions need an "epoch of creation" tag + a
  grace-window resolution rule (which signatures count after a
  year-boundary).
- Migration: v3 launches with epoch_2026. Pilot deployments
  before then run epoch_pilot.

### 6.5 Engineering scope

- Contract change: `EnrollmentRegistry` becomes
  `EnrollmentRegistry_{year}`, deployed per epoch. Or single
  contract with `mapping(uint16 => Root) rootByEpoch`.
- `PetitionRegistryV2` extends to carry `epoch_id`.
- DKG ceremony per epoch (§2.4): scheduled, ritualised, multi-party.
- Citizen-side flow has a "re-enroll for new epoch" UI surfaced
  proactively (the year before epoch_K closes, prompt to enroll
  for epoch_K+1).

## 7. Multi-QTSP within Ukraine

### 7.1 Goal

Accept QES from any Ukraine-qualified trust service provider, not
just Diia. v2 OPRF over RNOKPP already abstracts over the cert
issuer — same RNOKPP signed by Diia / Privatbank / Oschadbank /
Ukrsign / etc. produces the same commitment `s`.

### 7.2 What's actually needed

The cryptography is already QTSP-agnostic. The remaining work is
trust + parsing:

- **Trust manifest extension.** `packages/v3-trust/` (or extend
  v2's `trust/` package) maintains the canonical list of
  UA-qualified QTSP root + intermediate certs. Synced from the
  Ministry of Digital Transformation's published trust list.
- **CAdES parser flexibility.** Each QTSP's `signedAttrs` layout
  has small structural differences (extension OIDs, attribute
  ordering, optional signed timestamps). Cert parser becomes a
  per-provider strategy: detect issuer DN, pick the right
  signedAttrs walker.
- **Provider attribution at enrollment (off-chain, audit only).**
  Ciphernode logs which QTSP issued the source cert per
  enrollment, for compliance audit. Never goes on-chain — that
  would be a privacy regression.

### 7.3 Engineering scope

- ~1 week. Cheapest of the v3 increments.
- Code: trust manifest update, CAdES parser strategy registry,
  test fixtures from each major UA QTSP.

### 7.4 Open question

Multi-QTSP plus cert revocation: if a QTSP-issued cert is
revoked mid-epoch, the enrolled `s` persists (§6's epoch rotation
addresses propagation but only at the year boundary). For
intra-epoch revocation, an optional "revoke this `s`" endpoint
could let the ciphernode committee remove a leaf with proof of
revocation. Deferred to v3.1 if needed.

## 8. Multi-country (eIDAS expansion)

### 8.1 Goal

Same protocol, applied to non-UA citizens with eIDAS-qualified
QES. Each country has its own enrollment tree + domain separator.

### 8.2 Per-country adaptation

For each country `C`:

- **Persistent identifier choice.** UA uses RNOKPP. Others vary:
  EE uses isikukood (deterministic, lifetime-stable); PL uses
  PESEL (similar); DE has Steuer-ID (tax) and Personalausweis
  number (national ID); FR uses NIR (social security). Pick the
  most stable + universally-issued ID per country. Document the
  choice + its assumptions per-country.
- **Cert format.** Most EU/EEA QES are CAdES, but some are
  PAdES; signed-attribute locations differ. Reuse the §7
  per-provider strategy pattern, broadened to per-country.
- **Trust roots.** Each country's qualified-providers list is
  published on the EU LOTL (List of Trusted Lists). Trust
  manifest pulls from LOTL per country.
- **Domain separator.** Per-country tag in the nullifier +
  enrollment hash: `DOMAIN_C = sha256("crisp-qes-v3-" || ISO3166_C)`.
  Prevents cross-country Sybil-bypass (re-enrolling in country B
  to bypass country A's uniqueness check) while keeping the
  protocol math identical.

### 8.3 One global tree, or one tree per country?

Two options:

- **Per-country trees.** Default. Each country runs its own
  enrollment tree + ciphernode committee. Cross-country petitions
  aggregate over multiple trees, with separate Sybil checks per
  country. Honest separation of trust + jurisdiction.
- **Global tree.** One tree, all countries. Petitions specify
  eligibility predicate ("EU citizens", "OECD members",
  whatever). Sybil resistance requires global identifier
  uniqueness — but no global ID exists. Doesn't work.

→ Per-country trees. Cross-country aggregation happens at the
petition layer, not the enrollment layer.

### 8.4 Engineering scope

Per-country adaptation: ~1 week per country once the §7
multi-QTSP framework is in place. Bootstrap target countries:

- Phase 8.1: UA (already done v2)
- Phase 8.2: EE (smallest, well-documented eID, fastest pilot)
- Phase 8.3: PL (largest UA-adjacent neighbour)
- Phase 8.4: DE (largest EU economy)

eIDAS regulatory framework covers all of the above. The legal
research for §8 maps onto Iryna's dissertation area.

### 8.5 Trust + governance

Each country's enrollment-tree-admin admin slot should ideally
sit with a local civic-tech org or DAO multisig of trusted
in-country reviewers. v3 ship-day: project team operates all
country admin slots in parallel; transition to local
admin within 12 months of each country's launch.

## 9. Age verification

### 9.1 Goal

Petitions can require `age ≥ N` (typical: 16, 18, 21). Citizen
proves age threshold without revealing date of birth.

### 9.2 Where DOB lives in the cert

UA Diia QES: DOB is encoded in the subject DN. The exact field is
in the same OID family as RNOKPP — needs an in-line verification
pass (the parser already touches that region of the cert).
Investigation deliverable: confirm the exact OID + canonical form
(YYYYMMDD ASCII vs DER GeneralizedTime).

Other countries: varies. EE isikukood encodes DOB in the
identifier itself (positions 2-7 of the 11-digit code). PL PESEL
similar. DE Steuer-ID does NOT encode DOB. Each country's age
verification approach depends on whether DOB is in the cert.

### 9.3 Design shapes

#### 9.3.1 Enrollment-time age proof (recommended default)

At enrollment, citizen proves in ZK: "I know a DOB in the signed
Diia cert such that `dob_year + N ≤ current_year`". Output:
membership in an age-tier enrollment tree, e.g.
`EnrollmentTree_adults` (age ≥ 18) vs `EnrollmentTree_voters`
(age ≥ 18 with citizenship attestation).

Petition creator picks an age tier at creation. Signature proof
shows membership in the matching tier.

- ✓ Cheap per-signature (no per-petition age proof)
- ✓ Citizen pays the age proof cost once
- ✗ Only supports a small fixed set of age tiers
- ✗ Adding a new tier (e.g. 21) requires re-enrollment for that
  tier

#### 9.3.2 Per-signature age proof

At signature time, circuit includes a per-petition age threshold
check: "I know DOB such that `dob + N ≤ now`" where `N` is the
petition's age threshold (public input).

- ✓ Arbitrary age thresholds per petition
- ✗ More expensive per-signature (extra range proof)
- ✗ Requires DOB to be re-introduced into the signing circuit as
  a private input

#### 9.3.3 Hybrid

Enrollment binds the citizen's DOB as a private commitment
`pedersen(DOB)`; per-signature proof references that commitment
and proves the threshold without re-revealing DOB. Modest
per-signature cost increase; arbitrary thresholds.

→ Hybrid is the right v3 default. Ship enrollment-time tiers
first (cheaper engineering, covers 95% case), add per-signature
flexibility in v3.1 if needed.

### 9.4 Engineering scope

- Extend enrollment circuit (`packages/v3-enroll-circuit/` from
  §5) to optionally output `pedersen(DOB)` as a public input.
- Extend signature circuit
  (`packages/v3-circuit/`) to optionally take an age-threshold
  public input + DOB-commitment private input.
- Extend `PetitionRegistryV2` to take `ageThreshold` at petition
  creation; verifier check publicInputs `[petitionId, root,
  nullifier, ageThreshold]`.
- Per-country DOB-extraction adapters (§8): UA cert DOB OID
  parser, EE/PL identifier DOB position parser, DE deferral
  (no DOB in cert; age verification not available for DE
  petitions without an external attribution attestation).

### 9.5 Privacy notes

- DOB never leaves the citizen device in plaintext.
- `pedersen(DOB)` commitment is in the enrollment tree leaf
  metadata, not on-chain explicit.
- Age tier in enrollment tree leaks broad bucket only (e.g.
  "18+"), not exact age.
- Per-petition age thresholds leak the threshold (public input)
  but not the DOB. Standard ZK selective disclosure semantics.

## 10. Sequencing + milestone gating

v3 is not a single ship; it's a sequenced increment. Grant
funding (Web3 Resilience Lab, ~$25k) supports:

| Month  | Milestone                                       | Cumulative scope                |
| ------ | ----------------------------------------------- | ------------------------------- |
| M1     | DKG tooling + ciphernode binary (§2.4)          | Threshold OPRF ready, single committee |
| M2     | On-chain `K_pub` registry (§4)                  | Trust anchor moved on-chain     |
| M3     | Threshold-OPRF mainnet pilot (UA, 5-of-7)       | v3 OPRF in production           |
| M4     | QES-anchored recovery + multi-Passkey ceremony (§3)   | Recovery flow live (client-only, no contract work) |
| M5     | Multi-QTSP UA expansion (§7)                    | UA QTSP universe covered        |
| M6     | Epoch rotation infrastructure (§6)              | Epoch_2026 → Epoch_2027 cutover ready |

The remaining v3 scope items — multi-country (§8), age
verification (§9), `/oprf/register` ZK proof (§5) — are tracked
for v3.1 and Phase-3 follow-on funding. They are scoped here so
the full v3 protocol shape is documented.

## 11. Open research / v4 territory

- Coercion resistance (JCJ-style fake credentials). Touched on in
  spec v2 §7; full implementation requires citizens to generate
  N fake credentials per enrollment + tally-time FHE filtering.
  Likely v4.
- FHE-PSI for enrollment uniqueness without OPRF. Vitalik's
  "FHE restricted to vote-tally-shaped workloads" framing
  (spec v2 §0) holds for now; revisit if FHE-PSI moves into the
  tractable regime.
- Petition-creator anonymity. Currently petition creators are
  on-chain identified. Should petition creation itself be a
  ZK action ("some enrolled citizen created this petition")?
  v4 question.
- Cross-country petition aggregation UX + tally semantics. §8.3
  established per-country trees as the right boundary; the
  petition layer needs a design pass for petitions that
  legitimately span borders (EU-citizen petitions, OECD-citizen
  petitions, etc.).

### 11.1 Postmortem — why mnemonic recovery was dropped

Earlier drafts of v2 spec §3.4 and v3 spec §3 proposed BIP-39
mnemonic recovery paths. Both were rejected after design review on
2026-05-29.

**v2 §3.4 mnemonic disclosure** shipped as a non-functional
placeholder — the mnemonic encoded `HKDF(N)`, an irreversible
derivation that could not regenerate `N`. The disclosure was
deleted from the v2 codebase and UI.

**v3 §3 Path A "mnemonic 2FA"** failed analysis: the mnemonic gated
an OPRF re-derivation that the fresh Diia QES already authorizes.
A citizen with valid QES can re-run `/oprf/blind-eval` with fresh
blinding and recover `N` by OPRF determinism. The mnemonic added a
gate that the QES already provided, while introducing a recall-rate
failure mode for civic-tech users.

**v3 §3 Path B "raw N in mnemonic"** failed analysis: mechanically
correct (264 bits BIP-39 ≥ 256 bits `N`) but introduced a
non-rotatable bearer credential with sub-30% civic-tech write-down
recall rates. Net security regression vs the Passkey-wrapped
IndexedDB v2 already ships.

**Replacement design** (v3 §3 above + v2 spec §3.4 / §3.5 in the
v2 spec): three-tier recovery anchored on Diia QES + OPRF
determinism — cloud-synced Passkey (primary), multi-Passkey
enrollment ceremony (secondary), QES-anchored `/oprf/blind-eval`
re-derivation (tertiary), with §6 epoch rotation as the natural
floor.

Full design memo: `/tmp/recovery-design.md` (researcher,
2026-05-29). For future readers: don't bring mnemonic back. The
state-issued QES is the right anchor for civic-identity recovery;
self-sovereign-crypto recovery patterns do not transfer.

## 12. References

- v2 spec (this document's predecessor):
  `docs/specs/2026-05-29-crisp-qes-v2-refined.md` (commit `2261714`).
- RFC 9497 — Oblivious Pseudorandom Functions (OPRFs) using
  Prime-Order Groups.
- Gennaro–Jarecki–Krawczyk–Rabin — Secure Distributed Key
  Generation for Discrete-Log Based Cryptosystems.
- eIDAS Regulation (EU 910/2014) — qualified electronic signatures.
- EU List of Trusted Lists (LOTL).
- Web3 Resilience Lab grant programme (funded scope reference).
