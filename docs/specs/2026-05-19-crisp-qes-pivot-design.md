# CRISP-QES — design spec

> Date: 2026-05-19. Status: design-approved (pending), pre-implementation.
> Pivot from: zkqes V8 attestation registry (the `identityescroworg` repo).
> Grant deadline: 2026-05-31 (Web3Lab Ukraine).

## 0. Pivot rationale

The `identityescroworg` line shipped V8 anonymous-attestation through 2026-05-19 — an
on-chain registry where citizens can prove "I hold a valid Ukrainian Diia QES" without
exposing a per-person dedup key. The honest read of the privacy trilemma
(`docs/superpowers/specs/2026-05-19-attestation-registry-amendment.md` §1 in the parent
repo) is that V8 ended up in the **unlinkability + no-3rd-party** corner — but the
*on-chain anchor itself adds limited value* for an anonymous attestation, because the
contract can't dedup. The on-chain commitment is doing administrative work, not
cryptographic work.

**The pivot:** keep all the parts of V8 that do real cryptographic work — the CAdES
parser, the trust-list verification, the privacy framing, the walletless web flow —
and re-target them at a product where on-chain commitment *does* earn its keep:
**citizen-initiative petitions (UA-style «петиція»)** with privacy-preserving signature
collection.

The on-chain registry now stores a verifiable count of signatures, indexed by petition,
with nullifiers preventing double-signing. The privacy claim becomes honest: citizens
sign anonymously, no third party learns who supported what, but the count is publicly
auditable. This is what blockchains are *for*.

## 1. Product

A single `PetitionRegistry` smart contract:

- **Anyone** can create a petition. Petition state: `{id, fullText, createdAt, deadline,
  threshold}`. Full text on-chain (UTF-8 bytes — auditable, unimpeachable).
- **Any UA citizen with a Diia QES** can sign petitions. One signature per
  cert-per-petition, walletless, browser-only, cross-petition-unlinkable.
- **Signature count** is publicly observable. Threshold-crossed + deadline-passed is a
  pure on-chain state-machine event.

No login, no wallet for signers. Petition creators need a wallet (gas). Signers don't.

## 2. Cryptographic shape

### 2.1 Eligibility (Noir ZK over CAdES)

A Noir circuit proves, for a signature submission:

1. Citizen's `.p7s` (CAdES detached signature) is structurally valid.
2. The signer cert is on a chain to the UA Diia trusted root (Poseidon Merkle, pinned
   on-chain).
3. The signer cert's subject serial matches the `TINUA-<tax-id>` pattern (proves it's a
   real Ukrainian QES, not a generic cert).
4. The signature is a valid P-256 ECDSA signature over the CAdES `signedAttrs`.
5. The `signedAttrs` `messageDigest` matches `SHA-256(petition_id || "::" || petition_text_hash)`
   — binding the signature to a specific petition.
6. The emitted **nullifier** equals `Poseidon(cert_pubkey_x, cert_pubkey_y, petition_id, DOMAIN)`.

**Public signals (minimal):**
- `petition_id` (uint256)
- `nullifier` (Field)
- `trustRoot` (Field) — pinned input, contract checks equality
- `chainBindings` — `keccak256(petition_id, msg.sender)` to prevent proof-grinding /
  meta-tx relay-binding (optional; relayer flow may make this `address(0)`)

**Private signals:**
- `.p7s` bytes, leaf cert bytes, intermediate cert bytes
- Cert pubkey (x, y) — used in nullifier, then discarded
- Subject serial bytes (asserted to start with `TINUA-`)
- ECDSA signature `(r, s)`
- Merkle path from leaf-cert-commit to `trustRoot`

### 2.2 Nullifier — the design choice that matters

```
nullifier = Poseidon(pubkey.x, pubkey.y, petition_id, DOMAIN_PETITION_V1)
```

Where `pubkey.x`, `pubkey.y` are the P-256 public key affine coordinates of the
citizen's QES cert, extracted privately inside the circuit.

**Why pubkey, not tax-ID or signature:**

| Candidate | Per-petition unique | Cross-petition unlinkable | Dictionary-attack resistant | Notes |
|---|---|---|---|---|
| `Poseidon(tax_id, petition_id)` | ✓ | ✓ | **✗** (10¹⁰ values, ~laptop-hour) | Bucket A failure |
| `Poseidon(signature, petition_id)` | **✗** (ECDSA non-deterministic) | ✓ | ✓ | Sybil broken |
| `Poseidon(pubkey, petition_id)` | ✓ (within cert lifetime) | ✓ | ✓ (pubkey ≈256b entropy, not enumerable) | **CHOSEN** |

The pubkey is high-entropy and Diia QTSPs do not publish full issued-cert corpora
(CRLs + OCSP are the public surface, not the cert set). So an attacker can't enumerate
pubkeys to dictionary-attack the nullifier set.

### 2.3 Honest limitations

| Property | MVP | v2 (CRISP) |
|---|---|---|
| Per-petition Sybil resistance | ✓ within cert lifetime | ✓ per real citizen |
| Cross-petition unlinkability | ✓ | ✓ |
| Cert-renewal Sybil resistance | ✗ (new cert → new pubkey → can re-sign) | ✓ (FHE-checked tax-ID at enrollment) |
| Coercion resistance | ✗ (coercer can force re-sign with same cert, match on-chain nullifier) | ✓ (JCJ fake credentials) |
| Tax ID privacy | ✓ (never emitted) | ✓ |
| No third party | ✓ | Distributed 3rd party (ciphernode committee) |

Cert renewals during a petition window are rare in practice — Diia certs are 1–2 year
validity, petition windows are typically <90 days. The collision rate at MVP scale is
acceptable. v2 closes both gaps via CRISP composition.

## 3. Stack

- **Circuit:** Noir, Barretenberg (UltraPlonk / UltraHonk) backend, universal SRS
  (Aztec's `ignition` ceremony — no project-side ceremony work).
- **Verifier:** Aztec's Solidity `UltraVerifier` (auto-generated by Nargo, deployed
  once per circuit version).
- **Contract:** `PetitionRegistry.sol` — single global registry. Foundry-built,
  deployed on Base Sepolia (and Base mainnet for v1).
- **Web:** Vite + React + TS. Walletless signers. Browser proving via Barretenberg
  WASM. Petition creators use any EVM wallet.
- **Relayer:** Minimal Node service. Accepts `{petition_id, nullifier, proof}` from
  signers, submits to contract, pays gas. Stateless. Fly.io / Heroku target.
- **Reused from `identityescroworg`** (copy with attribution, no submodule):
  - LOTL flattener output format (Diia trusted CA Poseidon Merkle root)
  - `.p7s` TypeScript parser (subject extraction, signedAttrs validation)
  - Privacy-trilemma analysis (trilemma framing in user copy)
  - Country-identifier bucket model (informs the honest-limitation table)
  - i18n patterns (uk.json mandatory, en.json reference)

## 4. Repo layout

pnpm workspace monorepo.

```
crisp-qes/
├── docs/
│   ├── specs/                # design + amendments
│   └── plans/                # implementation plans (writing-plans output)
├── packages/
│   ├── circuit/              # Noir CAdES + P-256 + nullifier
│   │   ├── Nargo.toml
│   │   ├── src/main.nr
│   │   └── tests/
│   ├── contracts/            # Foundry: PetitionRegistry + UltraVerifier
│   │   ├── foundry.toml
│   │   ├── src/PetitionRegistry.sol
│   │   ├── src/UltraVerifier.sol  # generated, committed
│   │   ├── script/Deploy.s.sol
│   │   └── test/
│   ├── sdk/                  # TS: .p7s parse, witness build, BB WASM prove
│   │   ├── src/
│   │   └── tests/
│   ├── web/                  # Vite + React: walletless signing flow
│   │   ├── src/
│   │   └── i18n/{en,uk}.json
│   └── relayer/              # Node: gas-paying meta-tx relayer
│       ├── src/
│       └── tests/
├── fixtures/
│   └── diia/                 # .p7s samples — GITIGNORED (legal identity material)
├── .gitignore
├── pnpm-workspace.yaml
├── package.json
└── README.md
```

## 5. MVP scope (12 days to grant)

### In scope
- [ ] Noir circuit (CAdES walk, P-256 verify, Merkle trust check, pubkey-nullifier)
- [ ] UltraVerifier deployment on Base Sepolia
- [ ] `PetitionRegistry.sol`: `createPetition`, `signPetition`, `getPetition`,
      `signatureCount`, `hasNullifier`, `petitionStatus`
- [ ] TS witness builder: parses Diia `.p7s`, extracts inputs, calls BB WASM prover
- [ ] Web flow: browser-only, walletless, upload `.p7s`, pick petition, prove + relay
- [ ] Public relayer (self-run for MVP)
- [ ] One real demo petition end-to-end (live Diia → on-chain signature)
- [ ] uk.json + en.json (Ukrainian native review before ship)
- [ ] CLAUDE.md (repo-scoped orchestration playbook, mirrors `identityescroworg`)

### Out of scope (MVP)
- CRISP / FHE / ciphernodes — **v2**
- DSTU 4145 support — **v3** (Ukrainian-specific elliptic curve)
- Multi-QTSP beyond Diia / P-256 ECDSA — **v2**
- Petition discovery / search UI — **v2**
- Cross-cert-renewal Sybil resistance — **v2 via CRISP**
- Government petition-response integration — **out entirely**
- Petition deletion / amendment — **out entirely** (immutability is a feature)

## 6. v2 roadmap (post-grant, designed-for)

The MVP architecture is constructed so v2 is purely additive — no rewrite of the
circuit, contract, or web flow.

- **Ciphernode committee:** recruit independent operators (target: 5-of-7
  threshold). Reuse CRISP/Interfold's existing infrastructure where possible.
- **FHE-checked tax-ID uniqueness at enrollment:** citizen enrolls once, submits an
  FHE-encrypted tax-ID; ciphernodes check uniqueness across all enrolled tax-IDs
  under threshold-FHE, return a binding commitment. Future petition signatures use
  the committed enrollment-secret instead of cert pubkey.
- **JCJ fake-credentials branch:** citizen can reveal a "fake" credential under
  coercion; only the ciphernode threshold (under FHE) can distinguish real from fake.
- **RISC Zero wrapper:** wraps the Noir eligibility proof so it composes with CRISP's
  RISC Zero tally proofs. (CRISP already uses RISC Zero — reusing infrastructure.)
- **Per-citizen Sybil resistance:** cert-renewal no longer breaks Sybil — the enrolled
  secret is what's bound, not the per-cert pubkey.

The v2 work becomes the fundable phase 2 grant: concrete roadmap, partner asks
(CRISP/Interfold team for ciphernode infra), genuine cypherpunk story.

## 7. Open questions (resolve before implementation)

1. **Petition id derivation.** Sequential `uint256` (cheap, indexable) or
   `keccak256(text || creator || nonce)` (collision-free, content-addressed)?
   Recommendation: sequential — text hash lives in the struct anyway.
2. **Petition text size cap.** Gas-bounded. Recommendation: 8 KB cap (~1500 words,
   covers UA petition format), enforced at create-time.
3. **Threshold semantics.** Does the registry emit an `OnchainThresholdReached` event
   at the moment `signatureCount == threshold`, or do consumers poll? Event is cheap +
   indexable — recommendation: emit.
4. **Relayer trust model.** MVP self-runs the relayer. Should signers be able to
   submit directly (paying gas themselves) as a fallback? Recommendation: yes — the
   contract entrypoint is permissionless; the relayer is just a convenience.
5. **Petition creator deposit / spam control.** Without any deposit, anyone can spam
   petitions. Recommendation: small refundable creation deposit (returned at
   deadline regardless of outcome), or just rely on gas costs for MVP.

## 8. Non-goals

- We are **not** building a general-purpose eligibility-proof system. The eligibility
  primitive is petition-specific (per-petition nullifier).
- We are **not** competing with Diia's own petition system (petition.president.gov.ua)
  on feature parity. We are demonstrating a **privacy-preserving alternative** that
  Diia itself could adopt or that civic-tech orgs can run independently.
- We are **not** providing legal-grade signature semantics (this is not a substitute
  for a notarized QES on a legal document). The on-chain signature is a verifiable
  *support indication*, not a legal act.
