# crisp-qes — Civic Voice

Privacy-preserving citizen-initiative petitions. Citizens enroll once with a
**qualified electronic signature** (QES — e.g. Ukraine's Diia), then sign
petitions anonymously. No wallet, no app. The count is anchored on-chain and
auditable; the same person can't sign twice, yet their signatures across
petitions can't be linked back to them or to each other.

> **Experimental / unaudited.** The operator-blind enrollment path (Grumpkin
> VOPRF + in-circuit QES verification) has **not** had an external security
> audit. An adversarial self-audit found and fixed a real forgery bug. An
> external audit is mandatory before any real-world use.

## What makes it private

**The operator never learns who you are.** Enrollment is *operator-blind*: the
service that gates enrollment sees only a blinded curve point and a
zero-knowledge proof — never your tax ID, your certificate, or your date of
birth. Three properties hold simultaneously:

- **Sybil-resistant** — one real, government-issued QES identity → exactly one
  enrollment. A deterministic nullifier blocks a second enrollment of the same
  person.
- **Operator-blind** — the gate checks a proof, not your data. Nothing
  identifying leaves your device.
- **Cross-petition-unlinkable** — each petition signature reveals only a
  per-petition nullifier, so signatures can't be correlated across petitions.

## How enrollment works

1. The browser blinds your tax ID into a Grumpkin point `M = r·H2C(taxID)` and
   downloads a session-bound **challenge** `{intent, epoch, blindedInput: M}`.
2. You sign that challenge with **QES** → a `.p7s` (PKCS#7) signature.
3. The browser proves `enroll_commit_v2` **entirely on-device**. The proof
   establishes, in zero knowledge:
   - your QES leaf certificate chains to a **pinned Diia CA** (in-circuit
     CA → leaf ECDSA-P256 verification — the identity is *not* self-asserted);
   - the cert holder is **age ≥ 18** (date of birth extracted in-circuit);
   - `M` is the correct blinding of the tax ID *inside* that cert;
   - the signed challenge digest binds the signature to *this* enrollment.

   Only `M` and the proof leave the device.
4. The service verifies the proof, evaluates `Y = k·M` (it never sees the
   unblinded input), and — gated by a second `oprf_nullifier` proof — appends
   `commitment = pedersen(N)` to the enrollment Merkle tree and signs the
   on-chain `updateRoot`.

Because the commitment is deterministic per identity, re-enrolling the same QES
is **within-epoch recovery** (re-wrap the local vault on a new device — no new
leaf, no seed phrase, no server-side backup).

Signing a petition afterwards uses a separate, much smaller Noir circuit and
takes ~2 s.

## Circuits

| Circuit            | Role                                                          | Size          |
| ------------------ | ------------------------------------------------------------- | ------------- |
| `enroll_commit_v2` | QES → Diia CA chain → age≥18 → blinded `M` + challenge binding | ~457 k gates  |
| `oprf_nullifier`   | binds `commitment` to the cert via in-circuit DLEQ            | small         |
| sign circuit       | per-petition membership + nullifier                           | ~28 k constraints |

The enrollment proof is heavy (~457 k gates, ~700 MiB to prove) but runs in the
browser on desktop and on mobile Safari within a single-threaded 832 MiB wasm
budget. The sign circuit stays small by moving both P-256 ECDSA verifications
out of the per-signature path — they run once, at enrollment.

## Live demo

Enroll once with a real Diia QES, then support petitions in ~2 s.

| Component       | URL                                                                                |
| --------------- | ---------------------------------------------------------------------------------- |
| Web (UI)        | [civicvoice.fly.dev](https://civicvoice.fly.dev)                                   |
| OPRF service    | [crisp-qes-oprf-grumpkin.fly.dev](https://crisp-qes-oprf-grumpkin.fly.dev/healthz) |
| Relayer         | [crisp-qes-relayer.fly.dev](https://crisp-qes-relayer.fly.dev/healthz)             |

**Contracts** — Base Sepolia (chain 84532):

| Contract             | Address                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `EnrollmentRegistry` | [`0x64f40F22033E0AdB0c1183c42135e5C29266b817`](https://sepolia.basescan.org/address/0x64f40F22033E0AdB0c1183c42135e5C29266b817) |
| `PetitionRegistryV2` | [`0x4c6b7Da31dDb645A26F821f44DD44ecF3cd7000A`](https://sepolia.basescan.org/address/0x4c6b7Da31dDb645A26F821f44DD44ecF3cd7000A) |
| `UltraVerifierV2`    | [`0x62D83eaE3ae80c08d9945169EF638fC729aec3ea`](https://sepolia.basescan.org/address/0x62D83eaE3ae80c08d9945169EF638fC729aec3ea) |

Enrollment is **real-Diia-cert-only** (the trust-chain pins live Diia CAs).
Prove on desktop — the enrollment proof sits at the edge of mobile memory.

## Repo layout

| Path                          | What it is                                                                        |
| ----------------------------- | --------------------------------------------------------------------------------- |
| `packages/oprf/v3-grumpkin/`  | Operator-blind enrollment: Grumpkin VOPRF service + Noir circuits. In-process bb.js proof gating; Merkle store self-heals from on-chain `CommitmentInserted` events. |
| `packages/contracts/`         | Foundry: `EnrollmentRegistry`, `PetitionRegistryV2`, `UltraVerifierV2`.           |
| `packages/relayer/`           | Fastify meta-tx relayer (`updateRoot`, `signPetition`) — keeps signers walletless. |
| `packages/web/`               | Vite + React frontend: enrollment (`/verify`) + sign flow (uk/en).                |
| `packages/sdk/`               | TypeScript `.p7s` (PKCS#7) parsing, shared by web + oprf.                          |

## Develop

```sh
pnpm install
pnpm contracts:build
```

**Prerequisites:** Node 20+, pnpm 10+; Rust stable + Foundry (`forge`, `cast`,
`anvil`); Noir `nargo` 1.0.0-beta.19 and `bb` (Barretenberg) 4.0.0-nightly.

## Status

Testnet demo live on Base Sepolia; operator-blind enrollment with in-circuit
Diia trust-chain is the primary `/verify` flow. **Experimental / unaudited** —
external audit pending. See [`docs/roadmap.md`](docs/roadmap.md) for what's
next.
