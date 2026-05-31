# crisp-qes

Privacy-preserving citizen-initiative petitions, backed by QES (qualified
electronic signatures), anchored on Ethereum. Walletless for signers, on-chain
auditable count, cross-petition-unlinkable nullifiers.

**v3 (operator-blind enrollment) is the live system.** Enrollment is now
**operator-blind**: the OPRF service never sees your tax ID — only a
blinded curve point, gated by an in-browser zero-knowledge proof of a valid,
age≥18 QES certificate. The citizen signs a session-bound **challenge** using QES,
and that signature is bound to the enrollment *inside the ZK proof*. Signing
petitions then takes ~2 s via a separate Noir circuit.

> **EXPERIMENTAL / UNAUDITED.** The v3 operator-blind path (Grumpkin VOPRF +
> in-circuit QES cert verification) has not had an external security audit. An
> adversarial self-audit found and fixed a real forgery bug; an external audit is
> mandatory before any real-world use.

Specs:
[v3 funded scope](docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md),
[v3 bound-challenge enrollment](docs/superpowers/specs/2026-05-31-v3-bound-challenge-enrollment-design.md),
[v2 refined (sign flow)](docs/specs/2026-05-29-crisp-qes-v2-refined.md).
Original MVP design:
[`docs/specs/2026-05-19-crisp-qes-pivot-design.md`](docs/specs/2026-05-19-crisp-qes-pivot-design.md).

## Repo layout

- `packages/oprf/v3-grumpkin/` — **v3 operator-blind enrollment**: standalone
  Grumpkin VOPRF service + Noir circuits (`enroll_commit_v2` proves QES cert →
  age≥18 → blinded element + signed-challenge binding, ~2^19 gates; `oprf_nullifier`
  binds the commitment to the cert via in-circuit DLEQ). In-process bb.js proof
  gating (no `bb` CLI). Merkle store self-heals from on-chain `CommitmentInserted`.
- `packages/contracts/` — Foundry: `EnrollmentRegistry`, `PetitionRegistryV2`, `UltraVerifierV2`
- `packages/oprf/` — legacy v2 VOPRF service (RFC 9497 ristretto255-SHA512); superseded by v3-grumpkin for enrollment
- `packages/relayer/` — Fastify meta-tx relayer for `EnrollmentRegistry.updateRoot` + `PetitionRegistryV2.signPetition`
- `packages/web/` — Vite + React: walletless v3 enrol (`/verify`) + sign flow (uk/en)
- `packages/sdk/` — TS: `.p7s` parsing (shared by web + oprf)
- `packages/lotl-flattener/` — TS: EU LOTL CA-trust-list flattening + Pedersen-on-BN254 primitives
- `fixtures/diia/` — `.p7s` samples, **gitignored** (legal identity material)

## Prerequisites

- Node 20+, pnpm 10+
- Rust stable, Foundry (`forge`, `cast`, `anvil`)
- Noir: `nargo` 1.0.0-beta.19, `bb` (Barretenberg) 4.0.0-nightly

## Bootstrap

```sh
pnpm install
pnpm contracts:build
```

## How v3 enrollment works (operator-blind)

1. Enter tax ID → the browser computes a blinded Grumpkin point `M = r·H2C(taxID)`
   and downloads a session **challenge** `{intent, epoch, blindedInput: M}`.
2. Sign that challenge using **QES** → `.p7s`.
3. The browser proves `enroll_commit_v2` entirely on-device: a valid QES leaf
   ECDSA over `signedAttrs` (hashed in-circuit), tax ID + age≥18 extracted from
   the cert, `M` derived from that tax ID, and the signed `messageDigest` bound
   to `sha256(challenge)`. Only `M` + the proof leave the device.
4. The OPRF service verifies the proof, evaluates `Y = k·M`, and (with a second
   `oprf_nullifier` proof) appends `commitment = pedersen(N)` to the enrollment
   tree and signs the on-chain `updateRoot`. It never sees the cert or the tax ID.

Because the `commitment` is deterministic per tax ID, re-enrolling the same identity
is treated as **recovery** (re-wrap the vault on a new device; no new leaf).

## Performance (sign circuit)

Full methodology + raw records in
[`bench/v2-results-2026-05-29.md`](bench/v2-results-2026-05-29.md).

| Metric                              | MVP design (2026-05-28) | Shipped v2 sign (2026-05-29) | Δ              |
| ----------------------------------- | ----------------------- | ---------------------------- | -------------- |
| Browser prove (Chromium, median)    | 79.7 s                  | **2.4 s**                    | **34× faster** |
| Native prove (Node, threads=auto)   | 14.5 s                  | **0.47 s**                   | **30× faster** |
| Proof size on the wire              | 10,176 B                | **8,640 B**                  | 15 % smaller   |
| On-chain `signPetition` gas         | 4,242,422               | **2,620,543**                | 38 % cheaper   |

The sign circuit stays small (~28 k constraints) by moving both P-256 ECDSA
verifications **out of the per-signature circuit** — they run once at enrollment.
The v3 *enrollment* proof is heavier (~2^19 gates, ~700 MiB to prove in-browser):
it runs fine on desktop (Chrome, Safari) and on mobile Safari via a single-threaded
832 MiB wasm budget.

## Live demo

Enrol once via the operator-blind v3 flow, then vote on petitions in ~2 s.

| Layer                  | Component                     | URL                                                                        |
| ---------------------- | ----------------------------- | -------------------------------------------------------------------------- |
| Web (UI)               | `packages/web`                | [crisp-qes-web.fly.dev](https://crisp-qes-web.fly.dev)                      |
| v3 OPRF (enrollment)   | `packages/oprf/v3-grumpkin`   | [crisp-qes-oprf-grumpkin.fly.dev](https://crisp-qes-oprf-grumpkin.fly.dev/healthz) |
| Relayer                | `packages/relayer`            | [crisp-qes-relayer.fly.dev](https://crisp-qes-relayer.fly.dev/healthz)     |

Contracts (Ethereum Sepolia, chain 11155111 — clean-slate redeploy 2026-05-31):

| Contract              | Address                                                                                                                            |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `EnrollmentRegistry`  | [`0xC9b35dE202e0Bf92e38603deEC4176557eF249a4`](https://sepolia.etherscan.io/address/0xC9b35dE202e0Bf92e38603deEC4176557eF249a4)     |
| `PetitionRegistryV2`  | [`0x0BF0D1BD0550028887528d5bA310F1e3019ad6DB`](https://sepolia.etherscan.io/address/0x0BF0D1BD0550028887528d5bA310F1e3019ad6DB)     |
| `UltraVerifierV2`     | [`0xEC306EFA07D9688ae759d1c11D411cB6F0200acB`](https://sepolia.etherscan.io/address/0xEC306EFA07D9688ae759d1c11D411cB6F0200acB)     |

## Status

Testnet demo live on Ethereum Sepolia; v3 operator-blind enrollment is the
primary `/verify` flow (legacy v2 enrollment removed). **Experimental /
unaudited** — external audit pending. Still ahead on the funded hardening track
(threshold OPRF + epoch rotation) and the `cert[]`↔`pubkey` in-circuit binding;
see [v3 funded scope](docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md).
