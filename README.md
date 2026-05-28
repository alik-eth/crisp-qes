# crisp-qes

Privacy-preserving citizen-initiative petitions, backed by Ukrainian Diia QES
signatures, anchored on Base. Walletless for signers, on-chain auditable count,
cross-petition-unlinkable nullifiers.

Live spec (v2 shipped, v3 funded scope):
[`docs/specs/2026-05-29-crisp-qes-v2-refined.md`](docs/specs/2026-05-29-crisp-qes-v2-refined.md),
[`docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md`](docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md).
The original MVP design is at
[`docs/specs/2026-05-19-crisp-qes-pivot-design.md`](docs/specs/2026-05-19-crisp-qes-pivot-design.md).

## Repo layout

- `packages/circuit/` — Noir circuit (Merkle inclusion + Pedersen nullifier, ~28 k constraints)
- `packages/contracts/` — Foundry: `EnrollmentRegistry`, `PetitionRegistryV2`, `UltraVerifierV2`
- `packages/oprf/` — Fastify VOPRF service (RFC 9497 ristretto255-SHA512) + Diia QES verification + secp256k1 attester
- `packages/relayer/` — Fastify meta-tx relayer for `PetitionRegistryV2.signPetition`
- `packages/web/` — Vite + React: walletless enrol + sign flow (uk/en)
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
pnpm circuit:check
pnpm contracts:build
```

## Performance

Same 16-vCPU Linux box for both passes. Full methodology + raw per-run
records in [`bench/results-2026-05-28.md`](bench/results-2026-05-28.md)
(MVP design) and [`bench/v2-results-2026-05-29.md`](bench/v2-results-2026-05-29.md)
(shipped v2 design).

| Metric                              | MVP design (2026-05-28) | Shipped v2 (2026-05-29) | Δ                    |
| ----------------------------------- | ----------------------- | ----------------------- | -------------------- |
| Browser prove (Chromium, median)    | 79.7 s                  | **2.4 s**               | **34× faster**       |
| Native prove (Node, threads=auto)   | 14.5 s                  | **0.47 s**              | **30× faster**       |
| Proof size on the wire              | 10,176 B                | **8,640 B**             | 15 % smaller         |
| Native peak RSS                     | 346 MB                  | **228 MB**              | 34 % smaller         |
| On-chain `signPetition` gas         | 4,242,422               | **2,620,543**           | 38 % cheaper         |
| Per-signature cost @ ETH = $3,500   | $0.091                  | **$0.057**              | 38 % cheaper         |

The shipped jump comes from moving both P-256 ECDSA verifications **out of
the ZK circuit** — they run once at enrollment (via OPRF + Diia QES
check), not per signature. The circuit shrinks from ~100 k constraints
to ~28 k and from 15 to 3 public inputs.

## Live demo

Three-layer architecture: enrol once via OPRF + Diia QES, sign petitions in
2 s via Noir ZK. Fly app names retain the `v2` tag (external identifiers cited
in the grant proposal); repo paths are unprefixed.

| Layer        | Component             | URL                                                                                  |
| ------------ | --------------------- | ------------------------------------------------------------------------------------ |
| Web (UI)     | `packages/web`        | [crisp-qes-v2-web.fly.dev](https://crisp-qes-v2-web.fly.dev)                         |
| OPRF service | `packages/oprf`       | [crisp-qes-v2-oprf.fly.dev](https://crisp-qes-v2-oprf.fly.dev/healthz)               |
| Relayer      | `packages/relayer`    | [crisp-qes-v2-relayer.fly.dev](https://crisp-qes-v2-relayer.fly.dev/healthz)         |

Contracts (Base Sepolia, chain 84532):

| Contract              | Address                                                                                                                            |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `EnrollmentRegistry`  | [`0x4A17285f2f3035AD8bB6da86d9aB189cC33c4106`](https://sepolia.basescan.org/address/0x4a17285f2f3035ad8bb6da86d9ab189cc33c4106)     |
| `PetitionRegistryV2`  | [`0x11561749D669791117592332B8E5373Ff60406EF`](https://sepolia.basescan.org/address/0x11561749d669791117592332b8e5373ff60406ef)     |
| `UltraVerifierV2`     | [`0x173F7BB534C7589d3f6D11DF3BE8Efee07312577`](https://sepolia.basescan.org/address/0x173f7bb534c7589d3f6d11df3be8efee07312577)     |

Demo signature, end-to-end on Base Sepolia (full enrol + ZK sign + relay):
[`0xc80557d7…2dfb`](https://sepolia.basescan.org/tx/0xc80557d7c25c9c5b8ae4b770d4eda8690566092bd412d33e372a69526ec42dfb)
— native prove time 823 ms.

## Status

Testnet demo live on Base Sepolia. See
[v2-refined spec §5](docs/specs/2026-05-29-crisp-qes-v2-refined.md) for the
in-scope items and
[v3-funded-scope](docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md) for
the funded hardening track (threshold OPRF + FHE tally + recovery).
