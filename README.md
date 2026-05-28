# crisp-qes

Privacy-preserving citizen-initiative petitions, backed by Ukrainian Diia QES
signatures, anchored on Base. Walletless for signers, on-chain auditable count,
cross-petition-unlinkable nullifiers.

See `docs/specs/2026-05-19-crisp-qes-pivot-design.md` for the design.

## Repo layout

- `packages/circuit/` — Noir circuit (CAdES walk, P-256 verify, Merkle trust check, pubkey nullifier)
- `packages/contracts/` — Foundry: `PetitionRegistry.sol` + generated `UltraVerifier.sol`
- `packages/sdk/` — TS: `.p7s` parse, witness build, Barretenberg WASM prover
- `packages/web/` — Vite + React: walletless signing flow (uk/en)
- `packages/relayer/` — Node: gas-paying meta-tx relayer
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
(MVP) and [`bench/v2-results-2026-05-29.md`](bench/v2-results-2026-05-29.md) (v2).

| Metric                              | MVP (2026-05-28) | v2 (2026-05-29) | Δ                    |
| ----------------------------------- | ---------------- | ---------------- | -------------------- |
| Browser prove (Chromium, median)    | 79.7 s           | **2.4 s**        | **34× faster**       |
| Native prove (Node, threads=auto)   | 14.5 s           | **0.47 s**       | **30× faster**       |
| Proof size on the wire              | 10,176 B         | **8,640 B**      | 15 % smaller         |
| Native peak RSS                     | 346 MB           | **228 MB**       | 34 % smaller         |
| On-chain `signPetition` gas         | 4,242,422        | **2,620,543**    | 38 % cheaper         |
| Per-signature cost @ ETH = $3,500   | $0.091           | **$0.057**       | 38 % cheaper         |

The v2 jump comes from moving both P-256 ECDSA verifications **out of
the ZK circuit** — they run once at enrollment (via OPRF + Diia QES
check), not per signature. The circuit shrinks from ~100 k constraints
to ~28 k and from 15 to 3 public inputs.

## Status

MVP scaffolding in progress. See spec §5 for in-scope items.
