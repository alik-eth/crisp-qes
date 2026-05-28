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

## Status

MVP scaffolding in progress. See spec §5 for in-scope items.
