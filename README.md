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

Measured 2026-05-28 on a 16-vCPU Linux box; full methodology + tables in
[`bench/results-2026-05-28.md`](bench/results-2026-05-28.md).

- Proof generation, **desktop Chromium WASM** (live web app, n=3): **~80 s** median (76,962 ± 7,473 ms)
- Proof generation, **native Node + bb.js** (threads=auto, n=5): **~14.5 s** median, peak RSS ~350 MB
- Proof size on the wire: **10,176 bytes**, constant per signature
- **On-chain signature cost on Base Sepolia: 4,242,422 gas ≈ $0.09 per signature** at ETH = $3,500 (verifier 63 %, calldata 4.4 %, two RIP-7212 P-256 verifies + storage < 1 %)

## Status

MVP scaffolding in progress. See spec §5 for in-scope items.
