# ADR 0001 — Noir/Barretenberg v3↔v4 toolchain split

- **Status:** Accepted (2026-06-03)
- **Context branch:** `feat/crisp-fhe-tally`
- **Supersedes / relates to:** `docs/specs/2026-06-03-fhe-identity-e2e-design.md` (§4, the two-process E2E), `docs/specs/2026-06-01-crisp-fhe-tally-integration.md` (spike + client-side-proving requirement)

## Context

Two Barretenberg/Noir toolchains coexist in the repo, split cleanly along
**enrollment vs vote**:

| Side | `@aztec/bb.js` | `@noir-lang/noir_js` | Anchored by |
| --- | --- | --- | --- |
| **v4** — enrollment | `4.0.0-nightly.20260120` | `1.0.0-beta.19` | `packages/oprf/*`, `packages/web`, `bench`, `lotl-flattener` (already migrated, commit `786a3dd`) |
| **v3** — vote | `3.0.0-nightly.20260102` | `1.0.0-beta.16` | the deployed `CRISPQESVerifier` (fold VK) **and** a source-level pin: `fold/Nargo.toml` imports `bb_proof_verification` at git tag `v3.0.0-nightly.20260102` |

The vote path is the harder anchor: it is held both by the **deployed on-chain
verifier** (the `crisp_fold` VK, byte-sensitive to the bb nightly date) and by
the **recursion gadget pinned into the circuit source**. The enrollment side is
already on the current (v4/beta.19) line.

### Why they cannot coexist

- **One process:** bb.js exposes a single WASM singleton (`BarretenbergSync.initSingleton()`)
  under the same package name. Two copies collide on that global. This is why the
  identity E2E runs as two separate Node processes that communicate only via an
  artifact file + the chain.
- **One browser bundle:** today there is no collision because `packages/web`
  imports bb.js (v4) for enrollment only; the vote proof is not yet in the
  browser (there is a stub at `web/src/lib/vote.ts` lazy-importing `@crisp-e3/sdk`,
  marked "added in Task 4.0"). Bundling both naively collapses the shared bare
  specifier `@aztec/bb.js` and collides the WASM singleton.
- **Wire-format:** VKs are nightly-**date**-sensitive; the 1.x→4.x migration
  required ABI changes (Fr → raw 32-byte BE `Uint8Array`, `pedersenHash({inputs,hashIndex})`).
  A mismatched bb silently ships an incompatible verifier (guarded by `VK_HASH` +
  public-input-count checks in bootstrap).

### What this blocks

In-browser **per-user voting**. Everything else already works (enrollment in v4;
the vote proof runs in its own v3 process in the E2E and on-chain verify passes).

## Decision

**(C) now, (A) later.**

- **Now — (C): worker-isolated dual bb.js.** Add a pnpm-aliased
  `@aztec/bb.js-v3` (`npm:@aztec/bb.js@3.0.0-nightly.20260102`) imported **only**
  inside a dedicated `vote.worker.ts`, so the v3 WASM singleton lives in a
  separate worker realm and never shares global state with the v4 main thread.
  This requires **zero circuit recompilation, zero VK regen, zero redeploy**, and
  the worker + COOP/COEP + `optimizeDeps.exclude:["@aztec/bb.js"]` scaffolding
  already exists in `packages/web/vite.config.ts`.

- **Later — (A): converge the fork to beta.19/bb4.** Upgrade `crisp_qes` + `fold`
  + `crisp-sdk` + `enclave-sdk`, move the `bb_proof_verification` gadget to a v4
  tag, regenerate the recursive VK hashes + both fold key-hashes + `CRISPQESVerifier`,
  and redeploy. The Noir source delta is small (a test-only `Vec` patch, already
  automated in `bootstrap.sh`). The real blocker is operational: the
  **secure-8192 fold VK regen OOMs locally (~29 GiB, needs a high-mem host)**. Do
  this when such a host is available; the worker dual-bundle then collapses back
  to a single bb.js.

## Alternatives considered

- **(B) Downgrade enrollment to beta.16/bb3** — rejected. The OPRF/grumpkin
  circuits lean on current stdlib (`multi_scalar_mul`, `pedersen_hash_with_separator`,
  embedded-curve ops; `Fr` no longer exported in 4.x). High blast radius, fights
  the upstream direction.
- **(D) Server-side vote proving** — rejected. Proofs are over the cleartext
  ballot + signature; delegating breaks the secret-ballot guarantee. Client-side
  proving is inherent to the privacy model.

## Consequences

- **Accepted scope limit:** the vote proof is the ~1.5M-gate `crisp_fold`
  recursion, several× past the iOS ~832 MiB browser floor. In-browser voting is
  **desktop-only** under any path; **mobile-web stays on the transparent counter**
  (iOS-native remains the mobile track). This constraint is **accepted** and does
  not change with the toolchain decision.
- (C) adds ~2× bb.js WASM + a second CRS to the bundle, but worker-lazy so the
  enrollment path is not penalized.
- The split persists until (A); contributors must keep proving the vote in its
  own realm/process and never co-init two bb.js instances.
- Each fork circuit change still requires the pinned-v3 `bb` (via `bb-pinned.sh`)
  until (A).

## Follow-ups

- Prototype (C): pnpm-aliased `vote.worker.ts` proving the dual-bb.js coexistence
  in the actual vite build (this ADR's companion task).
- Schedule (A) when a high-mem host (≥32 GiB) is available for the secure-8192
  fold VK regeneration.
