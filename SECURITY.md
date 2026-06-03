# Security & Audit Scope — CRISP-QES

This document scopes the codebase for external security review (e.g. zkSecurity).
It pins the exact code to audit, lists in/out-of-scope components, states the
threat model, and **discloses known issues + prior internal reviews** so the
audit builds on them rather than re-deriving them.

> CRISP-QES is a privacy-preserving petition / voting platform: Ukrainian Diia
> **QES** (qualified e-signature) → **Grumpkin VOPRF** enrollment → anonymous
> nullifier-gated actions, with Noir / UltraHonk ZK and an EVM contract layer.
> A CRISP/Interfold threshold-FHE encrypted tally is an **experimental** add-on.

---

## 1. Audit target — pin these commits

Audit **immutable commits**, not branches.

| Repo | Ref | Commit | What |
| --- | --- | --- | --- |
| `github.com/alik-eth/crisp-qes` | `main` | `d53b03e` | **PRIMARY** — security-fixed OPRF circuits, enrollment + petition contracts, threshold work, prior security-review docs |
| `github.com/alik-eth/crisp-qes` | `feat/crisp-fhe-tally` | `c458fd5` | FHE voting (EXPERIMENTAL/demo) — see §4 caveat |
| `github.com/alik-eth/crisp-qes-enclave` | `main` | `decb429d` | Enclave/FHE backend fork (EXPERIMENTAL) |

> ⚠️ `feat/crisp-fhe-tally` branched **before** the OPRF security-fix merge, so its
> OPRF circuits are **stale/pre-fix**. Audit the OPRF on `main`, not on the FHE
> branch.

---

## 2. In scope (primary — on `main`)

### ZK circuits (Noir / UltraHonk) — `packages/oprf/v3-grumpkin/`
- `lib-noir/grumpkin_voprf/src/` — the crypto library:
  - `h2c.nr` — hash-to-curve (Shallue–van de Woestijne) onto Grumpkin
  - `dleq.nr` — Chaum–Pedersen DLEQ verification (single-key + per-share, epoch-bound)
  - `oprf.nr` — blind eval, unblind, nullifier, the **two-proof shared-`r` commitment** (`C_r`), and the **2-of-3 threshold** combine (pinned mod-N Lagrange, idx→Kpub binding)
  - `params.nr`, `lib.nr`
- `circuits/`:
  - `enroll_commit_v2/` — **deployed** enrollment-commitment circuit (two-proof gate)
  - `oprf_nullifier/` — threshold nullifier / register proof
  - `oprf_commitment/`, `qes_frontend/`, `enroll_commit/` (legacy)

### Smart contracts (Solidity 0.8.28, Foundry) — `packages/contracts/src/`
- `EnrollmentRegistry.sol` — Pedersen-Merkle enrollment root + attester-signed `updateRoot`
- `PetitionRegistryV2.sol` — nullifier-gated support instrument
- `UltraVerifierV2.sol` / `IVerifierV2.sol` — Honk verifier
- `P256.sol` — P-256 helpers
- Deployed addresses: `packages/contracts/deployments/{base-sepolia,sepolia}.json`

### Protocols / properties
- Diia QES → in-circuit trust-chain → Grumpkin **blind**-OPRF enrollment
- 2-of-3 **threshold** OPRF (DKG-lite, seed-derived shares, per-share DLEQ)
- Nullifier derivation + anti-double-vote / anti-Sybil

### Off-chain services (review for protocol soundness, not infra hardening)
- OPRF node + server: `packages/oprf/v3-grumpkin/service/` (proof-gate, attester, threshold combine)

---

## 3. Out of scope (or lower priority)
- Front-end UX (`packages/web`) beyond the proof/witness construction it performs
- Relayer infra, Fly.io deployment, CI
- The CRISP/Interfold **FHE tally** and enclave fork (experimental — see §4)

---

## 4. Status & known issues — **please read before reviewing**

Internal reviews already found and (mostly) fixed several issues. Prior reports
(on `main`) — hand these to the reviewer:
- `docs/2026-06-02-voprf-security-review.md` — the F1–F4 findings
- `docs/specs/2026-06-02-f2-two-proof-shared-r-commitment.md`
- `docs/specs/2026-06-02-grumpkin-voprf-library-and-f2-binding.md`
- `docs/specs/2026-06-02-threshold-oprf-demo.md`
- `docs/security-notes.md`, `docs/2026-06-01-crisp-phase3-review-findings.md`

**Known findings (v3 Grumpkin OPRF was "not sound as deployed"):**
- **F1** — unpinned DLEQ generator `G` → **fixed** on `main` (pinned constant).
- **F2** — free `rinv`/`r` blind witnesses (unbounded Sybil nullifiers) → **fixed** via the two-proof + `C_r = pedersen(r)` binding (NOT a fused single proof — that would open blind-eval to a deanonymization oracle).
- **F3** — unpinned SvdW hash-to-curve constants `c1..c4` → **fixed** (pinned).
- **C-1 / C-3** — DLEQ challenge binding / limb range-checks → addressed.
- **F4 (MEDIUM, partially open)** — operator can deanonymize at enrollment. The 2-of-3 threshold mitigates by design, but **real mitigation needs INDEPENDENT operators + verifiable DKG**; the current deployment is **co-hosted** (single operator). Treat single-operator deployments as non-private.

**Invariants worth explicitly checking:**
- The **synthetic test CA must never appear in the production pinned CA set** (would be a trust-anchor backdoor). Real Diia CAs only in prod.
- `V3_THRESHOLD_SEED` required + fail-closed in production; node key shares must be deterministic across restarts (recovery), not random.
- `EnrollmentRegistry.updateRoot` attester signature is bound to `address(this)` + chainid (replay scope).
- Genesis leaves emit no `CommitmentInserted` events — deploy with `genesisLeafCount=0`.

**Experimental / unaudited (do not assume sound):** the FHE/CRISP tally, the
enclave fork, and anything on `feat/crisp-fhe-tally`. The vote SDK pins
`@aztec/bb.js@3.x`; the web app uses `4.x` — VK hashes are bb-version-sensitive.

---

## 5. Build & reproduce
- Noir circuits: `nargo` (1.0.0-beta.19) — `nargo compile` / `nargo test` per circuit; VK hashes must be generated with the `bb` bundled in `@aztec/bb.js`, **not** a CLI `bb` on PATH.
- Contracts: `cd packages/contracts && forge test`.
- See each package's README + `docs/specs/` for the full toolchain.

## 6. Reporting
Please report findings privately to the maintainer (see repo owner contact) with
the affected file + commit, a PoC or constraint-level description, severity, and
suggested remediation. Do not open public issues for unfixed vulnerabilities.
