# v3 bound-challenge enrollment — design

**Date:** 2026-05-31
**Status:** approved (brainstorming) → pending implementation plan
**Tracks:** task #39 (v3 operator-blind enrollment)
**Component:** `packages/oprf/v3-grumpkin` (circuit + service), `packages/web` (UI), `packages/sdk` (consumed, unchanged)

## Problem

The v3 operator-blind enrollment flow (`/verify` → `V3Enroll`) dropped the v2
"challenge" step. The user uploads any existing Diia `.p7s`; the
`enroll_commit_v2` circuit verifies the leaf ECDSA over a **free-witness**
`msghash` and reads RNOKPP/DOB from the cert, but **nothing binds the signature
to this enrollment session**. Consequences:

- **No proof of live QES signing.** A captured/old `.p7s` can drive enrollment;
  v2 required signing a fresh, session-specific challenge in Diia.
- **Latent soundness gap.** `msghash` is unconstrained — the circuit only
  requires *some* signature by the cert key over *some* digest.

Sybil resistance is unaffected (`N = OPRF(RNOKPP)` is deterministic; the
on-chain nullifier blocks double-enrollment), but **impersonation via a leaked
`.p7s`** is the residual risk this design closes.

## Goal

Restore the v2 enrollment **interface and live-signing property** on top of the
v3 operator-blind crypto: the citizen enters their RNOKPP, downloads a personal
challenge, signs it in Diia, and the resulting `.p7s` is **cryptographically
bound to this session inside the ZK proof** — while the OPRF service still never
sees the certificate.

## Non-goals

- Server-issued nonces / stateful challenge store (rejected: `M` is already
  fresh-random, on-chain nullifier blocks double-enroll). Challenge stays
  **stateless**.
- `signingTime` freshness window (v2 task #30). Epoch-binding gives coarse
  freshness; a precise window would require parsing `signingTime` in-circuit.
  Deferred.
- **Out of scope but flagged:** binding `cert[]` ↔ `pubkey` (that the verified
  signature's key is the subject of the cert carrying the RNOKPP). Pre-existing
  question; logged as a follow-up audit item. This design is a strict
  improvement regardless.

## Approach (and rejected alternatives)

Bind the challenge **inside the circuit**. This is the only option that is both
**operator-blind** and **sound**:

- *Service-side check (v2 style):* rejected — in v3 the service cannot see
  `signedAttrs`/cert, so it cannot verify `messageDigest == sha256(challenge)`.
- *Public-input-only (no in-circuit `signedAttrs` hash):* rejected — unsound,
  because `msghash` stays free and a stale `.p7s` could be paired with any
  digest.

Therefore the circuit must compute `sha256(signedAttrs)` itself (which also
closes the free-`msghash` gap) and bind the extracted `messageDigest` to the
session challenge.

## End-to-end flow (v2 UX, v3 crypto)

1. User **enters RNOKPP** (10 digits).
2. Client picks random `r`, computes `H2C(RNOKPP)` on Grumpkin, `M = r·H2C(RNOKPP)`.
3. Client builds **challenge** =
   `{"intent":"crisp-qes-enroll-v3","epoch":"<epoch>","blindedInput":"0x<M>"}`
   (byte-exact, no whitespace, fixed key order — see Wire formats), downloads
   `crisp-qes-challenge.txt`.
4. User **signs it in Diia (QES)** → `.p7s` with `messageDigest = sha256(challenge)`.
5. Client uploads `.p7s`; verifies the cert's RNOKPP equals the entered RNOKPP;
   builds the witness incl. `signed_attrs`, `signed_attrs_len`, `msg_digest_off`,
   `expected_digest`.
6. Client **proves `enroll_commit_v2`** (now binds the signature to the challenge).
7. POST `/v3/blind-eval` → service reconstructs the challenge from public `M` +
   intent + epoch, `sha256`, splits into hi/lo limbs, requires they equal the
   proof's `expected_digest` public words, then verifies the proof and evaluates.
8. Unchanged from here: `oprf_nullifier` prove → `/v3/register` → relayer
   `/v2/enroll` (on-chain) → wrap vault under Passkey PRF.

## Components

### Circuit — `circuits/enroll_commit_v2/src/main.nr`

- **New private witness:** `signed_attrs: [u8; SA_LEN]`, `signed_attrs_len: u32`,
  `msg_digest_off: u32`. `SA_LEN` is a bound on the real Diia `signedAttrs`
  length (set from a real sample; see Risks).
- **New public OUTPUT (return):** `messageDigest` as two 16-byte field limbs
  `digest_hi`, `digest_lo` (`digest = digest_hi·2^128 + digest_lo`), **appended
  after** the existing `(M.x, M.y)` returns. Modeled as a return (not a `pub`
  param) so it lands at the *end* of the public-input vector and does **not**
  shift `M` off index 12 (ACIR orders `pub` params before appended returns).
- **In-circuit logic:**
  - `msghash = sha256_var(signed_attrs, signed_attrs_len)` — **replaces** the
    free `msghash` witness; feeds the existing
    `verify_signature(pubkey_x, pubkey_y, sig, msghash)`.
  - Assert `signed_attrs[msg_digest_off..msg_digest_off+2] == [0x04, 0x20]`
    (OCTET STRING, length 32) — same witnessed-offset assertion pattern already
    used for the RNOKPP OID run.
  - Read the 32-byte value at `msg_digest_off+2`, pack into two 16-byte limbs,
    **return** them as `(digest_hi, digest_lo)`. The circuit thus *exposes* the
    signed `messageDigest`; the **service** enforces it equals
    `sha256(challenge(M))` (see Service). No provided-digest input to assert
    against in-circuit.
- **Public-input vector layout (16 words):** `today[8]` (0–7), `c1..c4` (8–11),
  `M.x` (12), `M.y` (13), `digest_hi` (14), `digest_lo` (15).

### Service — `service/proof-gate.mjs` + `service/server.mjs`

- `PUBLIC_INPUT_WORD_COUNT`: **14 → 16**. `M_X_WORD_INDEX` stays 12. Add
  `DIGEST_HI_WORD_INDEX = 14`, `DIGEST_LO_WORD_INDEX = 15`.
- `/v3/blind-eval` handler: a service-side `buildChallengeBytes(M, epoch)`
  (mirrors v2 `packages/oprf/src/attestation.ts`), `sha256`, split into hi/lo
  16-byte limbs, require they equal the proof's returned digest words
  `publicInputs[14], publicInputs[15]`. Mismatch → `409 ChallengeMismatch`.
  Stateless; service never sees the cert.
- Intent/epoch constants live in the service config (intent
  `crisp-qes-enroll-v3`, epoch `v3-2026`), kept byte-identical to the web client.

### Web — `packages/web/src/`

- **`pages/V3Enroll.tsx`**: adopt the v2 staged interface —
  `enterRnokpp → challenge(download) → signInDiia → upload → running → enrolled → saved`.
- **`lib/grumpkin.ts`**: reuse `M = r·H2C(RNOKPP)`.
- **`lib/enrollmentChallenge.ts`**: add a v3 variant
  (`intent:"crisp-qes-enroll-v3"`, Grumpkin `M` encoding as `0x<128hex>`
  affine `x‖y`, byte-exact with the service).
- **`lib/p7sWitness.ts`**: add `signed_attrs`, `signed_attrs_len`,
  `msg_digest_off`, `expected_digest` (hi/lo) to the `InputMap`
  (all sourced from `parseP7s`: `signedAttrs`, `messageDigest`,
  `messageDigestOffset`); assert the cert RNOKPP equals the entered RNOKPP.
- **`worker/v3prove.worker.ts`**: untouched (already default proof flavor after
  the 2026-05-31 fix).
- **`lib/v3enroll.ts`**: orchestration — thread the entered RNOKPP + `r` +
  challenge; include `expected_digest` limbs in `publicInputs`.

### SDK — `packages/sdk/src/p7s.ts`

Consumed unchanged. Already exposes `signedAttrs` (re-tagged to CMS hash-input
SET form), `signedAttrsSha256`, `messageDigest`, `messageDigestOffset`.

## Wire formats

- **Challenge bytes (byte-exact, both sides):**
  `{"intent":"crisp-qes-enroll-v3","epoch":"<epoch>","blindedInput":"0x<128hex>"}`
  — UTF-8, no whitespace, fixed key order, no trailing newline. `<128hex>` is the
  Grumpkin `M` affine encoding `x(32B BE) ‖ y(32B BE)` = 64 bytes, matching the
  service's `pointToHex` and web `grumpkin.ts`, byte-identical on both sides.
- **digest limbs:** `digest_hi = sha256(challenge)[0..16]` BE,
  `digest_lo = sha256(challenge)[16..32]` BE, each a field word. The circuit
  returns these; the service recomputes `sha256(challenge(M))` and compares.

## Risks & decision gates

### `SA_LEN` / prove memory (sanity check, NOT a hard gate)

iOS's 384 MiB cap is **not** a constraint for this work (user decision,
2026-05-31). The only budget is **prove memory < 1 GB RAM**. `sha256_var(signed_attrs)`
raises gate count (~118k today) modestly; this stays well under 1 GB.

After the circuit edit, as a sanity check (not a blocker): compile, record gate
count, and measure native prove memory once via `bench/v2-mem-floor.mjs`. Set
`SA_LEN` to a tight bound on the real Diia `signedAttrs` length (one real sample)
for gate efficiency. No desktop-only fallback; all platforms proceed.

### Fixture regeneration

New circuit → new VK → all committed `enroll_commit_v2` artifacts
(`proof`, `public_inputs`, `vk`, `vk_hash`, witness `.gz`) regenerate, plus the
web `public/v3` + `dist/v3` copies. This **also clears** the pre-existing stale
`register-test.mjs` `NullifierMismatchedM` failures as a side effect. Redeploy
service + web. On-chain tree is genesis (leafCount 0) → no migration.

## Test plan

- **Circuit roundtrip** (synthetic Diia-shaped cert + challenge): prove + verify.
- **Negative**: a `.p7s` signed over a *different* challenge → in-circuit
  `expected_digest` assert fails (forge-style test).
- **`proof-gate` unit**: 16-word layout; challenge reconstruction + hi/lo split;
  `ChallengeMismatch` on mismatch.
- **`p7sWitness.test.ts`**: `signedAttrs` / `messageDigest` extraction +
  RNOKPP-equality check.
- **Prove-memory sanity check**: native prove < 1 GB RAM (not a gate).
- **End-to-end** (`register-test.mjs`): updated for the new public inputs;
  green after fixture regeneration.

## Security notes

- The binding chain becomes: **live Diia signature** over `signedAttrs`
  (in-circuit `sha256` → ECDSA) → `signedAttrs.messageDigest == sha256(challenge)`
  → challenge commits to this session's random `M` → `M` provably derived from
  the cert's RNOKPP. A stale/leaked `.p7s` cannot satisfy it without signing
  *this* session's challenge.
- Operator-blindness preserved: service sees only `M`, the reconstructed
  challenge, and the public digest — never the cert, RNOKPP, or signature.
- EXPERIMENTAL / UNAUDITED — the `cert[]`↔`pubkey` linkage remains a separate
  open audit item.
