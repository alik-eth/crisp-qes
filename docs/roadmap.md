# CRISP-QES Roadmap

> **Status:** living document. Last updated 2026-05-31.
> **Frame:** the path from an *experimental, operator-blind demo* → an *auditable production identity layer*, with a parallel research track that protects and extends the novel core (**Grumpkin in-circuit OPRF + Diia QES binding**).

## Where we are today

Deployed v3 on **Base Sepolia** — operator-blind Noir/UltraHonk enrollment, single-key Grumpkin OPRF (`crisp-qes-oprf-grumpkin.fly.dev`), on-chain signing + passkey vault. The public demo runs on a **synthetic certificate / test CA**. The in-circuit **Diia trust-chain** (CA→leaf→key→challenge) is built and soundness-reviewed (no holes found; 9/9 tests, fits the 2¹⁹ UltraHonk domain) but **local-only — not yet pushed or deployed** (branch `feat/diia-trust-chain`).

**Honest baseline:** experimental and **unaudited**. Self-review has been rigorous (it caught and fixed a real free-witness forgery bug), but no independent audit has been done. For research and testing — not yet high-stakes voting.

---

## Track 1 — Path to Production

### 🔵 NOW — land the trust-chain (close the self-asserted-identity gap)

The deployed circuit takes `cert[]` and `pubkey` as free witnesses, so enrollment identity is currently self-asserted. The trust-chain work closes this.

- **Web witness** — `packages/web/src/lib/p7sWitness.ts` emits `leaf_tbs` / `leaf_cert_sig` / `ca_pubkey` / offsets from `parseP7s`; drop the free `cert[]`.
- **Fixtures / VK + E2E** — regenerate `target/{proof,vk,vk_hash}` (public outputs `M`/digest unchanged); E2E enroll → service verify → sign on Base Sepolia.
- **iOS prove-memory** — *measured (bb.js WasmWorker): floor = **832 MiB**, exactly at the iOS Safari reservation ceiling.* The chain check did **not** regress it (276,910→456,811 gates stayed in the 2¹⁹ domain), but there is **no headroom** — iOS viability rests on whether real devices honor a >832 MiB reservation. On-device Safari confirmation still pending.
- **Push + deploy** the circuit to service + web.

**Real-Diia E2E: VALIDATED (2026-05-31).** A real Diia `.p7s` was proven end-to-end against the **production** pinned CA: leaf TBS 1203 B, issuing CA = pinned `UA-43395033-2311`, `nargo execute` solved, and bb.js prove+verify (service flavor) **passed**. The spec's out-of-band real-cert validation is done — the design works on a real Ukrainian eID, not just synthetic.

**Definition of done:** deployed enrollment identity is no longer self-asserted — RNOKPP/DOB are read from a CA-authenticated certificate, and a forged/unpinned cert fails closed. *(Circuit + real-cert proof validated locally; web witness builder + service redeploy remain.)*

### 🟢 NEXT — make it real, reduce operator trust

- **Real Diia-CA enrollment end-to-end** — replace the synthetic test CA in the demo path; wire real `.p7s` parsing through to a real-Diia happy path. *Highest-leverage item — most security caveats trace back to this.*
- **Threshold OPRF productionization** — take the `packages/oprf/v3-grumpkin/threshold/` t=5/n=7 prototype to a real DKG (Feldman/Pedersen commitments + complaint rounds) and wire it into the enrollment path. Removes the single-key "operator must be trusted not to brute-force the nullifier mapping" caveat → unlocks the "operator learns nothing" claim.
- **On-chain admin-settable CA root** — Merkle commitment so pinned Diia CA keys rotate without recompiling the circuit.

### 🟡 LATER — hardening

- **External security audit** — hard gate for any "production" / high-stakes positioning. Currently self-audited only.
- **iOS native-app track** — only if a future heavier circuit ever exceeds the browser WASM ceiling.
- **Encrypted tally (Interfold / CRISP FHE)** — *the second half of the "two committees" architecture; not yet built.*
  - **Why:** enrollment (OPRF + ZK) already makes signatures **unlinkable** — the registry never learns *who* you are. But the count is currently a **transparent on-chain counter**: an observer sees each anonymous nullifier's support and the running total. An encrypted tally adds the missing axis — **vote-content secrecy** (with multi-option ballots, hide *how* the votes split), **no running-count leak** (no bandwagon/strategic effects mid-vote), and **threshold-only disclosure** (decrypt just a "support > X?" predicate, revealing neither the exact count nor the distribution). It's what turns "anonymous voting on a public count" into a "secret ballot with programmable disclosure."
  - **How:** consume **Interfold's** (formerly Enclave) **CRISP** threshold-FHE (BFV) **ciphernode committee** as a *downstream client* — we do **not** build the committee. Each support signature becomes a 1-bit encrypted flag; the committee homomorphically aggregates and threshold-decrypts per the petition's policy (`threshold-only` / `full-count` / `never`). Client-side, each vote needs a Greco-style proof that the ciphertext encrypts a valid ballot. This is the **tally committee** (Interfold) sitting alongside our **enrollment committee** (the Grumpkin OPRF) — same "no single operator sees the private input" guarantee, each using the production-ready primitive for its job.
  - **Status:** designed (see v2-refined spec §4), **not implemented** — the live demo's tally is transparent. Gated on enrollment hardening + the Interfold integration. (Replacing FHE-PSI-at-enrollment with the OPRF was a deliberate split: FHE is the right tool for *tally*, not for the set-membership/uniqueness check at enrollment.)

---

## Track 2 — Research & Novelty *(parallel, first-class)*

### 🔵 NOW

- **Soundness / threat-model formalization** — write up the verified properties (CA→leaf→key→challenge chain, operator-blindness, OPRF Sybil-resistance, fail-closed behavior) as a citable threat model. Basis for the external audit and the public/pitch security notes.

### 🟢 NEXT

- **Multi-country / multi-QTSP (eIDAS)** — multiple pinned CA roots, variable-length `serialNumber`, per-country trust anchors. The (parked) longfellow build already mapped this structure.
- **Threshold-OPRF DKG research** — the verification/complaint-round design feeding Track 1's threshold productionization.

### 🟡 LATER / conditional

- **Fork enrollment proving onto zkID / OpenAC** *(conditional on open-sourcing)* — once OpenAC is open-sourced, evaluate rebasing enrollment on its anonymous-credential proving machinery. **Not a drop-in:**
  - OpenAC verifies **mdoc** (ISO 18013-5 / mDL, COSE/CBOR credentials). Diia QES is **eIDAS AdES** (CAdES / `p7s`, CMS over X.509 P-256). → requires a **fork that replaces/extends OpenAC's credential-verification layer** with the same Diia CA→leaf→`signedAttrs` chain we verify in-circuit today.
  - OpenAC does not supply Sybil-resistance / operator-blindness → **graft our custom Grumpkin OPRF** (per-person nullifier + blinded enrollment) on top.
  - **Honest consequence:** because we fork + change the credential format + add custom OPRF, we do **not** inherit OpenAC's audit — those three deltas (AdES verifier, OPRF, integration) re-expand our own audit surface. The real upside is **alignment with an open anonymous-credential ecosystem + reuse of OpenAC's proving framework**, not offloading the audit.
  - *Gates:* OpenAC open-sourced; license; proving-stack curve/field compatibility with our P-256 chain + Grumpkin OPRF; whether its circuit framework can express CAdES `p7s` verification at all.
- **Post-quantum + transparent (no-SRS) enrollment (longfellow)** — complete C++ circuit on `feat/longfellow-oprf-enrollment`, un-merged. Resume **only** if PQ / no-trusted-setup becomes a hard requirement (~2.81 GiB peak, loses iOS-in-browser → pairs with the native-app track).
- **Novelty positioning** — keep claims narrow: novel = **Grumpkin in-circuit OPRF + Diia QES binding**; the surrounding architecture (ZK identity, nullifiers, blind enrollment, threshold OPRF) is prior art (Rarimo Freedom Tool, World ID, zk-X509, RFC 9497).

### ⛔ Closed

- **SP1 on-chain longfellow verification** — abandoned; do not revisit.

---

## Cross-cutting (continuous)

- Audit-readiness, reproducible fixtures, the soundness/security notes for landing + pitch.
- **Recovery:** within-epoch Diia recovery is shipped — stays inside constraints (no mnemonic / seed-phrase / server-backup recovery).

---

## Sequencing

- **Critical path to "production":** trust-chain deploy (NOW) → real-Diia wiring (NEXT) → external audit (LATER).
- **Threshold OPRF** runs in parallel and independently gates the privacy ("operator learns nothing") claim.
- **OpenAC fork** and the **external audit** are *independent* credibility routes, **not substitutes** — the audit covers whatever enrollment stack we ship, OpenAC-forked or not. (The fork is a research bet on ecosystem alignment, not an audit shortcut.)
