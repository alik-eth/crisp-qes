# CRISP-QES — Security & Soundness Notes

> Honest, citable notes on what CRISP-QES guarantees, what it doesn't yet, and how the gaps are approached. Source material for the landing page, the pitch, and the eventual external audit. **Experimental / unaudited** — self-review only.

This doc is built up section by section; coercion resistance is the first.

---

## Coercion resistance

A system is **coercion-resistant** if a voter cannot prove to a third party how they voted — even if they want to, or are forced to. This is strictly harder than privacy or anonymity, and **CRISP-QES does not claim it today.** Enrollment is unlinkable (the operator-blind OPRF hides *who* you are), but the per-petition nullifier is **deterministic**, so a voter still holds the secret that could demonstrate their own vote to a coercer or vote-buyer. We treat coercion resistance as a layered goal, approached in stages rather than asserted:

- **Unlinkability — live.** The operator-blind OPRF + ZK enrollment mean no one — platform, chain, or operator — can tie a signature back to a person. This defeats *bulk* surveillance and retaliation, but not a voter who chooses to reveal their own secret.
- **Receipt-freeness via CRISP/FHE — roadmap.** Interfold's CRISP threshold-FHE committee would encrypt the ballots and reveal only the aggregate — or merely a "threshold reached" predicate. This removes the **public receipt**: there is no on-chain record showing how any anonymous voter voted, and under threshold-only disclosure, not even the totals. That sharply reduces casual vote-buying and coercion leverage, but it still doesn't stop a determined voter from handing over their own key.
- **Re-vote / revoke — live, partial.** A signature can be withdrawn or changed until the deadline, giving a coerced voter a later escape hatch — a mild mitigation, weak on its own against a coercer who re-checks.
- **JCJ-style fake credentials — v3 research.** The real fix: a voter registers genuine *and* decoy credentials; under coercion they surrender a decoy, and the ciphernode committee silently discards fake-credential votes at tally time under FHE. This is the research-grade, not-yet-built endgame — coercion resistance becomes a property of the *tally*, not something the voter has to enforce.

**In short:** CRISP/FHE buys receipt-freeness (no provable on-chain trace), and JCJ buys true coercion resistance — both on the roadmap. **Today the honest claim is unlinkability, not coercion resistance.**

---

## (planned) Soundness / threat model

To be written from the verified properties (CA→leaf→key→challenge chain, operator-blindness, OPRF Sybil-resistance, fail-closed behavior) — see `docs/roadmap.md` Track 2 "Soundness / threat-model formalization".
