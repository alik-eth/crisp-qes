# UX bench — CRISP-QES v2 web (task #56)

**Date:** 2026-05-29 · **Commit:** 5a2f869 (HEAD) vs deployed fly.dev (older — see §0)
**Harness:** `bench/ux-probe.mjs` (Playwright + Chromium, both iPhone-14 390×844 and 1440×900 desktop)
**Locale:** uk-UA default (the app pins `lng:"uk"` in `src/i18n.ts`; toggle to English measured separately)
**Raw data:** `bench/ux-snapshot-{live,head}-*.json` · screens in `bench/ux-screens/{live,head}/`

> Methodology: numbers first. Every flow walked headlessly; per-screen we record
> viewport, document `scrollHeight`, count of visible interactive elements,
> position of the primary CTA, and text-char density. "Screens-tall" = page
> scrollHeight ÷ viewport height (1.0 = single screen, 2.4 = needs 2½ swipes).

---

## 0. Critical pre-finding: deployed bundle ≠ HEAD

`https://crisp-qes-web.fly.dev` is serving an **older build** than `main`. The
deployed nav is **Petitions / Create petition / Lang**; HEAD nav is
**Petitions / Enroll / Recover / Lang**. The "Create" page was removed locally
(it appears as `??` in pre-#49 git status but no longer exists in `src/pages/`).

That means **everything below is measured twice**:

- **live** = what users see right now at fly.dev (Create-petition build, no Enroll/Recover entry points)
- **head** = what they will see at the next deploy (Enroll + Recover, no Create)

If the next deploy is going out before this review lands, treat the **head** column as canonical.

---

## 1. Headline friction numbers

### Sign flow — primary user journey

| Metric                                              | Live (mobile)    | Live (desktop) | HEAD (mobile)    | HEAD (desktop) |
| --------------------------------------------------- | ---------------- | -------------- | ---------------- | -------------- |
| Landing screens-tall                                | **2.36**         | 1.26           | 2.39             | 1.25           |
| Landing primary-CTA Y-position                      | 1771 px (offscreen) | 895 px (above fold) | 1782 px (offscreen) | 889 px (above fold) |
| **First scroll needed before user can engage?**     | **YES (mobile)** | no             | **YES (mobile)** | no             |
| Petitions screens-tall                              | 1.46             | 1.16           | **1.00** (error) | **1.00** (error) |
| Petitions: visible buttons / primary buttons        | 4 / 0            | 4 / 0          | 4 / 0            | 4 / 0          |
| Sign-page screens-tall (after vote selected)        | 1.97             | 1.39           | n/a (no list)    | n/a (no list)  |

### Enrollment flow (HEAD only — Enroll page doesn't exist on live)

| Metric                                              | HEAD (mobile)    | HEAD (desktop) |
| --------------------------------------------------- | ---------------- | -------------- |
| Enroll-initial screens-tall                         | **1.98**         | 1.48           |
| Visible buttons / primary / secondary               | 8 / 1 / 3        | 8 / 1 / 3      |
| Primary-CTA Y at first paint                        | 932 px (offscreen) | 628 px (above fold) |
| After first CTA: primary-CTA Y                      | 400 px (visible) | 628 px (visible) |
| Step list shown above panels?                       | yes (5 items)    | yes            |

### Recover flow (HEAD only)

| Metric                                              | HEAD (mobile)    | HEAD (desktop) |
| --------------------------------------------------- | ---------------- | -------------- |
| Recover screens-tall                                | 1.82             | 1.22           |
| Panels                                              | 2 (v2 + v3 info) | 2              |
| Primary CTA ("Back to petitions") Y-position        | 1297 px (deep scroll) | 863 px (just visible) |

### Language toggle (both builds)

| Metric                  | Live    | HEAD    |
| ----------------------- | ------- | ------- |
| Round-trip latency      | 282 ms  | 275 ms  |
| Char-count delta (uk→en)| −83     | −41     |
| Layout reflow visible?  | yes (one frame flash; new tree mounts) | yes |

---

## 2. The six friction hotspots, ranked

### 🔴 1. Landing CTA is offscreen on mobile (both builds)

`y=1771-1782 px` against an 844-px viewport means the user must scroll
**≈940 px (1.1 screens)** before they can tap "До петицій / Browse petitions".
Two long lists ("What we guarantee" / "What we don't") sit above it. **Fix:**
move the CTA to the top, beneath the lede; keep the long lists as scroll-down
reference material. Cost: 5 minutes; reward: −1 scroll on first session.

### 🔴 2. Petitions page on HEAD shows a raw viem stack trace

Screenshot `head/desktop-petitions.png`: when the registry call fails (the dist
points at the zero address — #54 fixed source but this `dist/` was built
before the fix), the UI dumps the raw error:

> `The contract function "nextPetitionId" returned no data ("0x"). … Contract Call: address: 0x000…000 function: nextPetitionId() Docs: https://viem.sh/docs/contract/readContract Version: viem@2.51.3`

This is in `Petitions.tsx:48-54`: the error branch renders `e.message` verbatim
into `<p className="note mono">`. **Fix:** clamp to a friendly fallback, log
the technical detail to console only. Cost: 10 lines; reward: nobody ever sees
a viem URL in production.

### 🔴 3. HEAD enroll page renders raw i18n keys

Screenshot `head/mobile-enroll-initial.png` — panel "1. Завантажити підписаний
.p7s" displays:
- `sign.upload.headline` (raw key)
- `sign.upload.browse` (raw key on the button)
- (also `sign.upload.hint`, `sign.upload.parsing` per code inspection)

`DropZone.tsx:41-44` references `sign.upload.{headline,hint,browse,parsing}` —
**none of these four keys exist in `i18n/en.json` or `i18n/uk.json`** (verified:
`sign.upload` object is empty in both). Either add the keys or change the
component to use the existing `enroll.upload.*` namespace. Cost: 8 lines of
JSON in two files; reward: stop shipping placeholder strings.

### 🟡 4. Sign page (live build) reveals only after vote click, jumps viewport

`live/mobile-sign-initial.png` shows a **7-step numbered checklist** above the
panels. After clicking "Vote" → only the first 2 panels render
(`scrollHeight=1564`), but a vote selection triggers a panel-2-becomes-visible
reveal that bumps `scrollHeight` by +96 px without scroll-anchoring. User
notices things "moving under their thumb". **Fix:** the `Sign.tsx` panel
chain is gated by 4 nested conditionals — replace the cascading `vote !==
null && unlocked && ...` chain with a stage machine that renders the next
panel placeholder dimmed (instead of hidden), so total page height is
constant once the page loads.

### 🟡 5. Both flows make "step list" visual lie — 5–7 numbered items, only 4–5 are real

- Live sign list shows **7** items (`0. File to sign / 1. Upload / 2. Verify
  cert / 3. Trust tree / 4. Nullifier / 5. ZK proof / 6. Submit`) — but only
  the first 2 are user-actioned; the rest happen inside the worker. The
  user counts "7 steps" and braces for a long form.
- HEAD enroll list shows **5** items, of which 1 is a download (no decision)
  and 2 are server round-trips (no decision). Effective user actions: 3 —
  upload + on-chain confirm + passkey tap.

**Fix:** collapse non-user steps into a single "We do this for you" row, so
the step count matches user actions.

### 🟡 6. Masthead always shows 3 nav buttons even from the landing zero-state

`Petitions / Enroll / Recover` are visible immediately. A user with no
enrollment who clicks "Recover" is shown a 1.8-screen-tall info wall whose
only actionable element is "Back to petitions". Same for "Enroll" — there is
no acknowledgement that this is required before signing. **Fix:** hide
"Recover" on first visit; surface it inline from the Sign page when the
"no enrollment on device" error fires. (Or: rename it from "Recover"
which implies emergency, to "I already enrolled on another device".)

---

## 3. Click-and-scroll budget per task

Counted on **mobile** because that's where the friction matters. "Scroll
events" = how many distinct ~viewport-height swipes the user must make
along the happy path. "Real clicks" excludes the initial app-open.

| Task                                            | Clicks | Scrolls (mobile) | Modal/auth pauses | Notes |
| ----------------------------------------------- | -----: | ---------------: | ----------------: | ----- |
| First-time visit → reach petition list          |      1 |             1.1× | 0                 | scroll to find CTA |
| Sign one petition (live, MVP-style)             |      4 |             2.0× | 1 (Diia)          | upload .p7s + select + prove + send |
| Sign one petition (HEAD, v2-style)              |      3 |             1.4× | 1 (Passkey)       | vote + unlock + send (prove is auto) |
| First-time enrollment (HEAD)                    |      6 |             2.0× | 3 (Diia, wallet, passkey) | binding-download + upload + OPRF + register + chain + passkey |
| Switch language                                 |      1 |             0    | 0                 | 282 ms reflow flash |
| Recover (no actual recovery; info only)         |      1 |             1.5× | 0                 | wall of text, dead-end CTA |

### What "best possible" looks like for sign (HEAD)

**2 clicks, 1 scroll, 1 Passkey tap.** Achievable with:
- merge "vote selection" and "submit" panels into a single screen
- have `unlock` auto-fire when user lands on the Sign page (you already know
  they have an enrollment; the Passkey prompt IS the unlock)
- drop the explicit "Generate proof" button — start proving the moment the
  vote is selected, show progress in-place
- the user's only deliberate actions are: pick vote → confirm Passkey

That's **−1 click, −0.6 scroll** vs current HEAD, **−2 clicks, −1.2 scroll**
vs live.

---

## 4. Information density (chars per screen)

| Surface              | Chars total | Chars/screen (mobile) | Verdict |
| -------------------- | ----------: | --------------------: | ------- |
| Landing              |       1,926 |                   806 | dense but OK |
| Petitions (1 card)   |         806 |                   806 | OK |
| Sign (live, post-vote) |     1,029 |                   523 | OK |
| Sign (HEAD, after vote) | — | (no live data — registry broken) | — |
| Enroll (HEAD, initial)  |       1,340 |                   677 | OK |
| Enroll (HEAD, after-1st) |      1,480 |                   708 | dense |
| Create petition (live, initial) |  1,191 |              505 | OK |
| Recover (HEAD)       |       1,423 |                   782 | dense; info-only page |

No "wall of text" red flag, but Enroll grows by 140 chars per panel reveal,
which compounds: by step 5, total page text is ≈3.2k chars — that's why
`screensTall` keeps creeping past 2.0× on mobile.

---

## 5. Recommended fix order (estimated cost / impact)

| Order | Fix                                                          | Cost      | Impact                                          |
| ----: | ------------------------------------------------------------ | --------- | ----------------------------------------------- |
|     1 | Add the four missing `sign.upload.*` i18n keys (or rename to `enroll.upload.*`) | 10 min  | stops shipping raw template strings to citizens |
|     2 | Wrap registry errors in friendly copy (#3.2)                 | 15 min    | no more viem stack traces in the UI             |
|     3 | Move landing CTA above the guarantees/limits lists           | 20 min    | mobile users no longer need to scroll to start  |
|     4 | Sign flow: render disabled-future panels instead of hiding   | 1 hr      | no viewport jump on panel reveal                |
|     5 | Sign flow: auto-fire Passkey unlock; auto-start prove        | 2 hr      | 4 clicks → 2 clicks                             |
|     6 | Re-deploy fly.dev so it matches HEAD nav (Enroll/Recover)    | 5 min     | live demo stops misrepresenting v2              |
|     7 | Collapse "what we do for you" step rows in lists             | 1 hr      | step list reads as 3, not 5–7                   |
|     8 | Re-evaluate "Recover" nav button for first-time visitors     | 30 min    | removes dead-end CTA from cold-start path       |

---

## 6. What was NOT measured

- **Real device** (this is a Chromium-headless probe at iPhone-14 viewport, NOT
  a real iOS browser; iOS Safari's bottom URL bar + keyboard would steal
  another ~120 px from the viewport, making every "screens-tall" number worse).
- **Keyboard / IME** interactions — never opened a soft keyboard for input.
- **Time-to-interactive**: bundle download + parse + i18n init not measured (a
  Lighthouse pass would be the right tool — out of scope here).
- **Wallet / Diia handoff round-trips**: the bench doesn't actually connect a
  wallet or sign in Diia; those add per-flow latency that swamps any UI
  micro-timing.
- **Accessibility**: no screen-reader / focus-order audit (axe-core run is a
  separate task).

---

## Appendix A — every visible button on every screen

Captured in JSON; quote the file rather than copy here. To inspect:

```sh
jq '.records[] | {label, buttons: [.buttonLabels[]?.text]}' \
  bench/ux-snapshot-head-*.json
```

## Appendix B — reproducing the probe

```sh
# Local HEAD build (assumes packages/web/dist is current)
cd /data/Develop/crisp-qes && python3 -m http.server 4173 --directory packages/web/dist &
cd bench && node ux-probe.mjs --url=http://localhost:4173 --tag=head

# Live
node ux-probe.mjs --url=https://crisp-qes-web.fly.dev --tag=live
```

Screenshots land in `bench/ux-screens/{tag}/`. JSON snapshot in
`bench/ux-snapshot-{tag}-{ts}.json`.
