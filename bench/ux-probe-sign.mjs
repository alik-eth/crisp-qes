// Sign-flow UX probe. Route-intercepts the registry RPC so we get a
// reachable Sign page without a populated on-chain registry. Measures:
//   - initial Sign render (no enrollment expected on a fresh browser)
//   - inline "I already enrolled →" affordance from #63 (YEL-6 option a)
//   - vote-selection scrollHeight delta (YEL-4 prediction test:
//     does the panel reveal still cause a viewport jump now that auto-
//     chain compressed the OPRF+Register steps in Enroll? On Sign, the
//     unlock+prove+submit chain is separate from auto-chain — we want
//     to know if the 96 px-per-reveal pattern from baseline still bites)
//
// WebAuthn is not driven (the Passkey API resists headless probing for
// security reasons). To exercise the post-unlock chain (prove/submit)
// we'd need to either (a) ship a `?devSign=1` flag on the web side that
// bypasses unlock and seeds a mock enrollment, or (b) hot-wire IndexedDB
// + override `evaluatePrfWithCredential`. Out of scope for round-6.
//
// Usage:
//   node ux-probe-sign.mjs --url=https://crisp-qes-web.fly.dev --tag=live-r6
//   node ux-probe-sign.mjs --url=http://localhost:4173 --tag=local-r6

import { writeFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

function arg(n, d) {
    const m = process.argv.find((a) => a.startsWith(`--${n}=`));
    return m ? m.slice(n.length + 3) : d;
}
const URL_BASE = arg("url", "http://localhost:4173");
const TAG = arg("tag", "local-r6");
const OUT = `/data/Develop/crisp-qes/bench/ux-screens/sign-${TAG}`;
mkdirSync(OUT, { recursive: true });

// Round-6 strategy: clicks through the petitions list IF the registry
// has at least one Open petition (post-fly-live Sepolia state). Against
// the local empty-Sepolia dist this short-circuits to capturing landing
// + petitions-empty only.
//
// A future round can add RPC-route interception to inject a synthetic
// petition response for `nextPetitionId()` (selector 0xfc9a31c0) and
// `getPetition(uint256)` (selector 0x9a3a85f6) so Sign is reachable
// without any on-chain state. The ABI tuple encoding for `getPetition`
// (id, creator, fullText, deadline, threshold, status, mode, yes/no/
// abstain counts) is the bottleneck and was de-scoped for round-6.

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
    viewport: { width: 390, height: 844 },
    locale: "uk-UA",
});
const page = await ctx.newPage();

async function snap(label) {
    const m = await page.evaluate(() => {
        const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
        const rectOf = (el) => { const r = el.getBoundingClientRect(); return { top: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) }; };
        const all = Array.from(document.querySelectorAll("button, a[href]")).filter(visible);
        const primary = Array.from(document.querySelectorAll("button.btn--accent")).filter(visible);
        const panels = Array.from(document.querySelectorAll(".panel"));
        const inlineErrPanel = document.querySelector(".panel--inline-error");
        const recoverLink = document.querySelector(".panel--inline-error .btn--link");
        const errLines = Array.from(document.querySelectorAll(".error-line"));
        return {
            vp: { w: window.innerWidth, h: window.innerHeight },
            scrollH: document.documentElement.scrollHeight,
            screensTall: +(document.documentElement.scrollHeight / window.innerHeight).toFixed(2),
            buttonCount: all.length,
            primaryCount: primary.length,
            panelCount: panels.length,
            inlineErrorPanel: inlineErrPanel ? {
                rect: rectOf(inlineErrPanel),
                errorText: inlineErrPanel.querySelector(".error-line")?.textContent?.trim().slice(0, 100),
                hasRecoverLink: !!recoverLink,
                recoverText: recoverLink?.textContent?.trim(),
            } : null,
            errorTexts: errLines.map(e => e.textContent?.trim().slice(0, 120)),
            primaryTexts: primary.map(b => b.textContent?.trim().slice(0, 60)),
        };
    });
    await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
    return { label, ...m };
}

const records = [];

console.log(`=== ux-probe-sign — ${TAG} — ${URL_BASE} ===`);

// 1. Landing
await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
records.push(await snap("landing"));

// 2. Petitions list. If registry is populated, click into petition #1
// and probe Sign. Otherwise capture the empty/error state.
const nav = await page.locator(".masthead__meta button").all();
for (const b of nav) {
    const t = ((await b.textContent()) ?? "").toLowerCase();
    if (t.includes("петиц") || t.includes("petition")) { await b.click(); break; }
}
await page.waitForSelector(".petition-grid, .section .note, .error-line", { timeout: 15000 });
await page.waitForTimeout(800);
records.push(await snap("petitions"));

// 3. Try to enter Sign. The Sign-page reachability depends on registry
// state. Locally (empty Sepolia or wrong-chain dist) this falls through.
const voteBtn = page.locator(".petition-card button").first();
const haveVoteBtn = (await voteBtn.count()) > 0;
if (haveVoteBtn) {
    console.log("[r6] petition card found → clicking to enter Sign view");
    await voteBtn.click();
    await page.waitForSelector(".section__title", { timeout: 8000 });
    await page.waitForTimeout(500);
    records.push(await snap("sign-initial"));

    // Vote-selection YEL-4 test: snapshot scrollHeight BEFORE and AFTER
    // clicking the first vote option. The delta = the panel-reveal jump.
    const beforeScroll = await page.evaluate(() => document.documentElement.scrollHeight);
    const firstVoteBtn = page.locator(".panel .actions button").first();
    if ((await firstVoteBtn.count()) > 0) {
        await firstVoteBtn.click();
        await page.waitForTimeout(400);
        const afterScroll = await page.evaluate(() => document.documentElement.scrollHeight);
        records.push({
            label: "yel4-vote-reveal-delta",
            beforeScrollH: beforeScroll,
            afterScrollH: afterScroll,
            delta: afterScroll - beforeScroll,
            verdict: (afterScroll - beforeScroll) > 50
                ? `still jumps (+${afterScroll - beforeScroll}px) — YEL-4 still applies; consider #60`
                : `no visible jump (Δ=${afterScroll - beforeScroll}px) — YEL-4 effectively de-escalated to polish`,
        });
        records.push(await snap("sign-after-vote"));
    }

    // #63 inline affordance: this branch only fires if hasEnrollment === false.
    // The probe is in a fresh browser context (no enrollment), so we should
    // see the panel--inline-error block at the top of the Sign view.
    const inlineErrSnapshot = records.find(r => r.label === "sign-initial")?.inlineErrorPanel;
    if (inlineErrSnapshot) {
        console.log(`[r6] #63 affordance: error="${inlineErrSnapshot.errorText}", hasRecover=${inlineErrSnapshot.hasRecoverLink}, recoverText="${inlineErrSnapshot.recoverText}"`);
    } else {
        console.log(`[r6] no panel--inline-error on Sign — either #63 not rendering or hasEnrollment is true`);
    }
} else {
    console.log("[r6] no petition card → registry empty / wrong chain. Sign view unreachable from local dist. Will rerun against fly-live.");
}

await browser.close();

const out = `/data/Develop/crisp-qes/bench/ux-snapshot-sign-${TAG}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
writeFileSync(out, JSON.stringify({ url: URL_BASE, tag: TAG, records }, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[done] ${records.length} records, screens in ${OUT}`);
process.exit(0);
