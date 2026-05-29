// Enroll-flow happy-path / error-path probe. Targets c2647d6's auto-chain:
// after .p7s parse, OPRF auto-fires (no button); after OPRF success, register
// auto-fires (no button). Errors show Retry buttons.
//
// We can't run a real .p7s through Diia, so we drive the hidden file input
// with a synthetic blob. parseP7s will throw → upload-error branch. That's
// useful because the auto-chain shouldn't be reached and we shouldn't see
// any OPRF panel either. Then we also count buttons in the static initial state.

import { writeFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

const URL_BASE = process.argv[2] ?? "http://localhost:4173";
const OUT = "/data/Develop/crisp-qes/bench/ux-screens/head-r6-enroll";
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, locale: "uk-UA" });
const page = await ctx.newPage();

async function snap(label) {
    const m = await page.evaluate(() => {
        const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
        const rectOf = (el) => { const r = el.getBoundingClientRect(); return { top: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) }; };
        const all = Array.from(document.querySelectorAll("button")).filter(visible);
        const primary = all.filter(b => b.classList.contains("btn--accent"));
        const retry = all.filter(b => (b.textContent || "").toLowerCase().match(/повтор|retry|ще раз|спробу/));
        const panels = Array.from(document.querySelectorAll(".panel")).map(p => ({
            title: p.querySelector(".panel__title")?.textContent?.trim().slice(0, 60),
            buttonCount: Array.from(p.querySelectorAll("button")).filter(visible).length,
            primaryCount: Array.from(p.querySelectorAll("button.btn--accent")).filter(visible).length,
            buttonTexts: Array.from(p.querySelectorAll("button")).filter(visible).map(b => b.textContent?.trim().slice(0, 40)),
            hasProgress: !!p.querySelector(".progress"),
            hasErrorLine: !!p.querySelector(".error-line"),
        }));
        return {
            vp: { w: window.innerWidth, h: window.innerHeight },
            scrollH: document.documentElement.scrollHeight,
            allButtons: all.map(b => ({ text: (b.textContent || "").trim().slice(0, 50), cls: b.className.split(' ').filter(c => c.startsWith('btn')).join(' '), rect: rectOf(b) })),
            primaryCount: primary.length,
            primaryTexts: primary.map(b => b.textContent?.trim().slice(0, 60)),
            retryButtons: retry.map(b => b.textContent?.trim()),
            panels,
        };
    });
    await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
    return { label, ...m };
}

const records = [];

// Navigate to enroll
await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
const navBtns = await page.locator(".masthead__meta button").all();
for (const b of navBtns) {
    const t = ((await b.textContent()) ?? "").toLowerCase();
    if (t.includes("реєстр") || t.includes("enroll")) { await b.click(); break; }
}
await page.waitForSelector(".section__title", { timeout: 8000 });
await page.waitForTimeout(500);
records.push(await snap("initial"));

// Try to drive the upload with a garbage blob → triggers parseError branch.
// This proves the upload handler fires, but OPRF chain doesn't kick.
const fileInput = page.locator('input[type="file"]').first();
const garbageBlob = Buffer.from("not-a-real-p7s-just-bytes-to-trigger-the-parse-error-branch");
await fileInput.setInputFiles({ name: "fake.p7s", mimeType: "application/octet-stream", buffer: garbageBlob }).catch(e => console.log(`setInputFiles err: ${e.message.split('\n')[0]}`));
await page.waitForTimeout(800);
records.push(await snap("after-bad-upload"));

await browser.close();
writeFileSync(`${OUT}/snapshot.json`, JSON.stringify(records, null, 2));

console.log("\n=== Round-5 enroll probe ===");
for (const r of records) {
    console.log(`\n[${r.label}]  scrollH=${r.scrollH}  primaryButtons=${r.primaryCount}  visibleButtons=${r.allButtons.length}`);
    console.log(`  primary texts: ${JSON.stringify(r.primaryTexts)}`);
    if (r.retryButtons.length) console.log(`  retry buttons present: ${JSON.stringify(r.retryButtons)}`);
    for (const p of r.panels) {
        const flags = [p.hasProgress && "progress", p.hasErrorLine && "error"].filter(Boolean).join(",");
        console.log(`  panel "${p.title}" → ${p.buttonCount} btns (${p.primaryCount} primary) ${flags ? `[${flags}]` : ""} :: ${JSON.stringify(p.buttonTexts)}`);
    }
}
