// UX probe — quantitative friction audit. Walks the v2 web app, counts
// clicks, scrolls, viewport jumps, panel reveals at iPhone-14 and
// 1440 desktop viewports. Language-agnostic: navigates by button-label
// keyword match (uk OR en), captures every visible label into JSON so
// the report can quote what the user actually sees in both locales.
//
// Usage: node ux-probe.mjs [--url=...] [--tag=live|head]
// Two passes recommended (live + local HEAD build) — see the README block
// in bench/ux-results-2026-05-29.md.

import { writeFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

function arg(n, d) {
    const m = process.argv.find((a) => a.startsWith(`--${n}=`));
    return m ? m.slice(n.length + 3) : d;
}
const URL_BASE = arg("url", "https://crisp-qes-web.fly.dev");
const TAG = arg("tag", "live");
const OUT_DIR = arg("outDir", `/data/Develop/crisp-qes/bench/ux-screens/${TAG}`);
mkdirSync(OUT_DIR, { recursive: true });

// Label keyword sets — match BOTH locales. Substring, case-insensitive.
const NAV_KEYWORDS = {
    petitions: ["петиці", "petition"],   // Петиції / Petitions
    enroll: ["реєстра", "enroll"],       // Реєстрація / Enroll
    recover: ["віднов", "recover"],      // Відновити доступ / Recover
    create: ["створ", "create"],         // Створити петицію / Create a petition
};
const CTA_KEYWORDS = {
    browse: ["до петицій", "browse petit"],          // landing CTA
    sign: ["підпис", "vote", "проголос", "sign"],   // petition card primary
};

async function findByLabel(page, scopeSel, keywords) {
    const all = await page.locator(scopeSel).all();
    for (const loc of all) {
        const t = ((await loc.textContent()) ?? "").trim().toLowerCase();
        if (keywords.some((k) => t.includes(k))) return loc;
    }
    return null;
}

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
    viewport: { width: 390, height: 844 },
    userAgent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    deviceScaleFactor: 3,
    locale: "uk-UA",
});
const desktopCtx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: "uk-UA",
});

async function snapshot(page, label) {
    const m = await page.evaluate(() => {
        const visible = (el) => {
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
        };
        const rectOf = (el) => {
            const r = el.getBoundingClientRect();
            return { top: Math.round(r.top), left: Math.round(r.left), w: Math.round(r.width), h: Math.round(r.height) };
        };
        const all = Array.from(document.querySelectorAll("button, a[href], input, textarea, select"));
        const visEls = all.filter(visible);
        const primary = Array.from(document.querySelectorAll("button.btn--accent, a.btn--accent")).filter(visible);
        const ghost = Array.from(document.querySelectorAll("button.btn--ghost, button.btn--link, a.btn--ghost")).filter(visible);
        const panels = Array.from(document.querySelectorAll(".panel"));
        const sections = Array.from(document.querySelectorAll(".section"));
        const headings = Array.from(document.querySelectorAll("h1,h2,h3,h4")).map((h) => h.textContent?.trim().slice(0, 80));
        const navBtns = Array.from(document.querySelectorAll(".masthead__meta button")).map((b) => b.textContent?.trim());
        return {
            viewport: { w: window.innerWidth, h: window.innerHeight },
            scrollHeight: document.documentElement.scrollHeight,
            screensTall: +(document.documentElement.scrollHeight / window.innerHeight).toFixed(2),
            interactiveCount: { all: all.length, visible: visEls.length, primary: primary.length, secondary: ghost.length },
            panelCount: panels.length,
            sectionCount: sections.length,
            headings,
            navLabels: navBtns,
            textChars: (document.body.innerText || "").length,
            buttonLabels: visEls
                .filter((b) => b.tagName === "BUTTON" || (b.tagName === "A" && b.classList.contains("btn")))
                .map((b) => ({ text: (b.textContent || "").trim().slice(0, 60), cls: b.className, rect: rectOf(b) })),
            primaryRects: primary.map((b) => ({ text: (b.textContent || "").trim().slice(0, 60), rect: rectOf(b) })),
            panelInfo: panels.map((p) => ({
                title: (p.querySelector(".panel__title")?.textContent ?? "").trim().slice(0, 80),
                rect: rectOf(p),
                textChars: (p.innerText || "").length,
                buttons: Array.from(p.querySelectorAll("button")).filter(visible).map((b) => ({
                    text: (b.textContent || "").trim().slice(0, 40),
                    cls: b.className,
                })),
            })),
            firstPrimaryTop: primary[0] ? rectOf(primary[0]).top : null,
            firstPrimaryRequiresScroll: primary[0] ? rectOf(primary[0]).top > window.innerHeight : null,
        };
    });
    const png = `${OUT_DIR}/${label}.png`;
    await page.screenshot({ path: png, fullPage: true });
    return { label, ...m, screenshot: png };
}

const records = [];

async function safe(name, fn) {
    try {
        return await fn();
    } catch (e) {
        console.log(`[!] ${name} failed: ${e.message.split("\n")[0]}`);
        return null;
    }
}

async function walk(ctxName, page) {
    // F1 — landing
    await safe(`${ctxName}/landing`, async () => {
        await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
        records.push(await snapshot(page, `${ctxName}-landing`));
    });

    // F1b — landing → petitions via CTA
    await safe(`${ctxName}/petitions`, async () => {
        const cta = await findByLabel(page, ".cta-row button.btn--accent, .section button.btn--accent", CTA_KEYWORDS.browse);
        if (cta) await cta.click();
        else await page.locator(".cta-row button.btn--accent").first().click();
        await page.waitForSelector(".petition-grid, .section .note, .error-line", { timeout: 20000 });
        await page.waitForTimeout(800);
        records.push(await snapshot(page, `${ctxName}-petitions`));
    });

    // F2 — sign first open petition (likely no enrollment → error)
    await safe(`${ctxName}/sign`, async () => {
        const voteBtn = page.locator(".petition-card button").first();
        if ((await voteBtn.count()) === 0) {
            console.log(`[F2] ${ctxName} / no Vote button on cards`);
            return;
        }
        await voteBtn.click();
        await page.waitForSelector(".section__title", { timeout: 5000 });
        await page.waitForTimeout(400);
        records.push(await snapshot(page, `${ctxName}-sign-initial`));
        const firstOpt = page.locator(".panel .actions button").first();
        if ((await firstOpt.count()) > 0) {
            await firstOpt.click();
            await page.waitForTimeout(400);
            records.push(await snapshot(page, `${ctxName}-sign-after-vote`));
        }
    });

    // F3 — enroll OR create (whichever the build exposes)
    await safe(`${ctxName}/enroll-or-create`, async () => {
        await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
        let nav = await findByLabel(page, ".masthead__meta button", NAV_KEYWORDS.enroll);
        const navLabel = nav ? "enroll" : "create";
        if (!nav) nav = await findByLabel(page, ".masthead__meta button", NAV_KEYWORDS.create);
        if (!nav) {
            console.log(`[F3] ${ctxName} / no enroll/create nav found`);
            return;
        }
        await nav.click();
        await page.waitForSelector(".section__title", { timeout: 8000 });
        await page.waitForTimeout(500);
        records.push(await snapshot(page, `${ctxName}-${navLabel}-initial`));

        // Try to click first .panel button to advance one step (suppress real downloads)
        const dl = page.locator(".panel button.btn--accent").first();
        if ((await dl.count()) > 0) {
            const dlPromise = page.waitForEvent("download", { timeout: 1500 }).catch(() => null);
            await dl.click({ force: true }).catch(() => {});
            const ev = await dlPromise;
            if (ev) await ev.cancel().catch(() => {});
            await page.waitForTimeout(400);
            records.push(await snapshot(page, `${ctxName}-${navLabel}-after-first-cta`));
        }
    });

    // F4 — recover
    await safe(`${ctxName}/recover`, async () => {
        await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
        const nav = await findByLabel(page, ".masthead__meta button", NAV_KEYWORDS.recover);
        if (!nav) {
            console.log(`[F4] ${ctxName} / no Recover nav (likely older build)`);
            return;
        }
        await nav.click();
        await page.waitForSelector(".section__title", { timeout: 8000 });
        await page.waitForTimeout(300);
        records.push(await snapshot(page, `${ctxName}-recover`));
    });

    // F5 — language toggle
    await safe(`${ctxName}/lang-toggle`, async () => {
        await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
        const allNav = page.locator(".masthead__meta button");
        const nCount = await allNav.count();
        if (nCount === 0) return;
        const langBtn = allNav.nth(nCount - 1); // language is always last
        const beforeLabel = (await langBtn.textContent())?.trim();
        const beforeChars = await page.evaluate(() => document.body.innerText.length);
        const t0 = Date.now();
        await langBtn.click();
        await page.waitForTimeout(250);
        const afterLabel = (await langBtn.textContent())?.trim();
        const afterChars = await page.evaluate(() => document.body.innerText.length);
        records.push({
            label: `${ctxName}-lang-toggle`,
            beforeLabel,
            afterLabel,
            charsBefore: beforeChars,
            charsAfter: afterChars,
            charDelta: afterChars - beforeChars,
            elapsedMs: Date.now() - t0,
        });
    });
}

console.log(`=== UX probe — ${TAG} — ${URL_BASE} ===`);
const mobile = await ctx.newPage();
await walk("mobile", mobile);
await mobile.close();

const desktop = await desktopCtx.newPage();
await walk("desktop", desktop);
await desktop.close();

await browser.close();

const ts = new Date().toISOString().replace(/[:.]/g, "-");
const out = `/data/Develop/crisp-qes/bench/ux-snapshot-${TAG}-${ts}.json`;
writeFileSync(out, JSON.stringify({ url: URL_BASE, tag: TAG, capturedAt: ts, records }, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[done] ${records.length} records, screens in ${OUT_DIR}`);
process.exit(0);
