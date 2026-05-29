// Single-shot probe at iPhone SE (375x667) — the worst-case mobile width
// we care about. Captures landing, petitions, enroll-initial, and the
// masthead wrap behavior at this narrowest baseline.
import { writeFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

const URL_BASE = process.argv[2] ?? "http://localhost:4173";
const OUT = "/data/Develop/crisp-qes/bench/ux-screens/head-r2-se";
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 375, height: 667 }, locale: "uk-UA" });
const page = await ctx.newPage();

async function snap(label) {
    const m = await page.evaluate(() => {
        const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
        const rectOf = (el) => { const r = el.getBoundingClientRect(); return { top: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) }; };
        const nav = Array.from(document.querySelectorAll(".masthead__meta button")).map(b => ({ text: b.textContent?.trim(), rect: rectOf(b) }));
        const prim = Array.from(document.querySelectorAll("button.btn--accent")).filter(visible).map(b => ({ text: b.textContent?.trim(), rect: rectOf(b) }));
        const mastheadH = document.querySelector(".masthead")?.getBoundingClientRect().height;
        return { vp: { w: window.innerWidth, h: window.innerHeight }, scrollH: document.documentElement.scrollHeight, navWraps: nav, mastheadH: Math.round(mastheadH), primary: prim };
    });
    await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
    return { label, ...m };
}

const records = [];
await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
records.push(await snap("se-landing"));

// Petitions
const langBtn = page.locator(".masthead__meta button").first();
await langBtn.click();
await page.waitForSelector(".section, .error-line, .petition-grid", { timeout: 10000 });
await page.waitForTimeout(500);
records.push(await snap("se-petitions"));

// Enroll
await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
const navBtns = await page.locator(".masthead__meta button").all();
for (const b of navBtns) {
    const t = ((await b.textContent()) ?? "").toLowerCase();
    if (t.includes("реєстр") || t.includes("enroll")) { await b.click(); break; }
}
await page.waitForSelector(".section__title", { timeout: 8000 });
await page.waitForTimeout(500);
records.push(await snap("se-enroll-initial"));

await browser.close();
writeFileSync(`${OUT}/snapshot.json`, JSON.stringify({ records }, null, 2));
console.log(JSON.stringify(records.map(r => ({ l: r.label, scrollH: r.scrollH, screensTall: +(r.scrollH/r.vp.h).toFixed(2), mastheadH: r.mastheadH, navN: r.navWraps?.length, primaryY: r.primary?.[0]?.rect?.top })), null, 2));
