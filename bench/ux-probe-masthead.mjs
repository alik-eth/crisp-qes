// Multi-width masthead probe. Captures mastheadH + nav visibility
// at 360 (iPhone mini), 375 (iPhone SE), 390 (iPhone-14), 420 (just-above breakpoint).
// Used to validate two-tier @media (max-width: 419px) + (max-width: 379px).
import { writeFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

const URL_BASE = process.argv[2] ?? "http://localhost:4173";
const OUT = "/data/Develop/crisp-qes/bench/ux-screens/head-r5-masthead";
mkdirSync(OUT, { recursive: true });

const WIDTHS = [
    { w: 360, h: 780, name: "iphone-mini-360" },     // < 380, expect full trim
    { w: 375, h: 667, name: "iphone-se-375" },        // < 380, expect full trim
    { w: 390, h: 844, name: "iphone-14-390" },        // 380-419, expect partial trim (tagline kept)
    { w: 420, h: 900, name: "wide-420" },             // = breakpoint edge, full chrome
    { w: 480, h: 900, name: "small-tablet-480" },     // > 419, full chrome
];

const browser = await chromium.launch({ headless: true });
const out = [];
for (const v of WIDTHS) {
    const ctx = await browser.newContext({ viewport: { width: v.w, height: v.h }, locale: "uk-UA" });
    const page = await ctx.newPage();
    await page.goto(URL_BASE + "/", { waitUntil: "networkidle" });
    const m = await page.evaluate(() => {
        const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
        const mast = document.querySelector(".masthead");
        const brand = document.querySelector(".masthead__brand");
        const tagline = document.querySelector(".masthead__tagline");
        const issueLabel = document.querySelector(".masthead__meta span");
        const nav = Array.from(document.querySelectorAll(".masthead__meta button")).filter(visible).map(b => b.textContent?.trim());
        const styleOf = (el) => el ? { display: getComputedStyle(el).display, fontSize: getComputedStyle(el).fontSize } : null;
        return {
            mastheadH: mast ? Math.round(mast.getBoundingClientRect().height) : null,
            brand: { text: brand?.textContent?.trim(), ...styleOf(brand), visible: brand ? visible(brand) : false },
            tagline: { text: tagline?.textContent?.trim().slice(0, 40), ...styleOf(tagline), visible: tagline ? visible(tagline) : false },
            issueLabel: { text: issueLabel?.textContent?.trim(), ...styleOf(issueLabel), visible: issueLabel ? visible(issueLabel) : false },
            nav,
        };
    });
    await page.screenshot({ path: `${OUT}/${v.name}.png`, clip: { x: 0, y: 0, width: v.w, height: Math.min(v.h, 250) } });
    out.push({ viewport: v, ...m });
    await ctx.close();
}
await browser.close();
writeFileSync(`${OUT}/snapshot.json`, JSON.stringify(out, null, 2));
console.log(JSON.stringify(out.map(r => ({
    vp: `${r.viewport.w}×${r.viewport.h} (${r.viewport.name})`,
    mastheadH: r.mastheadH,
    brand_fs: r.brand?.fontSize,
    tagline_display: r.tagline?.display,
    tagline_visible: r.tagline?.visible,
    issueLabel_display: r.issueLabel?.display,
    issueLabel_visible: r.issueLabel?.visible,
    navN: r.nav?.length,
})), null, 2));
