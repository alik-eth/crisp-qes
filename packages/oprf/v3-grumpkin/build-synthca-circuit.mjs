// TEST-ONLY build: a synthetic-CA-pinned copy of enroll_commit_v2.
//
// WHY: production enroll_commit_v2 main() hard-pins the REAL Diia QTSP CA keys
// (DIIA_PINNED_CA), so a proof built over a SYNTHETIC cert fails assert_ca_pinned
// and the /v3/blind-eval gate rejects it. The local full-stack E2E needs a cert
// it can fully control, so this script compiles a SEPARATE circuit whose pinned
// set contains the synthetic test CA (seed "crisp-qes-synthetic-test-ca-v1",
// the same CA gen-enroll-commit-v2-witness.mjs signs with).
//
// HARD SECURITY RULE: this synthetic CA is NEVER added to the committed
// production source. We copy the circuit into a separate, gitignored build dir
// (circuits/enroll_commit_v2_synthca/) and swap ONLY the DIIA_PINNED_CA global
// there. The production circuit + DIIA_PINNED_CA are left byte-for-byte intact.
//
// Output: circuits/enroll_commit_v2_synthca/target/enroll_commit_v2_synthca.json
// — used by BOTH the enrollment-phase prover and the OPRF gate (via the
// ENROLL_GATE_CIRCUIT env override) for local tests only.
//
// Usage: node build-synthca-circuit.mjs   (run from packages/oprf/v3-grumpkin)

import { execFileSync } from "node:child_process";
import { cpSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { p256 } from "./node_modules/@noble/curves/p256.js";
import { sha256 } from "./node_modules/@noble/hashes/sha2.js";

const ROOT = dirname(fileURLToPath(import.meta.url)); // packages/oprf/v3-grumpkin
const SRC_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const OUT_DIR = join(ROOT, "circuits", "enroll_commit_v2_synthca");
const PKG_NAME = "enroll_commit_v2_synthca";

// ── 1. derive the synthetic CA pubkey from the canonical seed ────────────────
// MUST match gen-enroll-commit-v2-witness.mjs (its caSeed) and the circuit's
// test_synth_ca() — all three derive from this one seed.
const caSeed = sha256(new TextEncoder().encode("crisp-qes-synthetic-test-ca-v1"));
const caSk = caSeed;
const caPub = p256.getPublicKey(caSk, false); // 0x04 || X[32] || Y[32]
const caX = Array.from(caPub.slice(1, 33));
const caY = Array.from(caPub.slice(33, 65));

// Self-check against the circuit's hard-coded test_synth_ca() so a noble/seed
// drift can never silently produce a circuit the witness can't satisfy.
const EXPECTED_CA_X = [
    241, 165, 35, 221, 3, 198, 49, 15, 232, 124, 198, 6, 75, 133, 189, 148, 83, 206, 186, 17,
    46, 126, 170, 183, 214, 92, 191, 164, 134, 135, 50, 251,
];
if (JSON.stringify(caX) !== JSON.stringify(EXPECTED_CA_X)) {
    throw new Error(
        "synthetic CA pubkey drifted from circuit test_synth_ca() — refusing to build.\n" +
            `  derived ca_x=${JSON.stringify(caX)}`,
    );
}

const noirBytes = (a) => `[${a.join(", ")}]`;

// ── 2. build the synth-pinned DIIA_PINNED_CA replacement block ───────────────
// Mirrors test_pinned_with_synth(): [(synth_ca), (dummy [1;32],[2;32])].
const synthGlobal = `global DIIA_PINNED_CA: [([u8; 32], [u8; 32]); 2] = [
    (
        // SYNTHETIC TEST CA x (seed "crisp-qes-synthetic-test-ca-v1") TEST-ONLY,
        // NEVER a production Diia key.
        ${noirBytes(caX)},
        // SYNTHETIC TEST CA y
        ${noirBytes(caY)},
    ),
    (
        // distinct dummy slot (never matches the synthetic CA)
        [1; 32],
        [2; 32],
    ),
];`;

// ── 3. copy the circuit into the gitignored build dir + swap the global ──────
if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });
mkdirSync(OUT_DIR, { recursive: true });
cpSync(join(SRC_DIR, "src"), join(OUT_DIR, "src"), { recursive: true });

// Nargo.toml: same relative deps (sibling dir => same depth), rename the package.
const nargo = readFileSync(join(SRC_DIR, "Nargo.toml"), "utf8").replace(
    /name\s*=\s*"enroll_commit_v2"/,
    `name = "${PKG_NAME}"`,
);
writeFileSync(join(OUT_DIR, "Nargo.toml"), nargo);

const mainPath = join(OUT_DIR, "src", "main.nr");
const main = readFileSync(mainPath, "utf8");
const swapped = main.replace(/global DIIA_PINNED_CA[\s\S]*?\n\];/, synthGlobal);
if (swapped === main) {
    throw new Error("DIIA_PINNED_CA global not found / not replaced — circuit shape changed?");
}
writeFileSync(mainPath, swapped);

// ── 4. compile with the pinned nargo (beta.19) ──────────────────────────────
console.log(`[synthca] compiling ${PKG_NAME} (nargo)…`);
execFileSync("nargo", ["compile"], { cwd: OUT_DIR, stdio: "inherit" });

const outJson = join(OUT_DIR, "target", `${PKG_NAME}.json`);
if (!existsSync(outJson)) throw new Error(`compile produced no ${outJson}`);
console.log(`[synthca] OK → ${outJson}`);
console.log(`[synthca] point the gate at it:  ENROLL_GATE_CIRCUIT=${outJson}`);
