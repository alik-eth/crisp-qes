// Worker realm for the dual-bb.js coexistence check. Loads the V3 (aliased)
// bb.js in its OWN module registry + globals (a node worker_thread realm ==
// a browser Web Worker realm), inits the WASM, and reports back. This is the
// realm the browser `vote.worker.ts` will use for v3 proving.
import { parentPort } from "node:worker_threads";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Barretenberg } from "@aztec/bb.js-v3";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "node_modules", "@aztec", "bb.js-v3", "package.json");

async function run() {
    const version = JSON.parse(readFileSync(PKG, "utf8")).version;
    const bb = await Barretenberg.new({ threads: 1 });
    // Touch the WASM so we know it actually instantiated in this realm.
    let info = null;
    try {
        info = await bb.getCircuitSizes?.(new Uint8Array([0]), false, false);
    } catch {
        info = "api-differs"; // v3/v4 API skew is fine — init is the signal.
    }
    await bb.destroy?.();
    parentPort.postMessage({ realm: "worker", lib: "@aztec/bb.js-v3", version, initialized: true, info: String(info).slice(0, 40) });
}

run().catch((e) => parentPort.postMessage({ realm: "worker", error: e?.message ?? String(e) }));
