// Historical-root Merkle path test (ADR-0001 path C, option B).
//
// An FHE round pins a SNAPSHOT root. A voter enrolled before the snapshot must
// get a path that verifies against THAT root even after later enrollments grow
// the tree. This proves proofAtCount() / leafCountForRoot() do exactly that.
//
// Run from packages/oprf/v3-grumpkin:  node service/historical-path-test.mjs

import { MerkleIndex, rootFromPath, bigintToHex32 } from "./merkle.mjs";

let failures = 0;
const check = (name, cond, extra) => {
    if (!cond) failures++;
    console.log(`  [${cond ? "PASS" : "FAIL"}] ${name}${extra ? "  — " + extra : ""}`);
};

async function main() {
    console.log("historical-root Merkle path (option B)\n");

    const sA = 111n, sB = 222n, sC = 333n;

    // Tree with one leaf (sA) -> snapshot root R1 (the round pins this).
    const tree = await MerkleIndex.fromLeaves([sA]);
    const R1 = tree.root;
    check("snapshot leafCount for R1 == 1", tree.leafCountForRoot(bigintToHex32(R1)) === 1);

    // Tree grows: two more voters enroll AFTER the round opened.
    await tree.append(sB);
    const r3 = await tree.append(sC);
    const R3 = r3.newRoot;
    check("live tree grew (R3 != R1)", R3 !== R1, `${bigintToHex32(R3).slice(0, 12)} != ${bigintToHex32(R1).slice(0, 12)}`);

    // HISTORICAL path for sA against the snapshot (leafCount 1) — what the vote needs.
    const hist = await tree.proofAtCount(0, 1);
    const histRoot = await rootFromPath(sA, hist.path, hist.indices);
    check("historical path for sA re-roots to the SNAPSHOT root R1", histRoot === R1);
    check("historical proof.root == R1", hist.root === R1);

    // LIVE path for sA is against the grown tree (R3) — would FAIL the round's pinned R1.
    const live = await tree.proofAt(0);
    const liveRoot = await rootFromPath(sA, live.path, live.indices);
    check("live path for sA re-roots to R3 (NOT R1) — why the live path is wrong for the round", liveRoot === R3 && liveRoot !== R1);

    // root -> leafCount lookup.
    check("leafCountForRoot(R3) == 3", tree.leafCountForRoot(bigintToHex32(R3)) === 3);
    check("leafCountForRoot(unknown) == undefined", tree.leafCountForRoot(bigintToHex32(999999n)) === undefined);

    // A voter enrolled AFTER the snapshot (sC, idx 2) is not in the R1 snapshot.
    let threw = false;
    try { await tree.proofAtCount(2, 1); } catch { threw = true; }
    check("proofAtCount rejects a leaf enrolled after the snapshot", threw);

    console.log(`\n${failures === 0 ? "ALL PASS — historical-root paths verify against the pinned snapshot" : failures + " FAILURE(S)"}`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
