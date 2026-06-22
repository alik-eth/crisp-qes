// v3 operator-blind enrollment orchestration (EXPERIMENTAL / UNAUDITED).
//
// Runs entirely in the browser:
//   1. build a SYNTHETIC Diia-style P-256 cert + enroll_commit_v2 witness
//      (mirrors gen-enroll-commit-v2-witness.mjs);
//   2. prove enroll_commit_v2 (~457k gates) in a Web Worker -> public M;
//   3. POST { M, proof, publicInputs } to the LIVE Grumpkin OPRF service
//      -> { Y, dleq:{c,z}, Kpub };
//   4. build the oprf_nullifier witness (unblind + DLEQ) and prove it;
//   5. derive + return the enrollment/nullifier commitment.
//
// SYNTHETIC vs REAL: the cert, RNOKPP, DOB and ECDSA key are synthetic and
// generated in-browser. Real Diia .p7s parsing is a deliberate follow-up. The
// blinded element M, the live service round-trip, both UltraHonk proofs, the
// DLEQ verification, the unblind and the final commitment are all REAL.

import type { InputMap } from "@noir-lang/noir_js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import {
    Fn,
    N,
    Point,
    hashToField2,
    mapToCurveSvdW,
    scalarLimbs,
    nullifierCommitment,
    verifyPartialDleq,
    combineThreshold,
    type Pt,
    type SvdWHints,
} from "./grumpkin.js";
import { buildP7sEnrollWitness } from "./p7sWitness.js";

export const OPRF_SERVICE_URL = "https://crisp-qes-oprf-grumpkin.fly.dev";
const BLIND_EVAL_PATH = "/v3/blind-eval";
const REGISTER_PATH = "/v3/register";

const ENROLL_CIRCUIT_URL = "/v3/enroll_commit_v2.json";
const NULLIFIER_CIRCUIT_URL = "/v3/oprf_nullifier.json";

const CERT_LEN = 768;
const RNOKPP = "1234567890";
const DOB = "19900115"; // YYYYMMDD — synthetic, > 18 years old vs `today`.

// Field element (decimal) -> 0x-padded 32-byte hex (what the circuit InputMaps
// for Field accept: any 0x or decimal string; we use decimal strings, which
// Noir.execute parses fine).
const dec = (v: bigint): string => v.toString();

// point = 0x{x:32B BE}{y:32B BE}  (the service wire format from /healthz).
function pointToHex(p: Pt): string {
    const a = p.toAffine();
    const be32 = (v: bigint): string => v.toString(16).padStart(64, "0");
    return `0x${be32(a.x)}${be32(a.y)}`;
}
function pointFromHex(hex: string): Pt {
    const h = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (h.length !== 128) throw new Error(`bad point hex length ${h.length}`);
    const x = BigInt(`0x${h.slice(0, 64)}`);
    const y = BigInt(`0x${h.slice(64, 128)}`);
    return Point.fromAffine({ x, y });
}

// Today as YYYYMMDD ASCII bytes (public input to the age check).
function todayYYYYMMDD(): string {
    const d = new Date();
    const y = d.getUTCFullYear().toString().padStart(4, "0");
    const m = (d.getUTCMonth() + 1).toString().padStart(2, "0");
    const day = d.getUTCDate().toString().padStart(2, "0");
    return `${y}${m}${day}`;
}

// Deterministic-ish blinding scalar in [1, N). Random per run (fresh blinding).
function randomScalar(): bigint {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    return (v % (N - 1n)) + 1n;
}

const hintArr = (h: SvdWHints): string[] => [
    dec(h.inv_t),
    dec(h.e1),
    dec(h.w1),
    dec(h.e2),
    dec(h.w2),
    dec(h.sqrt_x),
];

export interface EnrollWitnessBundle {
    witness: InputMap; // for enroll_commit_v2
    r: bigint; // blinding scalar (needed later for unblind)
    M: Pt; // public blinded element = r * H2C(RNOKPP)
}

// STALE / DEAD CODE: emits the OLD `msghash` + free `cert[]` fields. The
// enroll_commit_v2 circuit now (a) hashes signedAttrs in-circuit and (b)
// verifies a Diia CA->leaf trust chain, so it requires signed_attrs/* PLUS
// leaf_tbs / ca_pubkey_{x,y} / leaf_cert_sig / leaf_spki_off (see
// buildP7sEnrollWitness). This synthetic builder is NOT wired to any route and
// will NOT prove against the shipped circuit; kept only for reference/timing.
// Use buildP7sEnrollWitness (real .p7s) for the live flow.
// Build the synthetic cert + enroll_commit_v2 witness.
export function buildEnrollWitness(): EnrollWitnessBundle {
    const cert = new Uint8Array(CERT_LEN);
    for (let i = 0; i < CERT_LEN; i++) cert[i] = (i * 31 + 7) & 0xff;

    const rnokppOff = 64;
    const oid = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0a];
    for (let i = 0; i < oid.length; i++) cert[rnokppOff + i] = oid[i]!;
    for (let i = 0; i < 10; i++)
        cert[rnokppOff + 7 + i] = RNOKPP.charCodeAt(i);

    const dobOff = 200;
    for (let i = 0; i < 8; i++) cert[dobOff + i] = DOB.charCodeAt(i);

    const msghash = sha256(cert);
    const sk = p256.utils.randomPrivateKey();
    const pubUncompressed = p256.getPublicKey(sk, false);
    const pubX = pubUncompressed.slice(1, 33);
    const pubY = pubUncompressed.slice(33, 65);
    const sigObj = p256.sign(msghash, sk, { prehash: false }).normalizeS();
    const sig = sigObj.toCompactRawBytes();
    if (!p256.verify(sig, msghash, pubUncompressed, { prehash: false })) {
        throw new Error("JS-side ECDSA verify failed");
    }

    // u0,u1 are derived in-circuit, but JS still needs them for SvdW hints.
    const rnokppBytes = new TextEncoder().encode(RNOKPP);
    const [u0, u1] = hashToField2(rnokppBytes);
    const m0 = mapToCurveSvdW(u0);
    const m1 = mapToCurveSvdW(u1);
    const Hpt = m0.point.add(m1.point);

    const r = randomScalar();
    const M = Hpt.multiply(r);

    const { lo, hi } = scalarLimbs(r);

    const u8arr = (u8: Uint8Array): string[] =>
        Array.from(u8).map((b) => b.toString());
    const today = todayYYYYMMDD();

    const witness: InputMap = {
        pubkey_x: u8arr(pubX),
        pubkey_y: u8arr(pubY),
        sig: u8arr(sig),
        msghash: u8arr(msghash),
        cert: u8arr(cert),
        rnokpp_oid_off: rnokppOff.toString(),
        dob_off: dobOff.toString(),
        today: Array.from(today).map((c) => c.charCodeAt(0).toString()),
        // SvdW suite constants c1..c4 are no longer circuit inputs (pinned inside
        // grumpkin_voprf, F3); only the per-map hints h0/h1 are witnessed.
        h0: hintArr(m0.hints),
        h1: hintArr(m1.hints),
        r_lo: dec(lo),
        r_hi: dec(hi),
    };

    return { witness, r, M };
}

// One responder's partial (parsed): B_i = k_i*M + its epoch-bound per-share DLEQ
// + its published Kpub_i. The threshold service returns t=2 of these (the
// responders, indices 1 and 2).
export interface ThresholdPartial {
    i: bigint;
    B_i: Pt;
    dleq: { c: bigint; z: bigint };
    Kpub_i: Pt;
}

// Parsed threshold /v3/blind-eval response. `Y` is the LOCAL Lagrange combine
// (for the commitment / UX); the PROOF carries the partials for in-circuit
// re-verification. `publishedKpubSet` is the canonical 3-node Kpub set (indices
// 1,2,3) the threshold nullifier witness pins.
export interface BlindEvalResponse {
    partials: ThresholdPartial[]; // the t=2 responders (indices 1,2)
    epoch: bigint; // threshold session tag (bound into each DLEQ)
    publishedKpubSet: Pt[]; // the 3 published Kpub, index order 1,2,3
    Y: Pt; // local Lagrange combine of the partials
}

// POST the enroll proof + public M to the LIVE service (request shape unchanged:
// the gate + challengeDigestOk still apply). The THRESHOLD service returns the
// t=2 responders' partials, the session epoch, and the published 3-Kpub set.
// We verify EACH partial's per-share DLEQ client-side (fail fast on a misbehaving
// node) and Lagrange-combine Y locally for the commitment.
export async function blindEval(
    M: Pt,
    proofBytes: Uint8Array,
    publicInputs: string[],
): Promise<BlindEvalResponse> {
    const body = {
        M: pointToHex(M),
        proof: Array.from(proofBytes),
        publicInputs,
    };
    const res = await fetch(`${OPRF_SERVICE_URL}${BLIND_EVAL_PATH}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`blind-eval HTTP ${res.status}: ${text.slice(0, 300)}`);
    }
    const json = (await res.json()) as {
        partials: Array<{ i: string; B_i: string; dleq: { c: string; z: string }; Kpub_i: string }>;
        epoch: string;
        publishedKpubSet: Array<{ i: string; Kpub_i: string }>;
    };
    if (!Array.isArray(json.partials) || json.partials.length < 2) {
        throw new Error(`blind-eval: expected >=2 threshold partials, got ${json.partials?.length}`);
    }
    const epoch = BigInt(json.epoch);
    const partials: ThresholdPartial[] = json.partials.map((p) => ({
        i: BigInt(p.i),
        B_i: pointFromHex(p.B_i),
        dleq: { c: BigInt(p.dleq.c), z: BigInt(p.dleq.z) },
        Kpub_i: pointFromHex(p.Kpub_i),
    }));

    // Verify each responder's per-share DLEQ (fail fast on a misbehaving node).
    for (const p of partials) {
        // eslint-disable-next-line no-await-in-loop
        const ok = await verifyPartialDleq(p.Kpub_i, M, p.B_i, epoch, p.dleq);
        if (!ok) {
            throw new Error(`blind-eval: node ${p.i} returned an invalid per-share DLEQ`);
        }
    }

    // Published 3-Kpub set in index order (sorted by i so [0]=node1 ... [2]=node3).
    const publishedKpubSet = [...json.publishedKpubSet]
        .sort((a, b) => Number(BigInt(a.i) - BigInt(b.i)))
        .map((p) => pointFromHex(p.Kpub_i));

    // Local Lagrange combine for the commitment / UX (the proof re-verifies it).
    const Y = combineThreshold(partials.map((p) => ({ i: p.i, B_i: p.B_i })));

    return { partials, epoch, publishedKpubSet, Y };
}

// Build the THRESHOLD oprf_nullifier witness (13-word ABI) from the blind-eval
// response. The circuit re-verifies the t=2 per-share DLEQs vs the pinned GEN,
// binds each idx->Kpub from the PUBLISHED set, Lagrange-combines Y in-circuit (no
// free Y), unblinds N = rinv*Y, and re-asserts commit_r(r) == c_r (F2). `cr` is
// the enroll proof's PROVEN C_r (publicInputs[10]). Responders are idx1=1, idx2=2
// (partials[0], partials[1]); the full published 3-Kpub set is passed in order.
export function buildThresholdNullifierWitness(
    M: Pt,
    r: bigint,
    ev: BlindEvalResponse,
    cr: bigint,
): InputMap {
    if (ev.partials.length < 2) {
        throw new Error("buildThresholdNullifierWitness: need 2 responder partials");
    }
    if (ev.publishedKpubSet.length !== 3) {
        throw new Error("buildThresholdNullifierWitness: need the full 3-Kpub published set");
    }
    const Ma = M.toAffine();
    const kp1 = ev.publishedKpubSet[0]!.toAffine();
    const kp2 = ev.publishedKpubSet[1]!.toAffine();
    const kp3 = ev.publishedKpubSet[2]!.toAffine();

    // Sort responders ASCENDING by index so idx1 < idx2 (canonical order). The
    // circuit's select_lagrange_2of3 requires the canonical pair; a non-ascending
    // service response would otherwise fail proving.
    const sorted = [...ev.partials].sort((a, b) => Number(BigInt(a.i) - BigInt(b.i)));
    const pa = sorted[0]!; // responder idx1 (lower index)
    const pb = sorted[1]!; // responder idx2 (higher index)
    const Ba = pa.B_i.toAffine();
    const Bb = pb.B_i.toAffine();
    const caL = scalarLimbs(pa.dleq.c);
    const zaL = scalarLimbs(pa.dleq.z);
    const cbL = scalarLimbs(pb.dleq.c);
    const zbL = scalarLimbs(pb.dleq.z);

    const rinv = Fn.inv(Fn.create(r));
    const riL = scalarLimbs(rinv);
    const rL = scalarLimbs(r);

    return {
        // public: M, the published 3-Kpub set, responder indices, epoch, c_r
        mx: dec(Ma.x),
        my: dec(Ma.y),
        kp1x: dec(kp1.x),
        kp1y: dec(kp1.y),
        kp2x: dec(kp2.x),
        kp2y: dec(kp2.y),
        kp3x: dec(kp3.x),
        kp3y: dec(kp3.y),
        idx1: dec(pa.i),
        idx2: dec(pb.i),
        epoch: dec(ev.epoch),
        c_r: dec(cr),
        // private: the two responders' partials + DLEQs, then r/rinv
        bax: dec(Ba.x),
        bay: dec(Ba.y),
        bbx: dec(Bb.x),
        bby: dec(Bb.y),
        ca_lo: dec(caL.lo),
        ca_hi: dec(caL.hi),
        za_lo: dec(zaL.lo),
        za_hi: dec(zaL.hi),
        cb_lo: dec(cbL.lo),
        cb_hi: dec(cbL.hi),
        zb_lo: dec(zbL.lo),
        zb_hi: dec(zbL.hi),
        r_lo: dec(rL.lo),
        r_hi: dec(rL.hi),
        rinv_lo: dec(riL.lo),
        rinv_hi: dec(riL.hi),
    };
}

// Locally derive the unblinded OPRF output point N = rinv*Y and its pedersen
// commitment (same value the threshold circuit returns as its public output).
// `ev.Y` is the local Lagrange combine of the t=2 responder partials (= k'*M),
// so N = rinv*Y = k'*H2C(id) -- the deterministic per-identity leaf.
export async function deriveCommitment(
    r: bigint,
    ev: BlindEvalResponse,
): Promise<{ N: Pt; commitment: bigint }> {
    const rinv = Fn.inv(Fn.create(r));
    const N_ = ev.Y.multiply(rinv);
    const commitment = await nullifierCommitment(N_);
    return { N: N_, commitment };
}

// ---- Worker driver ----

export type Stage = "loadingCircuit" | "buildWitness" | "proving" | "done";

interface ProveResult {
    proofBytes: Uint8Array;
    publicInputs: string[];
}

function runProof(
    label: "enroll" | "nullifier",
    witness: InputMap,
    circuitUrl: string,
    onStage: (stage: Stage) => void,
): Promise<ProveResult> {
    const worker = new Worker(
        new URL("../worker/v3prove.worker.ts", import.meta.url),
        { type: "module" },
    );
    return new Promise<ProveResult>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent) => {
            const m = ev.data as
                | { type: "stage"; stage: Stage }
                | { type: "done"; proofBytes: number[]; publicInputs: string[] }
                | { type: "error"; detail: string };
            if (m.type === "stage") {
                onStage(m.stage);
            } else if (m.type === "done") {
                resolve({
                    proofBytes: new Uint8Array(m.proofBytes),
                    publicInputs: m.publicInputs,
                });
                worker.terminate();
            } else {
                reject(new Error(m.detail));
                worker.terminate();
            }
        };
        worker.onerror = (e) => {
            reject(new Error(e.message));
            worker.terminate();
        };
        worker.postMessage({ type: "prove", label, witness, circuitUrl });
    });
}

export interface RunStage {
    key:
        | "enrollWitness"
        | "enrollProve"
        | "serviceEval"
        | "nullifierProve"
        | "commitment";
    label: string;
    status: "running" | "done" | "error";
    detail?: string;
    ms?: number;
}

export interface RunResult {
    commitment: string; // 0x-hex of the pedersen commitment
    M: string; // public blinded element (point hex)
    totalMs: number;
}

// Legacy SYNTHETIC demo run (no route wires this anymore — the primary flow
// is runRealEnrollment below). NOTE: buildEnrollWitness() still emits the old
// bare-`13 0A` RNOKPP synthetic encoding, which the current enroll_commit_v2
// circuit (updated to the real Diia `13 10 "TINUA-"` layout) NO LONGER accepts;
// this helper is kept only for reference/timing and will fail to prove against
// the shipped circuit JSON. Use runRealEnrollment for the real flow.
// Full end-to-end run. Emits progress per stage with timings.
export async function runEnrollment(
    onStage: (stage: RunStage) => void,
): Promise<RunResult> {
    const t0 = performance.now();

    // 1. Build synthetic cert + enroll witness.
    let t = performance.now();
    onStage({ key: "enrollWitness", label: "Reading your Diia signature", status: "running" });
    const { witness: enrollWitness, r, M } = buildEnrollWitness();
    onStage({
        key: "enrollWitness",
        label: "Reading your Diia signature",
        status: "done",
        ms: performance.now() - t,
    });

    // 2. Prove enroll_commit_v2 (~457k gates).
    t = performance.now();
    onStage({ key: "enrollProve", label: "Confirming you're a unique adult", status: "running" });
    let enroll: ProveResult;
    try {
        enroll = await runProof("enroll", enrollWitness, ENROLL_CIRCUIT_URL, () => {});
    } catch (err) {
        onStage({ key: "enrollProve", label: "Confirming you're a unique adult", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "enrollProve",
        label: "Confirming you're a unique adult",
        status: "done",
        ms: performance.now() - t,
    });

    // Sanity: public M is at publicInputs [8],[9] (after today[8]); C_r at [10].
    const Maff = M.toAffine();
    const pubMxRaw = enroll.publicInputs[8];
    const pubMyRaw = enroll.publicInputs[9];
    const pubCrRaw = enroll.publicInputs[10];
    if (pubMxRaw === undefined || pubMyRaw === undefined || pubCrRaw === undefined) {
        throw new Error("enroll proof missing public M/C_r (publicInputs[8,9,10])");
    }
    const pubMx = BigInt(pubMxRaw);
    const pubMy = BigInt(pubMyRaw);
    if (pubMx !== Maff.x || pubMy !== Maff.y) {
        throw new Error("public M mismatch (proof publicInputs[8,9] != local M)");
    }
    // C_r the enroll proof PROVED (commit_r(r)). Threading this exact value into
    // the nullifier witness guarantees the nullifier's c_r == what the service
    // cross-checks (extractCrFromEnroll). The nullifier circuit re-asserts
    // commit_r(r) == c_r, so it fails closed if r and enrollCr disagree.
    const enrollCr = BigInt(pubCrRaw);

    // 3. Round-trip the LIVE service.
    t = performance.now();
    onStage({ key: "serviceEval", label: "Checking your signature privately", status: "running" });
    let ev: BlindEvalResponse;
    try {
        ev = await blindEval(M, enroll.proofBytes, enroll.publicInputs);
    } catch (err) {
        onStage({ key: "serviceEval", label: "Checking your signature privately", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "serviceEval",
        label: "Checking your signature privately",
        status: "done",
        ms: performance.now() - t,
    });

    // 4. Prove oprf_nullifier.
    t = performance.now();
    onStage({ key: "nullifierProve", label: "Creating your anonymous voting key", status: "running" });
    const nullifierWitness = buildThresholdNullifierWitness(M, r, ev, enrollCr);
    try {
        await runProof("nullifier", nullifierWitness, NULLIFIER_CIRCUIT_URL, () => {});
    } catch (err) {
        onStage({ key: "nullifierProve", label: "Creating your anonymous voting key", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "nullifierProve",
        label: "Creating your anonymous voting key",
        status: "done",
        ms: performance.now() - t,
    });

    // 5. Derive commitment.
    t = performance.now();
    onStage({ key: "commitment", label: "Creating your anonymous voting key", status: "running" });
    const { commitment } = await deriveCommitment(r, ev);
    onStage({
        key: "commitment",
        label: "Creating your anonymous voting key",
        status: "done",
        ms: performance.now() - t,
    });

    const commitmentHex = `0x${commitment.toString(16).padStart(64, "0")}`;
    return {
        commitment: commitmentHex,
        M: pointToHex(M),
        totalMs: performance.now() - t0,
    };
}

// =====================================================================
// REAL .p7s OPERATOR-BLIND ENROLLMENT — the PRIMARY on-chain path.
// =====================================================================
//
// Same in-browser pipeline as runEnrollment(), but driven by a REAL Diia
// .p7s (witness from p7sWitness.buildP7sEnrollWitness) and carried all the
// way to chain + vault:
//
//   build witness (real .p7s) -> prove enroll_commit_v2 -> POST /v3/blind-eval
//   -> prove oprf_nullifier -> POST /v3/register (BOTH proofs) -> take
//   {newRoot,newCommitments,attesterSig} -> POST relayer /v2/enroll (on-chain)
//   -> return the vault material the caller persists via encryptedStore.
//
// The commitment we register == pedersen([N.x, N.y]) (grumpkin.nullifierCommitment),
// which the service stores as the Merkle leaf. We persist that same value as
// enrollment_secret `s`. The v2 sign circuit (packages/circuit/src/main.nr)
// treats the leaf as `s` DIRECTLY (formula pin (a)) and derives the nullifier
// as pedersen([s, petition_id, DOMAIN_PETITION_V2]) — so storing s == leaf ==
// commitment makes the EXISTING sign/revoke flow work unchanged.

// /v3/register response — shape per the live Grumpkin service.
export interface V3RegisterResponse {
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    oldRoot: `0x${string}`;
    newRoot: `0x${string}`;
    newCommitments: `0x${string}`[];
    attesterSig: `0x${string}`;
    attesterAddr: `0x${string}`;
}

// POST both proofs + the commitment to the live service's /v3/register. The
// service appends the leaf to the enrollment tree and pre-signs the on-chain
// updateRoot batch.
export async function v3Register(args: {
    commitment: `0x${string}`;
    enrollProof: Uint8Array;
    enrollPublicInputs: string[];
    nullifierProof: Uint8Array;
    nullifierPublicInputs: string[];
}): Promise<V3RegisterResponse> {
    const body = {
        commitment: args.commitment,
        enrollProof: Array.from(args.enrollProof),
        enrollPublicInputs: args.enrollPublicInputs,
        nullifierProof: Array.from(args.nullifierProof),
        nullifierPublicInputs: args.nullifierPublicInputs,
    };
    const res = await fetch(`${OPRF_SERVICE_URL}${REGISTER_PATH}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        const err = new Error(
            `v3/register HTTP ${res.status}: ${text.slice(0, 300)}`,
        ) as Error & { status: number; bodyText: string };
        err.status = res.status;
        err.bodyText = text;
        throw err;
    }
    return (await res.json()) as V3RegisterResponse;
}

export interface V3RecoverResponse {
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    root: `0x${string}`;
}

// Thrown when the OPRF service has no leaf for this commitment (HTTP 404
// `NotEnrolled`). This is NOT a transient failure: it means the local vault's
// commitment isn't on the *current* enrollment registry — typically a stale
// vault left behind after a clean-slate redeploy (the tree + OPRF key were
// reset, so the old commitment can never reappear). The caller should prompt a
// fresh re-enrollment rather than surface a raw error.
export class NotEnrolledError extends Error {
    readonly commitment: string;
    constructor(commitment: string) {
        super(`commitment ${commitment} is not enrolled on the current registry`);
        this.name = "NotEnrolledError";
        this.commitment = commitment;
    }
}

// GET the existing enrollment path for an ALREADY-enrolled commitment. Because
// the commitment = pedersen(OPRF(RNOKPP)) is deterministic per identity, a
// "subsequent enrollment" with the same Diia identity is a RECOVERY: there is
// no new leaf to append, so we just fetch the existing leaf + Merkle path and
// re-wrap the vault locally (e.g. on a new device). No on-chain change happens.
export async function v3RecoverPath(
    commitment: `0x${string}`,
): Promise<V3RecoverResponse> {
    const res = await fetch(
        `${OPRF_SERVICE_URL}/v3/enrollment/${commitment}/path`,
    );
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        // 404 NotEnrolled = orphaned vault (registry reset / wrong epoch).
        // Surface as a typed error so the sign flow can offer re-enrollment.
        if (res.status === 404 && text.includes("NotEnrolled")) {
            throw new NotEnrolledError(commitment);
        }
        throw new Error(
            `v3 recover-path HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
    }
    return (await res.json()) as V3RecoverResponse;
}

export interface RealRunStage {
    key:
        | "parseWitness"
        | "enrollProve"
        | "serviceEval"
        | "nullifierProve"
        | "register"
        | "chain";
    label: string;
    status: "running" | "done" | "error";
    detail?: string;
    ms?: number;
}

// Everything the caller needs to (a) write the vault exactly like the v2
// Verify flow and (b) flip the account to `verified`.
export interface RealEnrollResult {
    /** s = pedersen([N.x,N.y]) — enrollment_secret AND on-chain Merkle leaf. */
    commitment: `0x${string}`;
    /** Unblinded grumpkin OPRF point N, 64-byte (x||y BE) hex — informational. */
    oprfOutputN: `0x${string}`;
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    /** On-chain enrollment tx (relayer-submitted updateRoot); null on recovery. */
    txHash: `0x${string}` | null;
    /** True when this re-enrolled/recovered an existing leaf (no new on-chain tx). */
    recovered: boolean;
    totalMs: number;
}

// Relayer submit signature, injected by the page (reuses lib/relayer.ts
// submitEnrollment unchanged) so this module stays free of config/relayer
// coupling and unit-testable.
export type SubmitEnrollmentFn = (args: {
    newRoot: `0x${string}`;
    newCommitments: `0x${string}`[];
    signature: `0x${string}`;
}) => Promise<
    | { ok: true; txHash: `0x${string}` }
    | { ok: false; code?: string; detail?: string }
>;

// 64-byte (x||y, each 32B BE) hex of a grumpkin point — informational N store.
function pointToOutputHex(p: Pt): `0x${string}` {
    return pointToHex(p) as `0x${string}`;
}

// Full REAL-cert end-to-end run. The caller supplies the .p7s bytes, the
// citizen's DOB (YYYYMMDD — same source the v2 age check uses, see report),
// and the relayer submit fn. Emits progress per stage.
export async function runRealEnrollment(
    p7sBytes: Uint8Array,
    dobDigits: string,
    submitEnrollment: SubmitEnrollmentFn,
    onStage: (stage: RealRunStage) => void,
    opts: { r?: bigint } = {},
): Promise<RealEnrollResult> {
    const t0 = performance.now();
    const stage = (
        key: RealRunStage["key"],
        label: string,
        status: RealRunStage["status"],
        extra?: Partial<RealRunStage>,
    ) => onStage({ key, label, status, ...extra });

    // 1. Parse the .p7s and build the enroll_commit_v2 witness.
    let t = performance.now();
    stage("parseWitness", "Reading your Diia signature", "running");
    let bundle: ReturnType<typeof buildP7sEnrollWitness>;
    try {
        bundle = buildP7sEnrollWitness(p7sBytes, dobDigits, { r: opts.r });
    } catch (err) {
        stage("parseWitness", "Reading your Diia signature", "error", {
            detail: String(err),
        });
        throw err;
    }
    const { witness: enrollWitness, r, M } = bundle;
    stage("parseWitness", "Reading your Diia signature", "done", {
        ms: performance.now() - t,
    });

    // 2. Prove enroll_commit_v2 (~457k gates).
    t = performance.now();
    stage("enrollProve", "Confirming you're a unique adult", "running");
    let enroll: ProveResult;
    try {
        enroll = await runProof("enroll", enrollWitness, ENROLL_CIRCUIT_URL, () => {});
    } catch (err) {
        stage("enrollProve", "Confirming you're a unique adult", "error", {
            detail: String(err),
        });
        throw err;
    }
    stage("enrollProve", "Confirming you're a unique adult", "done", {
        ms: performance.now() - t,
    });

    // Sanity: public M is at publicInputs [8],[9]; C_r at [10].
    const Maff = M.toAffine();
    const pubMx = enroll.publicInputs[8];
    const pubMy = enroll.publicInputs[9];
    const pubCr = enroll.publicInputs[10];
    if (pubMx === undefined || pubMy === undefined || pubCr === undefined) {
        throw new Error("enroll proof missing public M/C_r (publicInputs[8,9,10])");
    }
    if (BigInt(pubMx) !== Maff.x || BigInt(pubMy) !== Maff.y) {
        throw new Error("public M mismatch (proof publicInputs[8,9] != local M)");
    }
    // C_r the enroll proof PROVED; thread it into the nullifier witness so the
    // nullifier's c_r equals what the service cross-checks (extractCrFromEnroll).
    const enrollCr = BigInt(pubCr);

    // 3. Round-trip the LIVE service (proof-gated).
    t = performance.now();
    stage("serviceEval", "Checking your signature privately", "running");
    let ev: BlindEvalResponse;
    try {
        ev = await blindEval(M, enroll.proofBytes, enroll.publicInputs);
    } catch (err) {
        stage("serviceEval", "Checking your signature privately", "error", {
            detail: String(err),
        });
        throw err;
    }
    stage("serviceEval", "Checking your signature privately", "done", {
        ms: performance.now() - t,
    });

    // 4. Prove oprf_nullifier (unblind + DLEQ).
    t = performance.now();
    stage("nullifierProve", "Creating your anonymous voting key", "running");
    const nullifierWitness = buildThresholdNullifierWitness(M, r, ev, enrollCr);
    let nullifier: ProveResult;
    try {
        nullifier = await runProof(
            "nullifier",
            nullifierWitness,
            NULLIFIER_CIRCUIT_URL,
            () => {},
        );
    } catch (err) {
        stage("nullifierProve", "Creating your anonymous voting key", "error", {
            detail: String(err),
        });
        throw err;
    }
    stage("nullifierProve", "Creating your anonymous voting key", "done", {
        ms: performance.now() - t,
    });

    // Derive the commitment s = pedersen([N.x, N.y]) locally; it must equal
    // the nullifier proof's public output (publicInputs[last]).
    const { N: Npt, commitment } = await deriveCommitment(r, ev);
    const commitmentHex = `0x${commitment.toString(16).padStart(64, "0")}` as `0x${string}`;
    const pubOut = nullifier.publicInputs[nullifier.publicInputs.length - 1];
    if (pubOut !== undefined && BigInt(pubOut) !== commitment) {
        throw new Error(
            "nullifier proof commitment != locally derived commitment",
        );
    }

    // 5. POST /v3/register (BOTH proofs). If this identity is ALREADY enrolled
    //    (deterministic commitment per RNOKPP), treat it as RECOVERY: fetch the
    //    existing leaf + path instead of erroring, and skip the on-chain submit.
    t = performance.now();
    stage("register", "Recording your registration", "running");
    let reg: V3RegisterResponse | null = null;
    let recovery: V3RecoverResponse | null = null;
    try {
        reg = await v3Register({
            commitment: commitmentHex,
            enrollProof: enroll.proofBytes,
            enrollPublicInputs: enroll.publicInputs,
            nullifierProof: nullifier.proofBytes,
            nullifierPublicInputs: nullifier.publicInputs,
        });
    } catch (err) {
        const e = err as Error & { status?: number; bodyText?: string };
        if (e.status === 409 && (e.bodyText ?? "").includes("AlreadyEnrolled")) {
            recovery = await v3RecoverPath(commitmentHex);
        } else {
            stage("register", "Recording your registration", "error", {
                detail: String(err),
            });
            throw err;
        }
    }
    stage(
        "register",
        recovery ? "Restoring your existing registration" : "Recording your registration",
        "done",
        { ms: performance.now() - t },
    );

    // 6. Land it on-chain via the relayer — only for a FRESH enrollment. A
    //    recovery's leaf is already on-chain, so there is no new updateRoot.
    let txHash: `0x${string}` | null = null;
    if (reg) {
        t = performance.now();
        stage("chain", "Saving it to the public registry", "running");
        const tx = await submitEnrollment({
            newRoot: reg.newRoot,
            newCommitments: reg.newCommitments,
            signature: reg.attesterSig,
        });
        if (!tx.ok) {
            stage("chain", "Saving it to the public registry", "error", {
                detail: tx.detail ?? tx.code ?? "chain submit failed",
            });
            throw new Error(tx.detail ?? tx.code ?? "chain submit failed");
        }
        txHash = tx.txHash;
        stage("chain", "Saving it to the public registry", "done", {
            ms: performance.now() - t,
        });
    } else {
        stage("chain", "Already saved (recovery)", "done", { ms: 0 });
    }

    const path = reg ?? recovery!;
    return {
        commitment: commitmentHex,
        oprfOutputN: pointToOutputHex(Npt),
        leafIndex: path.leafIndex,
        merklePath: path.merklePath,
        merklePathIndices: path.merklePathIndices,
        txHash,
        recovered: reg === null,
        totalMs: performance.now() - t0,
    };
}
