// v3 operator-blind enrollment orchestration (EXPERIMENTAL / UNAUDITED).
//
// Runs entirely in the browser:
//   1. build a SYNTHETIC Diia-style P-256 cert + enroll_commit_v2 witness
//      (mirrors gen-enroll-commit-v2-witness.mjs);
//   2. prove enroll_commit_v2 (~118k gates) in a Web Worker -> public M;
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
    G,
    N,
    Point,
    SVDW_CONSTS,
    hashToField2,
    mapToCurveSvdW,
    scalarLimbs,
    nullifierCommitment,
    type Pt,
    type SvdWHints,
} from "./grumpkin.js";

export const OPRF_SERVICE_URL = "https://crisp-qes-oprf-grumpkin.fly.dev";
const BLIND_EVAL_PATH = "/v3/blind-eval";

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

// Build the synthetic cert + enroll_commit_v2 witness, mirroring
// gen-enroll-commit-v2-witness.mjs exactly.
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

    const { c1, c2, c3, c4 } = SVDW_CONSTS;
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
        c1: dec(c1),
        c2: dec(c2),
        c3: dec(c3),
        c4: dec(c4),
        h0: hintArr(m0.hints),
        h1: hintArr(m1.hints),
        r_lo: dec(lo),
        r_hi: dec(hi),
    };

    return { witness, r, M };
}

export interface BlindEvalResponse {
    Y: Pt;
    c: bigint;
    z: bigint;
    Kpub: Pt;
}

// POST the enroll proof + public M to the LIVE service. Proof-gating is
// enforced: the service bb.js-verifies enroll_commit_v2 and checks public M.
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
        Y: string;
        dleq: { c: string; z: string };
        Kpub: string;
    };
    return {
        Y: pointFromHex(json.Y),
        c: BigInt(json.dleq.c),
        z: BigInt(json.dleq.z),
        Kpub: pointFromHex(json.Kpub),
    };
}

// Build the oprf_nullifier witness from the service response (mirrors
// gen-nullifier-witness.mjs). Unblind N = rinv*Y; the circuit re-derives the
// DLEQ challenge and the commitment.
export function buildNullifierWitness(
    M: Pt,
    r: bigint,
    ev: BlindEvalResponse,
): InputMap {
    const Ga = G.toAffine();
    const Ka = ev.Kpub.toAffine();
    const Ma = M.toAffine();
    const Ya = ev.Y.toAffine();

    const cL = scalarLimbs(ev.c);
    const zL = scalarLimbs(ev.z);
    const rinv = Fn.inv(Fn.create(r));
    const riL = scalarLimbs(rinv);
    const rL = scalarLimbs(r);

    return {
        gx: dec(Ga.x),
        gy: dec(Ga.y),
        kpx: dec(Ka.x),
        kpy: dec(Ka.y),
        mx: dec(Ma.x),
        my: dec(Ma.y),
        yx: dec(Ya.x),
        yy: dec(Ya.y),
        c_lo: dec(cL.lo),
        c_hi: dec(cL.hi),
        z_lo: dec(zL.lo),
        z_hi: dec(zL.hi),
        rinv_lo: dec(riL.lo),
        rinv_hi: dec(riL.hi),
        r_lo: dec(rL.lo),
        r_hi: dec(rL.hi),
        c_expected: dec(ev.c),
    };
}

// Locally derive the unblinded OPRF output point N = rinv*Y and its pedersen
// commitment (same value the circuit returns as its public output).
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

// Full end-to-end run. Emits progress per stage with timings.
export async function runEnrollment(
    onStage: (stage: RunStage) => void,
): Promise<RunResult> {
    const t0 = performance.now();

    // 1. Build synthetic cert + enroll witness.
    let t = performance.now();
    onStage({ key: "enrollWitness", label: "Build synthetic cert + witness", status: "running" });
    const { witness: enrollWitness, r, M } = buildEnrollWitness();
    onStage({
        key: "enrollWitness",
        label: "Build synthetic cert + witness",
        status: "done",
        ms: performance.now() - t,
    });

    // 2. Prove enroll_commit_v2 (~118k gates).
    t = performance.now();
    onStage({ key: "enrollProve", label: "Prove enroll_commit_v2 (~118k gates)", status: "running" });
    let enroll: ProveResult;
    try {
        enroll = await runProof("enroll", enrollWitness, ENROLL_CIRCUIT_URL, () => {});
    } catch (err) {
        onStage({ key: "enrollProve", label: "Prove enroll_commit_v2 (~118k gates)", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "enrollProve",
        label: "Prove enroll_commit_v2 (~118k gates)",
        status: "done",
        ms: performance.now() - t,
    });

    // Sanity: public M is at publicInputs [12],[13] (after today[8], c1..c4).
    const Maff = M.toAffine();
    const pubMxRaw = enroll.publicInputs[12];
    const pubMyRaw = enroll.publicInputs[13];
    if (pubMxRaw === undefined || pubMyRaw === undefined) {
        throw new Error("enroll proof missing public M (publicInputs[12,13])");
    }
    const pubMx = BigInt(pubMxRaw);
    const pubMy = BigInt(pubMyRaw);
    if (pubMx !== Maff.x || pubMy !== Maff.y) {
        throw new Error("public M mismatch (proof publicInputs[12,13] != local M)");
    }

    // 3. Round-trip the LIVE service.
    t = performance.now();
    onStage({ key: "serviceEval", label: "Live OPRF blind-eval (Grumpkin)", status: "running" });
    let ev: BlindEvalResponse;
    try {
        ev = await blindEval(M, enroll.proofBytes, enroll.publicInputs);
    } catch (err) {
        onStage({ key: "serviceEval", label: "Live OPRF blind-eval (Grumpkin)", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "serviceEval",
        label: "Live OPRF blind-eval (Grumpkin)",
        status: "done",
        ms: performance.now() - t,
    });

    // 4. Prove oprf_nullifier.
    t = performance.now();
    onStage({ key: "nullifierProve", label: "Prove oprf_nullifier (DLEQ + unblind)", status: "running" });
    const nullifierWitness = buildNullifierWitness(M, r, ev);
    try {
        await runProof("nullifier", nullifierWitness, NULLIFIER_CIRCUIT_URL, () => {});
    } catch (err) {
        onStage({ key: "nullifierProve", label: "Prove oprf_nullifier (DLEQ + unblind)", status: "error", detail: String(err) });
        throw err;
    }
    onStage({
        key: "nullifierProve",
        label: "Prove oprf_nullifier (DLEQ + unblind)",
        status: "done",
        ms: performance.now() - t,
    });

    // 5. Derive commitment.
    t = performance.now();
    onStage({ key: "commitment", label: "Derive enrollment commitment", status: "running" });
    const { commitment } = await deriveCommitment(r, ev);
    onStage({
        key: "commitment",
        label: "Derive enrollment commitment",
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
