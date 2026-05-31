// CRISP-QES v3 Grumpkin VOPRF — conformance / regression vectors.
//
// FIRST-PASS conformance + self-audit. The Grumpkin ciphersuite is NON-STANDARD
// (no official RFC-9380 test vectors exist for it), so these are SELF-PINNED
// regression vectors generated from lib.mjs, NOT third-party conformance vectors.
// They lock the current behaviour so any future change to the H2C / OPRF / DLEQ
// path is caught. THIS IS NOT A SUBSTITUTE FOR AN EXTERNAL CRYPTOGRAPHIC AUDIT.
//
// Run from this directory:  node --test vectors.test.mjs
//
// What is asserted:
//   1. Grumpkin suite params (P, N, B=-17, cofactor 1, generator on-curve+order).
//   2. SvdW constants c1..c4 independently re-derived from Z=1 == lib's.
//   3. find_z_svdw conditions hold for Z=1.
//   4. hashToField2 == an independent RFC-9380 expand_message_xmd reimpl.
//   5. hashToCurve points: on-curve, deterministic, distinct, PINNED.
//   6. Full OPRF (input,r,k) -> output N: PINNED + N == k*H(m).
//   7. Chaum-Pedersen DLEQ: honest verifies; tampered Y rejects. PINNED (c,z).

import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import { bytesToNumberBE } from "@noble/curves/utils";
import {
    P, N, Fp, Fn, B, ZETA, SVDW_Z, G, Point, SVDW_CONSTS,
    g, isSq, hashToField2, hashToCurve, mapToCurveSvdW, oprfEval, dleqProve,
} from "./lib.mjs";

const enc = (s) => new TextEncoder().encode(s);
const hx = (v) => "0x" + v.toString(16);
const A = 0n;

// ---------------------------------------------------------------------------
// PINNED VECTORS (regenerate intentionally only when the suite is meant to
// change; a silent diff here is a regression).
// ---------------------------------------------------------------------------
const PIN = {
    params: {
        P: 21888242871839275222246405745257275088548364400416034343698204186575808495617n,
        N: 21888242871839275222246405745257275088696311157297823662689037894645226208583n,
        B: "0x" + Fp.create(-17n).toString(16),
        Gx: 1n,
        Gy: 17631683881184975370165255887551781615748388533673675138860n,
    },
    svdw: {
        c1: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff1",
        c2: "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000",
        c3: "0x2cf135e7506a45d66a7931f8d66dae274453478a4c627115c",
        c4: "0x2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000016",
    },
    h2c: [
        { input: "3334567890", u0: "0x13f1090196ad43af2ea0e223ed6fea698fff14fd1673c06b7ff252759034f7d2", u1: "0x23804a585686c105e937de8a6e4ace87f9c5bd16d96298ac29072430837a9b69", Hx: "0x304e21a2212d337dba5029a36540e036593d4e652db1b84d531cd77b6e7e404d", Hy: "0x2338b78b9d90a50b388766f03071e64ef3330be6cd32a810e8da7b56d2e0e38c" },
        { input: "0000000001", u0: "0x29e20f7678cb255f1c3cb94f37c7d6b06528aa9a0a7d746d5179730739edf3ca", u1: "0x124ee00fb3d1920b9613c446e69712bfaa0802e43c209b7a1b3b7fef4c00b0d2", Hx: "0x2df3ba87d0e7f9f4b2ad60ae5a5fbb71d4dcdd6e98659505fe1913297fcb40ed", Hy: "0x22846b43742c671969fd511fb2221351ea9a84ac91f5d6532f6a0d5bfb9df749" },
        { input: "9999999999", u0: "0x1ad97e5125595fbae12cd6ac1916b0edc699efd247f69711557a0f8ade1a02da", u1: "0x2223f590b6553a0443fd0900df3f97ebc6df0919e0a62cc875e745e82cb2f108", Hx: "0x204bc3bacfe0ad5d495a21d89e6a4d7120ca6549be55ba474720a3af4224638f", Hy: "0x2ef9816964103a23455574b61a31bf1e9cac0229b183c77febcf490ac4eb695b" },
    ],
    mapSingle: { x: "0x16cd381a0d4f66190326250ae5c8645b9aaa6eaeb5a89b14211c60e5e5b229ea", y: "0x28daf6c7865de13058382c27e02dfa42ca6c15438052e745da1218e94373d09c" },
    oprf: {
        r: 12345678901234567890n,
        k: 98765432109876543210n,
        t: 555555555555n,
        Nx: "0x2c42ed7fd9e06ce4159ec68ed1b9723b8e715063015bc2ac19be139f2b28148e",
        Ny: "0x2148ace918dfdf7dd0b5acef0c865076ae060efb4ab1a5b7451a79b3352a8c2b",
        c: "0x23b3748dad4f6a2d9dc8514bc54bc7a140faec2850c3f649ae0022739e50a9be",
        z: "0x196fb056f51b992244b0c4a4d60e6f0807f3a5590fecd815fa196d5914b60a74",
    },
};

// Independent RFC-9380 expand_message_xmd(SHA-256) reimplementation (strict).
const DST = enc("CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_");
const i2osp = (v, len) => { const o = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
function xmdRef(msg, lenInBytes) {
    const ell = Math.ceil(lenInBytes / 32);
    assert.ok(ell <= 255, "ell <= 255 (RFC-9380 bound)");
    const DSTp = concatBytes(DST, i2osp(BigInt(DST.length), 1)); // DST_prime
    const b0 = sha256(concatBytes(new Uint8Array(64) /*Z_pad=s_in_bytes*/, msg, i2osp(BigInt(lenInBytes), 2), i2osp(0n, 1), DSTp));
    const blocks = [sha256(concatBytes(b0, i2osp(1n, 1), DSTp))];
    for (let i = 2; i <= ell; i++) {
        const xored = b0.map((v, j) => v ^ blocks[i - 2][j]);
        blocks.push(sha256(concatBytes(xored, i2osp(BigInt(i), 1), DSTp)));
    }
    return concatBytes(...blocks).slice(0, lenInBytes);
}
function htf2Ref(msg) {
    const b = xmdRef(msg, 96); // L=48, count=2 -> 96 bytes
    return [Fp.create(bytesToNumberBE(b.slice(0, 48))), Fp.create(bytesToNumberBE(b.slice(48, 96)))];
}

const log = (...a) => console.log("    [VECTOR]", ...a);

// ---------------------------------------------------------------------------

test("1. Grumpkin suite parameters", () => {
    assert.equal(P, PIN.params.P, "base field P");
    assert.equal(N, PIN.params.N, "group order N");
    assert.equal(Fp.create(-17n), Fp.create(B), "b == -17");
    assert.equal(A, 0n, "a == 0");
    const Ga = G.toAffine();
    assert.equal(Ga.x, PIN.params.Gx, "Gx pinned");
    assert.equal(Ga.y, PIN.params.Gy, "Gy pinned");
    // generator on-curve: y^2 == x^3 + b
    assert.equal(Fp.mul(Ga.y, Ga.y), g(Ga.x), "generator on-curve");
    // cofactor 1, order N: (N-1)*G == -G  =>  N*G == O
    assert.ok(G.multiply(Fn.create(N - 1n)).equals(G.negate()), "order(G) == N (cofactor 1)");
    log("P  =", hx(P));
    log("N  =", hx(N));
    log("b  =", PIN.params.B, "(== -17 mod P)");
    log("G  = (", hx(Ga.x), ",", hx(Ga.y), ")  on-curve, order N, cofactor 1");
});

test("2. SvdW constants c1..c4 independently re-derived from Z=1", () => {
    const Z = SVDW_Z;
    assert.equal(Z, 1n, "SVDW_Z == 1");
    const inner = Fp.add(Fp.mul(3n, Fp.mul(Z, Z)), Fp.mul(4n, A)); // 3Z^2 + 4A
    const c1 = g(Z);
    const c2 = Fp.div(Fp.neg(Z), 2n);
    const c3 = Fp.sqrt(Fp.mul(Fp.neg(c1), inner));
    const c4 = Fp.div(Fp.mul(-4n, c1), inner);
    assert.equal(c1, SVDW_CONSTS.c1, "c1 == g(Z)");
    assert.equal(c2, SVDW_CONSTS.c2, "c2 == -Z/2");
    // c3 = sqrt(...): both roots are valid; pin |c3| via c3^2.
    assert.equal(Fp.mul(c3, c3), Fp.mul(SVDW_CONSTS.c3, SVDW_CONSTS.c3), "c3^2 matches");
    assert.ok(c3 === SVDW_CONSTS.c3 || c3 === Fp.neg(SVDW_CONSTS.c3), "c3 == ±lib.c3");
    assert.equal(c4, SVDW_CONSTS.c4, "c4 == -4*g(Z)/(3Z^2+4A)");
    // also pinned (catches any change to the chosen c3 root)
    assert.equal(hx(SVDW_CONSTS.c1), PIN.svdw.c1);
    assert.equal(hx(SVDW_CONSTS.c2), PIN.svdw.c2);
    assert.equal(hx(SVDW_CONSTS.c3), PIN.svdw.c3);
    assert.equal(hx(SVDW_CONSTS.c4), PIN.svdw.c4);
    log("c1 =", hx(SVDW_CONSTS.c1));
    log("c2 =", hx(SVDW_CONSTS.c2));
    log("c3 =", hx(SVDW_CONSTS.c3));
    log("c4 =", hx(SVDW_CONSTS.c4));
});

test("3. find_z_svdw conditions hold for Z=1", () => {
    const Z = SVDW_Z;
    const c1 = g(Z);
    const inner = Fp.add(Fp.mul(3n, Fp.mul(Z, Z)), Fp.mul(4n, A));
    // (1) g(Z) != 0
    assert.notEqual(c1, 0n, "g(Z) != 0");
    // (2) h(Z) = -(3Z^2+4A)/(4 g(Z)) is a nonzero square
    const hZ = Fp.div(Fp.neg(inner), Fp.mul(4n, c1));
    assert.notEqual(hZ, 0n, "h(Z) != 0");
    assert.ok(isSq(hZ), "h(Z) is a square");
    // (3) is_square(g(Z)) OR is_square(g(-Z/2))
    assert.ok(isSq(g(Z)) || isSq(g(Fp.div(Fp.neg(Z), 2n))), "g(Z) or g(-Z/2) is a square");
    log("g(Z) != 0:", c1 !== 0n, "| h(Z) nonzero square:", isSq(hZ), "| is_square(g(Z)):", isSq(g(Z)));
});

test("4. hashToField2 matches independent RFC-9380 expand_message_xmd", () => {
    for (const v of PIN.h2c) {
        const [u0, u1] = hashToField2(enc(v.input));
        const [r0, r1] = htf2Ref(enc(v.input));
        assert.equal(u0, r0, `u0 independent xmd (${v.input})`);
        assert.equal(u1, r1, `u1 independent xmd (${v.input})`);
        assert.equal(hx(u0), v.u0, `u0 pinned (${v.input})`);
        assert.equal(hx(u1), v.u1, `u1 pinned (${v.input})`);
    }
    log("hashToField2 == independent expand_message_xmd reimpl for all inputs");
});

test("5. hashToCurve: on-curve, deterministic, distinct, pinned", () => {
    const xs = new Set();
    for (const v of PIN.h2c) {
        const p1 = hashToCurve(enc(v.input)).toAffine();
        const p2 = hashToCurve(enc(v.input)).toAffine();
        assert.deepEqual(p1, p2, `deterministic (${v.input})`);
        assert.equal(Fp.mul(p1.y, p1.y), g(p1.x), `on-curve (${v.input})`);
        assert.equal(hx(p1.x), v.Hx, `Hx pinned (${v.input})`);
        assert.equal(hx(p1.y), v.Hy, `Hy pinned (${v.input})`);
        xs.add(p1.x.toString());
        log(`H2C(${v.input}) = (${hx(p1.x)}, ${hx(p1.y)})`);
    }
    assert.equal(xs.size, PIN.h2c.length, "distinct inputs -> distinct points");

    // map_to_curve single-point determinism + pin
    const [u0] = hashToField2(enc("3334567890"));
    const m = mapToCurveSvdW(u0).point.toAffine();
    assert.equal(Fp.mul(m.y, m.y), g(m.x), "map_to_curve output on-curve");
    assert.equal(hx(m.x), PIN.mapSingle.x, "mapToCurveSvdW x pinned");
    assert.equal(hx(m.y), PIN.mapSingle.y, "mapToCurveSvdW y pinned");
});

test("6 + 7. full OPRF output N and Chaum-Pedersen DLEQ (honest + tamper), pinned", async () => {
    const { r, k, t } = PIN.oprf;
    const Hm = hashToCurve(enc("3334567890"));
    const M = Hm.multiply(Fn.create(r));      // client blinds
    const Y = oprfEval(k, M);                  // node: Y = k*M
    const Kpub = G.multiply(Fn.create(k));     // node public key
    const Nout = Y.multiply(Fn.create(Fn.inv(Fn.create(r)))); // client unblinds N = rinv*Y

    // determinism / correctness: N == k*H(m)
    assert.ok(Nout.equals(Hm.multiply(Fn.create(k))), "N == k*H(m)");
    const Na = Nout.toAffine();
    assert.equal(hx(Na.x), PIN.oprf.Nx, "OPRF output Nx pinned");
    assert.equal(hx(Na.y), PIN.oprf.Ny, "OPRF output Ny pinned");

    // DLEQ proof (fixed nonce t -> deterministic c, z)
    const { c, z } = await dleqProve(k, Kpub, M, Y, t);
    assert.equal(hx(c), PIN.oprf.c, "DLEQ challenge c pinned");
    assert.equal(hx(z), PIN.oprf.z, "DLEQ response z pinned");

    // Honest verify: a1 = z*G - c*Kpub == t*G ; a2 = z*M - c*Y == t*M.
    const a1 = G.multiply(Fn.create(z)).add(Kpub.multiply(Fn.create(c)).negate());
    const a2 = M.multiply(Fn.create(z)).add(Y.multiply(Fn.create(c)).negate());
    assert.ok(a1.equals(G.multiply(Fn.create(t))), "DLEQ a1 == t*G");
    assert.ok(a2.equals(M.multiply(Fn.create(t))), "DLEQ a2 == t*M");

    // Tamper: a response Y' from a different key must break the M-leg.
    const Ybad = oprfEval(777n, M);
    const a2bad = M.multiply(Fn.create(z)).add(Ybad.multiply(Fn.create(c)).negate());
    assert.ok(!a2bad.equals(M.multiply(Fn.create(t))), "tampered Y -> DLEQ rejects");

    log("N      = (", hx(Na.x), ",", hx(Na.y), ")");
    log("DLEQ c =", hx(c));
    log("DLEQ z =", hx(z));
    log("honest DLEQ verifies; tampered Y rejected");
});
