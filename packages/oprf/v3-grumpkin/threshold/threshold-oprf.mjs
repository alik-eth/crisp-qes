// CRISP-QES v3 — THRESHOLD OPRF over Grumpkin (prototype, build / unaudited).
//
// Validates the no-single-keyholder design (CRISP-QES v3 §2): the OPRF key k is
// never held by, or reconstructed at, any single party. Instead k is Shamir-shared
// across n nodes; any t of them can jointly evaluate the OPRF by each returning a
// partial B_i = k_i * M, and the client (or a combiner) recombines them via
// Lagrange-in-the-exponent to get Y = k * M — WITHOUT ever materialising k.
//
// This is the JS math prototype of what becomes a Rust MPC node (forked from PSE
// vOPRF-ID, github.com/privacy-ethereum/vOPRF-ID). PSE's nodes are secp256k1 +
// BabyJubjub; we target Grumpkin so the result is consistent with our Noir circuits.
// Hence we REUSE v3-grumpkin/lib.mjs (Point, G, N, Fn, hashToCurve, oprfEval) — the
// same curve, generator and scalar field the circuits assume.
//
// Map to a future Rust node (per node i):
//   - holds long-lived share k_i in Fn (the BN254 base field = Grumpkin scalar order)
//   - exposes partialEval(M) -> B_i = k_i * M   (single scalar-mult; constant work)
//   - publishes Kpub_i = k_i * G as its verifiable share public key (commitment)
//   - (production) attaches a DLEQ proof that log_G(Kpub_i) == log_M(B_i) so the
//     combiner can reject a malicious/faulty node — lib.mjs already has dleqProve
//     for the single-key case; the threshold version proves it per-share.
// Map to the combiner (client side):
//   - picks any t responders S, computes Lagrange coeffs lambda_i(0) mod N,
//     Y = sum_{i in S} lambda_i * B_i = (sum lambda_i k_i) * M = f(0)*M = k*M.

import { Point, G, N, Fn, oprfEval, dleqProveShare, verifyDleqShare } from "../lib.mjs";
import { sha256 } from "@noble/hashes/sha2";

// ----------------------------------------------------------------------------
// Field helpers over the SCALAR field N (= BN254 base field). All polynomial
// arithmetic, Lagrange interpolation and share values live in Fn — points live
// on the Grumpkin curve and are only ever scaled by elements of Fn.
// ----------------------------------------------------------------------------

// Uniform-ish random scalar in [1, N). For a prototype; a real node would use a
// CSPRNG with rejection sampling to remove the (negligible) modulo bias.
export function randScalar() {
    const bytes = new Uint8Array(48); // 384 bits >> 254, bias negligible
    globalThis.crypto.getRandomValues(bytes);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return Fn.create(v === 0n ? 1n : v);
}

// --- DETERMINISTIC seeded scalar source (restart-stable keygen) -------------
// A keygen seeded from a single secret `seed` produces the SAME shares (hence
// the same k' and the same published Kpub set) on every boot. This is what keeps
// the deterministic nullifier -- and therefore recovery + in-flight enrollments
// -- stable across service restarts. The seed is a SECRET (treated like a key):
// never logged, never committed. (A real independent-operator deployment would
// have each node hold its OWN share with no shared seed; the single-seed demo
// trades that for restart-stability -- see the makeNodes caveat.)
//
// kdfScalar(seedBytes, counter) = rejection-sampled scalar in [1, N) from
// sha256(seedBytes || "crisp-qes-v3-threshold-kdf" || counter_be4), advancing a
// sub-counter on the (vanishingly rare) >= N draw so the result is uniform in
// [1, N) with no modulo bias.
const KDF_DOMAIN = new TextEncoder().encode("crisp-qes-v3-threshold-kdf");
function seedToBytes(seed) {
    if (seed instanceof Uint8Array) return seed;
    if (typeof seed === "bigint") {
        const o = new Uint8Array(32);
        let v = seed;
        for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
        return o;
    }
    throw new Error("seed must be a bigint or Uint8Array");
}
function be4(n) {
    return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function concatBytes(...arrs) {
    let len = 0;
    for (const a of arrs) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
}
function kdfScalar(seedBytes, counter) {
    // Rejection-sample into [1, N): try sub-counters until the 256-bit draw < N.
    for (let sub = 0; sub < 256; sub++) {
        const digest = sha256(concatBytes(seedBytes, KDF_DOMAIN, be4(counter), be4(sub)));
        let v = 0n;
        for (const b of digest) v = (v << 8n) | BigInt(b);
        if (v < N && v !== 0n) return v; // uniform in [1, N), no modulo bias
    }
    throw new Error("kdfScalar: rejection sampling exhausted (unreachable)");
}

// A deterministic scalar source bound to a seed: returns a fresh KDF scalar on
// each call (advancing an internal counter), so callers that consume randomness
// in a fixed order get reproducible values for a fixed seed.
function seededRand(seed) {
    const seedBytes = seedToBytes(seed);
    let counter = 0;
    return () => kdfScalar(seedBytes, counter++);
}

// Evaluate polynomial (coeffs[0] + coeffs[1] x + ...) at x, all mod N.
function polyEval(coeffs, x) {
    let acc = 0n;
    for (let j = coeffs.length - 1; j >= 0; j--) {
        acc = Fn.add(Fn.mul(acc, x), coeffs[j]);
    }
    return acc;
}

// ----------------------------------------------------------------------------
// (1) Shamir secret sharing of k over Fn.
// Degree-(t-1) polynomial with f(0) = k; share i is (i, f(i)) for node index i>=1.
// Returns { shares: [{i, k_i}], coeffs }. NEVER reconstructs k from shares.
// ----------------------------------------------------------------------------
// `rand` is the randomness source for the (t-1) non-constant coeffs; defaults to
// the CSPRNG randScalar, but a seeded source (seededRand) makes the split
// deterministic for a fixed seed.
export function shamirSplit(k, n, t, rand = randScalar) {
    if (t < 1 || t > n) throw new Error(`bad params: need 1<=t<=n, got t=${t} n=${n}`);
    const coeffs = [Fn.create(k)];
    for (let j = 1; j < t; j++) coeffs.push(rand());
    const shares = [];
    for (let i = 1; i <= n; i++) {
        shares.push({ i: BigInt(i), k_i: polyEval(coeffs, BigInt(i)) });
    }
    return { shares, coeffs };
}

// ----------------------------------------------------------------------------
// DKG-style key generation (prototype variant).
// Each of the n nodes acts as a dealer: picks its own random secret s_j and
// Shamir-splits it. Node i's final share is the SUM of the i-th sub-shares from
// every dealer; the effective key k = sum_j s_j is never assembled anywhere.
// This models a real DKG's additive structure WITHOUT the verification/complaint
// rounds (Feldman/Pedersen commitments, broadcast channel) a production DKG needs.
// We still expose the implied k here ONLY so the test can compare against the
// single-key OPRF; a live DKG would never reveal it.
//
// SEEDED (restart-stable): pass `seed` (a bigint or Uint8Array SECRET) to derive
// ALL randomness deterministically via the KDF, so the SAME seed => the SAME
// shares => the SAME k' => the SAME published Kpub set on every boot. This keeps
// the deterministic nullifier (and recovery) stable across restarts. Without a
// seed the CSPRNG path is used (fine for tests that don't depend on stability).
// NEVER log the seed or any k_i.
// ----------------------------------------------------------------------------
export function dkgKeygen(n, t, seed) {
    const rand = seed === undefined ? randScalar : seededRand(seed);
    const finalShares = Array.from({ length: n }, (_, idx) => ({ i: BigInt(idx + 1), k_i: 0n }));
    let kImplied = 0n; // test-only; not known to any node in production
    for (let dealer = 0; dealer < n; dealer++) {
        const s_j = rand();
        kImplied = Fn.add(kImplied, s_j);
        const { shares } = shamirSplit(s_j, n, t, rand);
        for (let idx = 0; idx < n; idx++) {
            finalShares[idx].k_i = Fn.add(finalShares[idx].k_i, shares[idx].k_i);
        }
    }
    return { shares: finalShares, kImplied };
}

// ----------------------------------------------------------------------------
// (4) Per-share / group public keys.
//   Kpub_i = k_i * G  (each node publishes this; a verifiable commitment to its share)
//   Kpub   = k   * G  (group public key; equals the Lagrange combination of Kpub_i)
// ----------------------------------------------------------------------------
export function sharePublicKey(share) {
    return G.multiply(Fn.create(share.k_i));
}
export function groupPublicKey(k) {
    return G.multiply(Fn.create(k));
}

// ----------------------------------------------------------------------------
// (2) Per-node partial evaluation: B_i = k_i * M, WITH a per-share epoch-bound
// DLEQ (review #7: per-share verification). Returns { i, B_i, dleq, Kpub_i }:
//   B_i    = k_i * M (the partial)
//   Kpub_i = k_i * G (the node's published share public key)
//   dleq   = { c, z } proving log_G(Kpub_i) == log_M(B_i) for THIS epoch
// The combiner/service rejects a faulty/malicious node via verifyPartialDleq.
// ----------------------------------------------------------------------------
export async function partialEval(share, Mpoint, epoch) {
    const B_i = oprfEval(share.k_i, Mpoint);
    const Kpub_i = G.multiply(Fn.create(share.k_i));
    const dleq = await dleqProveShare(Kpub_i, share.k_i, Mpoint, B_i, epoch);
    return { i: BigInt(share.i), B_i, dleq, Kpub_i };
}

// Recompute-and-check a node's per-share DLEQ (client/service side; mirrors the
// circuit's verify_dleq_share). True iff the partial is a valid k_i-evaluation
// of M under this epoch. Use to fail-fast on a cheating/faulty node.
export async function verifyPartialDleq(Kpub_i, Mpoint, B_i, epoch, dleq) {
    return verifyDleqShare(Kpub_i, Mpoint, B_i, epoch, dleq);
}

// ----------------------------------------------------------------------------
// Lagrange coefficient lambda_i(0) for the index set S, evaluated at x=0, mod N:
//   lambda_i = prod_{j in S, j!=i} ( -j / (i - j) )   (mod N)
// These are the weights such that sum_{i in S} lambda_i * f(i) = f(0).
// ----------------------------------------------------------------------------
export function lagrangeCoeff(i, indices) {
    let num = 1n, den = 1n;
    for (const j of indices) {
        if (j === i) continue;
        num = Fn.mul(num, Fn.neg(j));      // (0 - j)
        den = Fn.mul(den, Fn.sub(i, j));   // (i - j)
    }
    return Fn.mul(num, Fn.inv(den));
}

// ----------------------------------------------------------------------------
// (3) Combine partials via Lagrange-in-the-exponent (needs >= t partials):
//   Y = sum_{i in S} lambda_i * B_i
//     = sum_{i in S} lambda_i * (k_i * M)
//     = ( sum_{i in S} lambda_i * f(i) ) * M
//     = f(0) * M = k * M.
// k is NEVER reconstructed: only the points B_i are scaled and summed.
// ----------------------------------------------------------------------------
export function combine(partials) {
    const indices = partials.map((p) => BigInt(p.i));
    // review #7: reject duplicate responder indices (combine() dedup). Lagrange
    // interpolation requires DISTINCT indices; a dup would mis-weight the sum.
    const seen = new Set();
    for (const i of indices) {
        const key = i.toString();
        if (seen.has(key)) throw new Error("duplicate responder index");
        seen.add(key);
    }
    let Y = null;
    for (const { i, B_i } of partials) {
        const lambda = lagrangeCoeff(BigInt(i), indices);
        const term = B_i.multiply(Fn.create(lambda));
        Y = Y === null ? term : Y.add(term);
    }
    return Y;
}

export { Point, G, N, Fn };
