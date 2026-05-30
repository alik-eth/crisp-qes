// Phase-0 spike C: blinding-binding cost, the dominant risk (#1).
// The obligation (v3 spec 5.2) is to prove M = r * H2C(RNOKPP) in-circuit.
//
// ristretto255 (Curve25519) is NON-NATIVE to BN254 -> needs foreign-field
// EC arithmetic (no stdlib support), expected to dominate the circuit.
//
// This measures the SAME operation on Noir's NATIVE embedded curve
// (Grumpkin, a blackbox): one variable-base scalar mult. If this is cheap,
// it quantifies the recommended mitigation: co-design the OPRF over a
// SNARK-friendly curve instead of proving ristretto255 non-natively.

fn main(scalar_lo: Field, scalar_hi: Field, base_x: pub Field, base_y: pub Field) -> pub std::embedded_curve_ops::EmbeddedCurvePoint {
    let base = std::embedded_curve_ops::EmbeddedCurvePoint { x: base_x, y: base_y, is_infinite: false };
    let s = std::embedded_curve_ops::EmbeddedCurveScalar { lo: scalar_lo, hi: scalar_hi };
    // M = r * base  (variable-base scalar multiplication)
    std::embedded_curve_ops::multi_scalar_mul([base], [s])
}
