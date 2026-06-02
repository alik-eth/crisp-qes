// grumpkin_voprf::params -- pinned curve/suite constants (ONE source of truth).
//
// These globals are copied VERBATIM from the F1/F3 security-fix commit (8da263b):
//   GEN_X/GEN_Y          from oprf_nullifier (F1: pinned DLEQ generator)
//   SVDW_C1..C4, SVDW_Z  from oprf_commitment (F3: pinned RFC-9380 SvdW suite)
//   ZETA, BCURVE         from oprf_commitment (curve params for SvdW)
//   DST                  from enroll_commit_v2 (RFC-9380 domain separation tag)
//
// Every consumer of this library inherits these pinned values with NO way to
// opt out: hash-to-curve cannot be redefined (F3) and the DLEQ base cannot be
// substituted (F1).

// Canonical Grumpkin generator (== Noir's embedded-curve generator, == lib.mjs
// GEN_X/GEN_Y and packages/web grumpkin.ts). The DLEQ base MUST be this point.
pub global GEN_X: Field = 1;
pub global GEN_Y: Field = 17631683881184975370165255887551781615748388533673675138860;

// Curve y^2 = x^3 + BCURVE over the Grumpkin base field; ZETA = least quadratic
// non-residue mod P (used by the SvdW square-selection gadget).
pub global ZETA: Field = 5;
pub global BCURVE: Field = -17;
pub global SVDW_Z: Field = 1;

// Canonical RFC-9380 SvdW suite constants for Grumpkin (== lib.mjs SVDW_CONSTS).
// A prover cannot supply different (c1..c4 + matching hints) to redefine
// hash-to-curve: these are globals, not inputs (F3).
pub global SVDW_C1: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495601;
pub global SVDW_C2: Field = 10944121435919637611123202872628637544274182200208017171849102093287904247808;
pub global SVDW_C3: Field = 17631683881184975371348829942606096167675058198229016842588;
pub global SVDW_C4: Field = 14592161914559516814830937163504850059032242933610689562465469457717205663766;

// DST = "CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_" (42 bytes). Copied verbatim
// from enroll_commit_v2. Hash-to-field (expand_message_xmd) stays app-side, but
// the DST is published here as the canonical separator for any consumer.
pub global DST_LEN: u32 = 42;
pub global DST: [u8; 42] = [
    67, 82, 73, 83, 80, 45, 81, 69, 83, 45, 86, 51, 45, 71, 114, 117, 109, 112, 107, 105, 110, 95,
    88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 86, 68, 87, 95, 82, 79, 95,
];
