// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal surface for the Barretenberg-generated UltraVerifierV2.
///
/// Mirrors the MVP `IVerifier`. Kept as a distinct interface so the v2
/// contracts can be deployed alongside the MVP without typename collisions
/// in tooling, and so that a future v2.2 verifier swap (e.g. Poseidon2 +
/// shorter proof) can re-implement this interface unchanged.
interface IVerifierV2 {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        returns (bool);
}
