// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal surface for the Barretenberg-generated UltraVerifier.
interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}
