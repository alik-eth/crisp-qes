// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "./IVerifier.sol";

// Placeholder until `nargo compile` + `bb write_solidity_verifier` produces the
// real verifier. Replace by running, from packages/circuit/:
//   nargo compile
//   bb write_vk -b target/crisp_qes_circuit.json -o target/vk
//   bb write_solidity_verifier -k target/vk -o ../contracts/src/UltraVerifier.sol
contract UltraVerifier is IVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        revert("UltraVerifier: stub - regenerate from circuit");
    }
}
