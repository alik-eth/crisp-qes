// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title P256 — thin wrapper around the RIP-7212 P-256 verify precompile.
/// @notice The precompile lives at `0x0000...0100` on Base Sepolia and Base
///         mainnet. Its calling convention is:
///
///           input  (160 bytes) = msg_hash(32)
///                              || r(32) || s(32)
///                              || pubkey_x(32) || pubkey_y(32)
///           output  (32 bytes) = 0x...01 on valid, 0x...00 on invalid
///
///         The call is a `staticcall`. If the precompile is not deployed
///         (e.g. a stock local anvil), returndata is empty and we treat the
///         result as `false` — tests must opt in via `vm.etch` or
///         `vm.mockCall`.
library P256 {
    /// @dev RIP-7212 precompile address.
    address internal constant PRECOMPILE = address(0x100);

    /// @notice Verify a P-256 ECDSA signature via the RIP-7212 precompile.
    /// @param msgHash The 32-byte message digest (typically SHA-256 of signedAttrs).
    /// @param r       The signature's `r` scalar.
    /// @param s       The signature's `s` scalar.
    /// @param x       The signer public key's affine X coordinate.
    /// @param y       The signer public key's affine Y coordinate.
    /// @return ok     True iff the precompile returned the canonical
    ///                32-byte `0x...01`. Empty returndata → false.
    function verify(bytes32 msgHash, uint256 r, uint256 s, uint256 x, uint256 y)
        internal
        view
        returns (bool ok)
    {
        bytes memory input = abi.encodePacked(msgHash, r, s, x, y);
        (bool success, bytes memory output) = PRECOMPILE.staticcall(input);
        if (!success) return false;
        if (output.length != 32) return false;
        return abi.decode(output, (uint256)) == 1;
    }
}
