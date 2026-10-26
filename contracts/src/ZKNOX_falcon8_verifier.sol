// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon8_verifier.sol
// Description: ISigVerifier adapter over the eight-lane Falcon-512 NIST verifier
//              (ETHFALCON branch exp/pq-verifier-gas, ZKNOX_falcon8 / falcon_core8).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {SSTORE2} from "sstore2/SSTORE2.sol";
import {SALT_LEN} from "ETHFALCON/src/ZKNOX_common.sol";
import {falcon_S256} from "ETHFALCON/src/ZKNOX_falcon_utils.sol";
import {falcon_core8} from "ETHFALCON/src/ZKNOX_falcon_core8.sol";

/// @title ZKNOX_falcon8_verifier
/// @notice Falcon-512 (NIST, SHAKE-256 hash-to-point) behind the ISigVerifier interface used by the
///         ZKNOX post-quantum accounts. Same key and signature encodings as `ZKNOX_falcon`:
///         - key blob   : 32 words, 16 coefficients of 16 bits per word, the public key h in NTT domain
///                        (1024 bytes, stored once with SSTORE2 by `setKey`, referenced by its 20-byte pointer)
///         - signature  : salt (40 bytes) || s2 compact (32 words), 1064 bytes, canonical length enforced
/// @dev The Keccak-f[1600] helper is ETHFALCON's own (test/f1600_zknox.hex, resident-lane interface),
///      bound by code hash exactly as in `ZKNOX_falcon8`. It is a different contract from the Fireblocks
///      helper the ML-DSA verifier binds to: two helpers per chain.
/// @custom:experimental Not audited, do not use in production.
contract ZKNOX_falcon8_verifier is ISigVerifier {
    /// @notice keccak256 of the expected helper RUNTIME (ETHFALCON test/f1600_zknox.hex, 23,846 bytes)
    bytes32 internal constant F1600_CODEHASH = 0x661c9f13236c0174873874530946d802d0ac54373091f0bdea36ab2e3f409155;
    uint256 internal constant KEY_LEN = 32 * falcon_S256; // 1024
    uint256 internal constant SIG_LEN = SALT_LEN + 32 * falcon_S256; // 1064

    address public immutable f1600Helper;

    error BadHelper();

    constructor(address helper) {
        if (helper.codehash != F1600_CODEHASH) revert BadHelper();
        f1600Helper = helper;
    }

    /// @notice Stores a compact NTT-domain public key (1024 bytes) with SSTORE2.
    /// @return The 20-byte pointer, which is the `key` expected by `verify`.
    function setKey(bytes memory pubkey) external returns (bytes memory) {
        require(pubkey.length == KEY_LEN, "invalid pubkey length");
        return abi.encodePacked(SSTORE2.write(pubkey));
    }

    /// @inheritdoc ISigVerifier
    function verify(bytes calldata key, bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        // canonical encodings only: any other length would admit several encodings of the same signature
        if (key.length != 20 || signature.length != SIG_LEN) return 0xFFFFFFFF;
        if (f1600Helper.codehash != F1600_CODEHASH) revert BadHelper();

        address pointer;
        assembly {
            pointer := shr(96, calldataload(key.offset))
        }
        if (pointer.code.length != KEY_LEN + 1) return 0xFFFFFFFF; // SSTORE2 prefixes the blob with STOP

        // public key, read in place: the bytes blob is reinterpreted as uint256[32]
        bytes memory blob = SSTORE2.read(pointer);
        uint256[] memory ntth;
        assembly {
            mstore(blob, falcon_S256)
            ntth := blob
        }

        bytes memory salt = signature[0:SALT_LEN];
        uint256[] memory s2 = new uint256[](falcon_S256);
        assembly {
            calldatacopy(add(s2, 32), add(signature.offset, SALT_LEN), mul(32, falcon_S256))
        }

        if (falcon_core8(salt, abi.encodePacked(digest), f1600Helper, s2, ntth)) {
            return ISigVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }
}
