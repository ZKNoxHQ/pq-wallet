// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_SafePQSignatures.sol
// Description: digests and signature packing for Safes whose owners are EOAs, ZKNOX_PQAccount7702 clones
//              (ERC-1271, hybrid ECDSA + ML-DSA/Falcon) and nested Safes.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISafeView} from "../interfaces/ISafeView.sol";
import {IZKNOX_PQAccount} from "../interfaces/IZKNOX_PQAccount.sol";

/// @notice Digest chain, from the transaction of the Safe that executes to the bytes an owner signs:
///
///         owner kind                         signs
///         EOA of Safe S                      h                                   (h = safeTxHash, or the hash S validates)
///         ZKNOX_PQAccount7702 clone P of S   P.hashWrapped(h)                    (k1 and ML-DSA-65, same digest)
///         nested Safe C of S                 C's owners sign safeMessageHash(C, h), recursively
///
///         For the NESTED policy the whole chain is `nestedOwnerDigest`: that one value is what a hardware
///         signer is handed.
///
///         Safe 1.5.0 `checkNSignatures` layout: 65 bytes per signature, sorted by owner address, followed by the
///         dynamic part of the contract signatures (`uint256 length || payload`, pointed to by `s`).
library ZKNOX_SafePQSignatures {
    /// keccak256("SafeMessage(bytes message)"), CompatibilityFallbackHandler
    bytes32 internal constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    enum Kind {
        ECDSA, // data = r || s || v (65 bytes), v in {27, 28} or {31, 32} for eth_sign
        CONTRACT, // data = ERC-1271 payload given to owner.isValidSignature(hash, data)
        APPROVED // data empty: owner called approveHash(hash) or is the executor
    }

    struct OwnerSig {
        address owner;
        Kind kind;
        bytes data;
    }

    error BadEcdsaLength(address owner);

    // ------------------------------------------------------------------ digests

    /// @notice Hash that the owners of `safe` sign so that `safe.isValidSignature(hash, sig)` holds, through
    ///         CompatibilityFallbackHandler (1.3.0+): EIP-712 SafeMessage(abi.encode(hash)) in `safe`'s domain.
    function safeMessageHash(address safe, bytes32 hash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(abi.encode(hash))));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), ISafeView(safe).domainSeparator(), structHash));
    }

    /// @notice Digest the pre-quantum and post-quantum keys of `pqAccount` sign for `hash`.
    function pqAccountDigest(address pqAccount, bytes32 hash) internal view returns (bytes32) {
        return IZKNOX_PQAccount(pqAccount).hashWrapped(hash);
    }

    /// @notice The 32 bytes a post-quantum owner signs, for a transaction of the NESTED root: the whole chain
    ///         in one call, root safeTxHash -> SafeMessage of the child -> EIP-712 wrap of the clone.
    /// @dev    This is what a hardware signer is handed. The ECML-Signer Ledger app signs an arbitrary 32-byte
    ///         digest (HYBRID_SIGN_HASH), so the device needs this value and nothing else; the k1 half of the
    ///         hybrid signature is made over the same digest.
    function nestedOwnerDigest(address sPq, address pqAccount, bytes32 safeTxHash) internal view returns (bytes32) {
        return pqAccountDigest(pqAccount, safeMessageHash(sPq, safeTxHash));
    }

    /// @notice ERC-1271 payload of ZKNOX_PQAccount7702: normalized keys (20-byte address / SSTORE2 pointer) and sigs.
    function hybridPayload(bytes memory preQKey, bytes memory preQSig, bytes memory postQKey, bytes memory postQSig)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(preQKey, preQSig, postQKey, postQSig);
    }

    // ------------------------------------------------------------------ packing

    function ecdsa(address owner, bytes memory rsv) internal pure returns (OwnerSig memory) {
        return OwnerSig(owner, Kind.ECDSA, rsv);
    }

    function contractSig(address owner, bytes memory payload) internal pure returns (OwnerSig memory) {
        return OwnerSig(owner, Kind.CONTRACT, payload);
    }

    function approved(address owner) internal pure returns (OwnerSig memory) {
        return OwnerSig(owner, Kind.APPROVED, "");
    }

    /// @notice Packs signatures in Safe order (ascending owner address). The input array is not modified.
    function pack(OwnerSig[] memory sigs) internal pure returns (bytes memory) {
        uint256 n = sigs.length;
        OwnerSig[] memory s = new OwnerSig[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = sigs[i];
        }
        for (uint256 i = 1; i < n; i++) {
            OwnerSig memory x = s[i];
            uint256 j = i;
            while (j > 0 && s[j - 1].owner > x.owner) {
                s[j] = s[j - 1];
                j--;
            }
            s[j] = x;
        }

        bytes memory head;
        bytes memory tail;
        uint256 staticLen = 65 * n;
        for (uint256 i = 0; i < n; i++) {
            OwnerSig memory x = s[i];
            bytes32 ownerWord = bytes32(uint256(uint160(x.owner)));
            if (x.kind == Kind.ECDSA) {
                if (x.data.length != 65) revert BadEcdsaLength(x.owner);
                head = bytes.concat(head, x.data);
            } else if (x.kind == Kind.APPROVED) {
                head = bytes.concat(head, ownerWord, bytes32(0), bytes1(0x01));
            } else {
                head = bytes.concat(head, ownerWord, bytes32(staticLen + tail.length), bytes1(0x00));
                tail = bytes.concat(tail, bytes32(x.data.length), x.data);
            }
        }
        return bytes.concat(head, tail);
    }
}
