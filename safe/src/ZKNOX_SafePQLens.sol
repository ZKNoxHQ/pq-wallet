// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_SafePQLens.sol
// Description: stateless checker of the hybrid owner policies of a Safe 1.5.0 using ZKNOX_PQAccount7702
//              clones as post-quantum owners. Read by scripts and monitoring, and called as the last call of a
//              reconfiguration batch so that a wrong configuration reverts the whole Safe transaction.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISafeView} from "./interfaces/ISafeView.sol";
import {IZKNOX_PQAccount} from "./interfaces/IZKNOX_PQAccount.sol";

/// @title ZKNOX_SafePQLens
/// @notice Two policies, both "every valid signature set holds at least k ECDSA owners AND k post-quantum owners":
///
///         NESTED   root (T = 2) owned by exactly {S_ecdsa, S_pq}; S_ecdsa: EOAs, T >= k; S_pq: PQ clones, T >= k.
///         SINGLE   one Safe, nE EOAs + nP PQ clones, T >= nE + k and T >= nP + k.
///
///         Common conditions: Safe 1.5.0 singleton (L1 or L2) for every Safe involved (1.4.1 calls the legacy
///         `isValidSignature(bytes,bytes)` the PQ account does not implement), no module (a module executes
///         without signatures, and a module of a child can make it `approveHash` on the root), fallback
///         handler of every Safe equal to the trusted CompatibilityFallbackHandler (root and single: or unset),
///         since the handler answers ERC-1271 for the Safe. PQ owners must be initialized ERC-1167 clones of the
///         given implementation: an EOA delegated with EIP-7702 is refused, its ECDSA key alone passes the
///         `ecrecover` branch of `checkNSignatures`.
///
///         Point-in-time view: messages already approved in `signedMessages` and token allowances granted before
///         the reconfiguration are not visible here.
contract ZKNOX_SafePQLens {
    enum AccountKind {
        EOA,
        DELEGATED_7702,
        PQ_CLONE,
        PQ_CLONE_UNINITIALIZED,
        SAFE_150,
        SAFE_OTHER,
        CONTRACT
    }

    // ------------------------------------------------------------------ violation flags
    uint256 public constant ROOT_NOT_SAFE_150 = 1 << 0;
    uint256 public constant ROOT_OWNERS = 1 << 1;
    uint256 public constant ROOT_THRESHOLD = 1 << 2;
    uint256 public constant ROOT_MODULES = 1 << 3;
    uint256 public constant ROOT_HANDLER = 1 << 4;

    // child flags: CHILD_* << ECDSA_SHIFT for S_ecdsa, CHILD_* << PQ_SHIFT for S_pq
    uint256 public constant ECDSA_SHIFT = 8;
    uint256 public constant PQ_SHIFT = 16;
    uint256 public constant CHILD_NOT_SAFE_150 = 1 << 0;
    uint256 public constant CHILD_HANDLER = 1 << 1;
    uint256 public constant CHILD_THRESHOLD = 1 << 2;
    uint256 public constant CHILD_OWNERS = 1 << 3;
    uint256 public constant CHILD_MODULES = 1 << 4;

    uint256 public constant SINGLE_NOT_SAFE_150 = 1 << 24;
    uint256 public constant SINGLE_OWNERS = 1 << 25;
    uint256 public constant SINGLE_THRESHOLD = 1 << 26;
    uint256 public constant SINGLE_MODULES = 1 << 27;
    uint256 public constant SINGLE_HANDLER = 1 << 28;

    // ------------------------------------------------------------------ Safe constants
    /// keccak256("fallback_manager.handler.address")
    uint256 internal constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address internal constant SENTINEL = address(0x1);

    address public immutable SAFE_SINGLETON;
    address public immutable SAFE_SINGLETON_L2;
    address public immutable FALLBACK_HANDLER;

    error HybridPolicyViolation(uint256 violations);

    constructor(address safeSingleton, address safeSingletonL2, address fallbackHandler) {
        SAFE_SINGLETON = safeSingleton;
        SAFE_SINGLETON_L2 = safeSingletonL2;
        FALLBACK_HANDLER = fallbackHandler;
    }

    // ------------------------------------------------------------------ policies

    function nestedViolations(address root, address sEcdsa, address sPq, uint256 k, address pqImplementation)
        public
        view
        returns (uint256 v)
    {
        if (!isSafe150(root)) {
            v |= ROOT_NOT_SAFE_150;
        } else {
            address[] memory owners = ISafeView(root).getOwners();
            bool ownersOk = owners.length == 2 && sEcdsa != sPq
                && ((owners[0] == sEcdsa && owners[1] == sPq) || (owners[0] == sPq && owners[1] == sEcdsa));
            if (!ownersOk) v |= ROOT_OWNERS;
            if (ISafeView(root).getThreshold() != 2) v |= ROOT_THRESHOLD;
            if (hasModules(root)) v |= ROOT_MODULES;
            address h = fallbackHandlerOf(root);
            if (h != address(0) && h != FALLBACK_HANDLER) v |= ROOT_HANDLER;
        }
        v |= _childViolations(sEcdsa, k, AccountKind.EOA, pqImplementation) << ECDSA_SHIFT;
        v |= _childViolations(sPq, k, AccountKind.PQ_CLONE, pqImplementation) << PQ_SHIFT;
    }

    function singleViolations(address safe, uint256 k, address pqImplementation) public view returns (uint256 v) {
        if (!isSafe150(safe)) return SINGLE_NOT_SAFE_150;
        address[] memory owners = ISafeView(safe).getOwners();
        uint256 nE;
        uint256 nP;
        for (uint256 i = 0; i < owners.length; i++) {
            AccountKind kind = classify(owners[i], pqImplementation);
            if (kind == AccountKind.EOA) nE++;
            else if (kind == AccountKind.PQ_CLONE) nP++;
            else v |= SINGLE_OWNERS;
        }
        uint256 t = ISafeView(safe).getThreshold();
        if (k == 0 || t < nE + k || t < nP + k) v |= SINGLE_THRESHOLD;
        if (hasModules(safe)) v |= SINGLE_MODULES;
        address h = fallbackHandlerOf(safe);
        if (h != address(0) && h != FALLBACK_HANDLER) v |= SINGLE_HANDLER;
    }

    function requireNested(address root, address sEcdsa, address sPq, uint256 k, address pqImplementation)
        external
        view
    {
        uint256 v = nestedViolations(root, sEcdsa, sPq, k, pqImplementation);
        if (v != 0) revert HybridPolicyViolation(v);
    }

    function requireSingle(address safe, uint256 k, address pqImplementation) external view {
        uint256 v = singleViolations(safe, k, pqImplementation);
        if (v != 0) revert HybridPolicyViolation(v);
    }

    // ------------------------------------------------------------------ building blocks

    function classify(address account, address pqImplementation) public view returns (AccountKind) {
        bytes memory code = account.code;
        if (code.length == 0) return AccountKind.EOA;
        if (code.length == 23 && code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00) {
            return AccountKind.DELEGATED_7702;
        }
        if (pqImplementation != address(0) && keccak256(code) == keccak256(cloneCode(pqImplementation))) {
            (bool ok, bytes memory ret) =
                account.staticcall(abi.encodeWithSelector(IZKNOX_PQAccount.isInitialized.selector));
            if (ok && ret.length == 32 && abi.decode(ret, (bool))) return AccountKind.PQ_CLONE;
            return AccountKind.PQ_CLONE_UNINITIALIZED;
        }
        address singleton = singletonOf(account);
        if (singleton == address(0)) return AccountKind.CONTRACT;
        if (singleton == SAFE_SINGLETON || singleton == SAFE_SINGLETON_L2) return AccountKind.SAFE_150;
        return AccountKind.SAFE_OTHER;
    }

    function isSafe150(address safe) public view returns (bool) {
        if (safe.code.length == 0) return false;
        address singleton = singletonOf(safe);
        if (singleton == address(0)) return false;
        return singleton == SAFE_SINGLETON || singleton == SAFE_SINGLETON_L2;
    }

    /// @notice Slot 0 of a Safe proxy through `StorageAccessible.getStorageAt`, 0 if `safe` does not answer.
    function singletonOf(address safe) public view returns (address) {
        return address(uint160(uint256(_storageAt(safe, 0))));
    }

    function fallbackHandlerOf(address safe) public view returns (address) {
        return address(uint160(uint256(_storageAt(safe, FALLBACK_HANDLER_SLOT))));
    }

    function hasModules(address safe) public view returns (bool) {
        (address[] memory modules,) = ISafeView(safe).getModulesPaginated(SENTINEL, 1);
        return modules.length != 0;
    }

    /// @notice Runtime code of an OpenZeppelin `Clones` (ERC-1167) proxy to `implementation`.
    function cloneCode(address implementation) public pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ------------------------------------------------------------------ internals

    function _childViolations(address child, uint256 k, AccountKind ownerKind, address pqImplementation)
        internal
        view
        returns (uint256 v)
    {
        if (!isSafe150(child)) return CHILD_NOT_SAFE_150;
        if (fallbackHandlerOf(child) != FALLBACK_HANDLER) v |= CHILD_HANDLER;
        if (k == 0 || ISafeView(child).getThreshold() < k) v |= CHILD_THRESHOLD;
        address[] memory owners = ISafeView(child).getOwners();
        for (uint256 i = 0; i < owners.length; i++) {
            if (classify(owners[i], pqImplementation) != ownerKind) {
                v |= CHILD_OWNERS;
                break;
            }
        }
        if (hasModules(child)) v |= CHILD_MODULES;
    }

    function _storageAt(address safe, uint256 slot) internal view returns (bytes32 word) {
        (bool ok, bytes memory ret) =
            safe.staticcall(abi.encodeWithSelector(ISafeView.getStorageAt.selector, slot, uint256(1)));
        // abi.encode(bytes) of one word: offset (= 32) || length (= 32) || word; anything else is not a Safe
        if (!ok || ret.length != 96) return bytes32(0);
        uint256 offset;
        uint256 len;
        assembly {
            offset := mload(add(ret, 32))
            len := mload(add(ret, 64))
            word := mload(add(ret, 96))
        }
        if (offset != 32 || len != 32) return bytes32(0);
    }
}
