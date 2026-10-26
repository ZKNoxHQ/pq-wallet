// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: SafePQScriptBase.sol
// Description: shared environment handling of the safe-pq-signers scripts. Every Safe address defaults to the
//              canonical 1.5.0 deployment and can be overridden (local chains, tests).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ZKNOX_SafeDeployments as D} from "../src/libraries/ZKNOX_SafeDeployments.sol";
import {ISafeView} from "../src/interfaces/ISafeView.sol";

abstract contract SafePQScriptBase is Script {
    uint256 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    address internal constant SENTINEL = address(0x1);

    function singleton150() internal view returns (address) {
        return vm.envOr("SAFE_SINGLETON_150", D.SAFE_150);
    }

    function singletonL2150() internal view returns (address) {
        return vm.envOr("SAFE_SINGLETON_L2_150", D.SAFE_L2_150);
    }

    function handler150() internal view returns (address) {
        return vm.envOr("FALLBACK_HANDLER_150", D.COMPATIBILITY_FALLBACK_HANDLER_150);
    }

    function migration150() internal view returns (address) {
        return vm.envOr("SAFE_MIGRATION_150", D.SAFE_MIGRATION_150);
    }

    function multiSend150() internal view returns (address) {
        return vm.envOr("MULTI_SEND_CALL_ONLY_150", D.MULTI_SEND_CALL_ONLY_150);
    }

    function proxyFactory150() internal view returns (address) {
        return vm.envOr("SAFE_PROXY_FACTORY_150", D.PROXY_FACTORY_150);
    }

    function requireCode(address a, string memory what) internal view {
        require(a.code.length > 0, string.concat(what, " has no code on this chain: ", vm.toString(a)));
    }

    /// LENS from the environment if deployed, otherwise a lens created in the local simulation only.
    function lensForReading() internal returns (ZKNOX_SafePQLens) {
        address l = vm.envOr("LENS", address(0));
        if (l != address(0) && l.code.length > 0) return ZKNOX_SafePQLens(l);
        return new ZKNOX_SafePQLens(singleton150(), singletonL2150(), handler150());
    }

    function guardOf(address safe) internal view returns (address) {
        return address(uint160(uint256(bytes32(ISafeView(safe).getStorageAt(GUARD_SLOT, 1)))));
    }

    function kindName(ZKNOX_SafePQLens.AccountKind k) internal pure returns (string memory) {
        if (k == ZKNOX_SafePQLens.AccountKind.EOA) return "EOA";
        if (k == ZKNOX_SafePQLens.AccountKind.DELEGATED_7702) return "EOA delegated (EIP-7702)";
        if (k == ZKNOX_SafePQLens.AccountKind.PQ_CLONE) return "ZKNOX PQ account (clone)";
        if (k == ZKNOX_SafePQLens.AccountKind.PQ_CLONE_UNINITIALIZED) return "ZKNOX PQ account (NOT initialized)";
        if (k == ZKNOX_SafePQLens.AccountKind.SAFE_150) return "Safe 1.5.0";
        if (k == ZKNOX_SafePQLens.AccountKind.SAFE_OTHER) return "Safe (other version)";
        return "contract";
    }

    function versionIs(address safe, string memory v) internal view returns (bool) {
        return keccak256(bytes(ISafeView(safe).VERSION())) == keccak256(bytes(v));
    }
}
