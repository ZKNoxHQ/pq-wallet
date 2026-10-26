// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DeployNestedSafes.s.sol
// Description: creates S_ecdsa (EOAs, threshold K) and S_pq (ZKNOX_PQAccount7702 clones, threshold K) as
//              Safe 1.5.0 proxies with the 1.5.0 CompatibilityFallbackHandler. Owner kinds are checked first.
//   ECDSA_OWNERS=0xa,0xb,0xc PQ_OWNERS=0xd,0xe,0xf K=2 PQ_IMPLEMENTATION=0x... [SALT_NONCE=..] [L2=true] \
//   forge script script/DeployNestedSafes.s.sol --rpc-url $RPC --ledger --sender $DEPLOYER --broadcast
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ISafeProxyFactory, ISafeSetup, ISafeView} from "../src/interfaces/ISafeView.sol";

contract DeployNestedSafes is SafePQScriptBase {
    error WrongOwnerKind(address owner, string expected, string found);

    function run() external returns (address sEcdsa, address sPq) {
        address[] memory ecdsaOwners = vm.envAddress("ECDSA_OWNERS", ",");
        address[] memory pqOwners = vm.envAddress("PQ_OWNERS", ",");
        uint256 k = vm.envUint("K");
        address impl = vm.envAddress("PQ_IMPLEMENTATION");
        uint256 salt = vm.envOr("SALT_NONCE", block.timestamp);
        address singleton = vm.envOr("L2", false) ? singletonL2150() : singleton150();
        require(k > 0 && k <= ecdsaOwners.length && k <= pqOwners.length, "K out of range");
        requireCode(singleton, "Safe 1.5.0 singleton");
        requireCode(proxyFactory150(), "SafeProxyFactory 1.5.0");
        requireCode(handler150(), "CompatibilityFallbackHandler 1.5.0");

        ZKNOX_SafePQLens lens = lensForReading();
        _checkKinds(lens, ecdsaOwners, impl, ZKNOX_SafePQLens.AccountKind.EOA);
        _checkKinds(lens, pqOwners, impl, ZKNOX_SafePQLens.AccountKind.PQ_CLONE);

        vm.startBroadcast();
        sEcdsa = _create(singleton, ecdsaOwners, k, salt);
        sPq = _create(singleton, pqOwners, k, salt + 1);
        vm.stopBroadcast();

        require(versionIs(sEcdsa, "1.5.0") && versionIs(sPq, "1.5.0"), "created Safes are not 1.5.0");
        console.log("S_ecdsa", sEcdsa);
        console.log("S_pq   ", sPq);

        string memory o = "children";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeUint(o, "k", k);
        vm.serializeAddress(o, "pqImplementation", impl);
        vm.serializeAddress(o, "sEcdsa", sEcdsa);
        string memory json = vm.serializeAddress(o, "sPq", sPq);
        vm.writeJson(
            json, string.concat("plans/", vm.toString(block.chainid), "-children-", vm.toString(sEcdsa), ".json")
        );
    }

    function _checkKinds(
        ZKNOX_SafePQLens lens,
        address[] memory owners,
        address impl,
        ZKNOX_SafePQLens.AccountKind expected
    ) internal view {
        for (uint256 i = 0; i < owners.length; i++) {
            ZKNOX_SafePQLens.AccountKind found = lens.classify(owners[i], impl);
            if (found != expected) revert WrongOwnerKind(owners[i], kindName(expected), kindName(found));
        }
    }

    function _create(address singleton, address[] memory owners, uint256 k, uint256 salt) internal returns (address) {
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup, (owners, k, address(0), "", handler150(), address(0), 0, payable(address(0)))
        );
        return ISafeProxyFactory(proxyFactory150()).createProxyWithNonce(singleton, init, salt);
    }
}
