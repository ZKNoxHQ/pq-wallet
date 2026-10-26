// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DeployPqStack65.s.sol
// Description: the ML-DSA-65 account stack on a chain that already has Safe 1.5.0 and an EntryPoint.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ECDSAk1Verifier} from "InterfaceVerifier/VerifierECDSAk1.sol";
import {ZKNOX_dilithium65} from "ETHDILITHIUM/src/ZKNOX_dilithium65.sol";
import {ZKNOX_PQFactory7702} from "pq-account/ZKNOX_PQFactory7702.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";

/// `../contracts/script/DeployPQAccount7702.s.sol` deploys the ML-DSA-**44** stack, which is what the
/// wallet demo uses. The Safe side runs on ML-DSA-**65** — that is the scheme `ZKNOX_dilithium65` verifies
/// and the one the ECML-Signer produces — so it needs a factory of its own, bound to that verifier.
///
/// Deploys: the Keccak-f1600 helper, the secp256k1 verifier, ZKNOX_dilithium65, a factory, and the policy
/// lens bound to the canonical Safe 1.5.0 singletons. Nothing Safe-related is deployed: on any chain where
/// the Safe singleton factory ran, those addresses already hold code, and the script checks it.
///
///   RPC=https://… SENDER=0x… forge script script/DeployPqStack65.s.sol \
///     --rpc-url $RPC --ledger --sender $SENDER --broadcast
///
/// ENTRY_POINT defaults to the canonical v0.8 address. The account never calls it in the Safe arrangement
/// (ERC-4337 is ruled out there, see the README), but the implementation takes one at construction.
contract DeployPqStack65 is SafePQScriptBase {
    address constant ENTRY_POINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    function run() external {
        IEntryPoint entryPoint = IEntryPoint(vm.envOr("ENTRY_POINT", ENTRY_POINT_V08));
        string memory version = vm.envOr("VERSION", string("0.1.0"));
        requireCode(address(entryPoint), "EntryPoint v0.8");
        requireCode(singleton150(), "Safe 1.5.0 singleton");
        requireCode(singletonL2150(), "SafeL2 1.5.0 singleton");
        requireCode(proxyFactory150(), "SafeProxyFactory 1.5.0");
        requireCode(handler150(), "CompatibilityFallbackHandler 1.5.0");

        vm.startBroadcast();
        address helper = vm.envOr("F1600_HELPER", address(0));
        if (helper == address(0)) helper = _deployHelper("../lib/ETHDILITHIUM/test/f1600_170.hex");
        ECDSAk1Verifier k1 = new ECDSAk1Verifier();
        ZKNOX_dilithium65 mldsa = new ZKNOX_dilithium65(helper);
        ZKNOX_PQFactory7702 factory = new ZKNOX_PQFactory7702(entryPoint, k1, mldsa, version);
        ZKNOX_SafePQLens lens = new ZKNOX_SafePQLens(singleton150(), singletonL2150(), handler150());
        vm.stopBroadcast();

        console.log("f1600 helper      ", helper);
        console.log("ECDSAk1Verifier   ", address(k1));
        console.log("ZKNOX_dilithium65 ", address(mldsa));
        console.log("factory           ", address(factory));
        console.log("implementation    ", address(factory.IMPLEMENTATION()));
        console.log("lens              ", address(lens));

        string memory j = "pq65";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeAddress(j, "entryPoint", address(entryPoint));
        vm.serializeAddress(j, "f1600Helper", helper);
        vm.serializeAddress(j, "k1Verifier", address(k1));
        vm.serializeAddress(j, "mldsa65Verifier", address(mldsa));
        vm.serializeAddress(j, "factory", address(factory));
        vm.serializeAddress(j, "pqImplementation", address(factory.IMPLEMENTATION()));
        string memory out = vm.serializeAddress(j, "lens", address(lens));
        vm.writeJson(out, string.concat("deployments/", vm.toString(block.chainid), "-pq65.json"));
        console.log("wrote deployments/%s-pq65.json", vm.toString(block.chainid));
    }

    /// The Keccak-f1600 kernel the verifier calls, deployed from its runtime bytecode. The verifier checks
    /// the codehash at construction, so a wrong helper fails here rather than at the first signature.
    function _deployHelper(string memory path) internal returns (address helper) {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = path;
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "helper: CREATE failed");
    }
}
