// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: CreatePqOwner.s.sol
// Description: one post-quantum owner, from the keys a device reported.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_PQFactory7702} from "pq-account/ZKNOX_PQFactory7702.sol";
import {ZKNOX_PQAccount7702} from "pq-account/ZKNOX_PQAccount7702.sol";

/// Creates the ERC-1167 clone that will be an owner of `S_pq`. It holds no key: it stores `keccak256` of
/// the secp256k1 address and `keccak256` of what the verifier's `setKey` returned — for ML-DSA-65 in the
/// calldata form, that is the 38,112-byte expanded key itself, which then travels in every signature.
///
/// The expanded key is read from a file rather than an environment variable: 38 kB of hex is past what a
/// shell comfortably carries, and a file is what the host-side signer naturally writes.
///
///   FACTORY=0x…                       from deployments/<chainId>-pq65.json
///   K1_ADDRESS=0x…                    the device's secp256k1 address, 20 bytes
///   KEY_FILE=keys/holder-1.hex        the expanded ML-DSA-65 key, 0x-prefixed, 38112 bytes
///   [SALT=0]
///   forge script script/CreatePqOwner.s.sol --rpc-url $RPC --ledger --sender $SENDER --broadcast
///
/// DRY_RUN=true stops before broadcasting and prints the address the clone would take.
contract CreatePqOwner is SafePQScriptBase {
    uint256 constant ML_DSA_65_KEY_BYTES = 38112;

    error BadKeyLength(uint256 got, uint256 expected);

    function run() external {
        ZKNOX_PQFactory7702 factory = ZKNOX_PQFactory7702(vm.envAddress("FACTORY"));
        address k1 = vm.envAddress("K1_ADDRESS");
        uint256 salt = vm.envOr("SALT", uint256(0));
        requireCode(address(factory), "factory");

        bytes memory key = vm.parseBytes(vm.trim(vm.readFile(vm.envString("KEY_FILE"))));
        if (key.length != ML_DSA_65_KEY_BYTES) revert BadKeyLength(key.length, ML_DSA_65_KEY_BYTES);
        bytes memory preQKey = abi.encodePacked(k1);

        console.log("factory        ", address(factory));
        console.log("k1 address     ", k1);
        console.log("expanded key   ", key.length, "bytes");
        console.log("keccak256(key) ", vm.toString(keccak256(key)));

        if (vm.envOr("DRY_RUN", false)) {
            console.log("DRY_RUN: nothing sent");
            return;
        }

        vm.startBroadcast();
        ZKNOX_PQAccount7702 account = factory.createAccount(preQKey, key, salt);
        vm.stopBroadcast();

        // What the clone stores is what will be checked on every signature: if these do not match, every
        // later verification reverts, and it is cheaper to find out now.
        (bytes32 preH, bytes32 postH) = account.keyHashes();
        require(preH == keccak256(preQKey), "preQ key hash mismatch");
        require(postH == keccak256(key), "postQ key hash mismatch");
        require(account.isInitialized(), "clone not initialized");

        console.log("clone          ", address(account));
        console.log("");
        console.log("Add this address to PQ_OWNERS for DeployNestedSafes.");
    }
}
