// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DeployLens.s.sol
// Description: deploys ZKNOX_SafePQLens bound to the canonical Safe 1.5.0 singletons and fallback handler.
//   forge script script/DeployLens.s.sol --rpc-url $RPC --ledger --sender $DEPLOYER --broadcast
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";

contract DeployLens is SafePQScriptBase {
    function run() external returns (ZKNOX_SafePQLens lens) {
        requireCode(singleton150(), "Safe 1.5.0 singleton");
        requireCode(singletonL2150(), "SafeL2 1.5.0 singleton");
        requireCode(handler150(), "CompatibilityFallbackHandler 1.5.0");
        vm.startBroadcast();
        lens = new ZKNOX_SafePQLens(singleton150(), singletonL2150(), handler150());
        vm.stopBroadcast();
        console.log("ZKNOX_SafePQLens", address(lens));
    }
}
