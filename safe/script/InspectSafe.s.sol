// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: InspectSafe.s.sol
// Description: read-only report on a Safe: version, singleton flavour, owners by kind, threshold, modules, guard.
//   SAFE=0x... [PQ_IMPLEMENTATION=0x...] forge script script/InspectSafe.s.sol --rpc-url $RPC
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ZKNOX_SafeDeployments as D} from "../src/libraries/ZKNOX_SafeDeployments.sol";
import {ISafeView} from "../src/interfaces/ISafeView.sol";

contract InspectSafe is SafePQScriptBase {
    function run() external {
        address safe = vm.envAddress("SAFE");
        address impl = vm.envOr("PQ_IMPLEMENTATION", address(0));
        ZKNOX_SafePQLens lens = lensForReading();
        ISafeView s = ISafeView(safe);

        address singleton = lens.singletonOf(safe);
        string memory flavour = D.isKnownL2Singleton(singleton)
            ? "L2 (canonical)"
            : D.isKnownL1Singleton(singleton) ? "L1 (canonical)" : "not a canonical singleton";
        console.log("Safe            ", safe);
        console.log("version         ", s.VERSION());
        console.log("singleton       ", singleton, flavour);
        console.log("threshold       ", s.getThreshold());
        console.log("nonce           ", s.nonce());
        console.log("fallback handler", lens.fallbackHandlerOf(safe));
        console.log("guard           ", guardOf(safe));

        (address[] memory modules,) = s.getModulesPaginated(SENTINEL, 50);
        console.log("modules         ", modules.length);
        for (uint256 i = 0; i < modules.length; i++) {
            console.log("  module", modules[i]);
        }
        address[] memory owners = s.getOwners();
        console.log("owners          ", owners.length);
        for (uint256 i = 0; i < owners.length; i++) {
            console.log("  owner", owners[i], kindName(lens.classify(owners[i], impl)));
        }
    }
}
