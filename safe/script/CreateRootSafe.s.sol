// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: CreateRootSafe.s.sol
// Description: the 2-of-2 root whose two owners are the child Safes.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ISafeProxyFactory, ISafeSetup, ISafeView} from "../src/interfaces/ISafeView.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";

/// `DeployNestedSafes` makes the two children; this makes the Safe that owns them. It is deliberately a
/// script rather than a click in Safe{Wallet}: the lens requires **1.5.0** everywhere, and the version the
/// interface creates depends on what the chain's configuration recommends that day.
///
/// Once created, the root is an ordinary Safe — the indexer picks the proxy creation up and it opens in
/// Safe{Wallet} by address, which is the whole point of the approveHash design.
///
///   S_ECDSA=0x… S_PQ=0x… K=2 [PQ_IMPLEMENTATION=0x…] [LENS=0x…] [FUND=0]
///   forge script script/CreateRootSafe.s.sol --rpc-url $RPC --ledger --sender $SENDER --broadcast
///
/// With PQ_IMPLEMENTATION and LENS set, the NESTED policy is checked after creation and the script fails
/// rather than leaving an arrangement that does not hold.
contract CreateRootSafe is SafePQScriptBase {
    function run() external returns (address root) {
        address sEcdsa = vm.envAddress("S_ECDSA");
        address sPq = vm.envAddress("S_PQ");
        uint256 salt = vm.envOr("SALT_NONCE", block.timestamp);
        uint256 fund = vm.envOr("FUND", uint256(0));
        address singleton = vm.envOr("L2", false) ? singletonL2150() : singleton150();
        requireCode(singleton, "Safe 1.5.0 singleton");
        requireCode(proxyFactory150(), "SafeProxyFactory 1.5.0");
        requireCode(handler150(), "CompatibilityFallbackHandler 1.5.0");
        require(versionIs(sEcdsa, "1.5.0"), "S_ecdsa is not a Safe 1.5.0");
        require(versionIs(sPq, "1.5.0"), "S_pq is not a Safe 1.5.0");

        address[] memory owners = new address[](2);
        // Safe stores owners in a linked list and refuses duplicates; order here is irrelevant.
        owners[0] = sEcdsa;
        owners[1] = sPq;
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup, (owners, 2, address(0), "", handler150(), address(0), 0, payable(address(0)))
        );

        vm.startBroadcast();
        root = ISafeProxyFactory(proxyFactory150()).createProxyWithNonce(singleton, init, salt);
        if (fund > 0) {
            (bool ok,) = root.call{value: fund}("");
            require(ok, "funding the root failed");
        }
        vm.stopBroadcast();

        require(versionIs(root, "1.5.0"), "created root is not 1.5.0");
        require(ISafeView(root).getThreshold() == 2, "root threshold is not 2");

        console.log("root    ", root);
        console.log("S_ecdsa ", sEcdsa);
        console.log("S_pq    ", sPq);

        address impl = vm.envOr("PQ_IMPLEMENTATION", address(0));
        address lensAddr = vm.envOr("LENS", address(0));
        if (impl != address(0) && lensAddr != address(0)) {
            uint256 v = ZKNOX_SafePQLens(lensAddr).nestedViolations(root, sEcdsa, sPq, vm.envUint("K"), impl);
            console.log("nestedViolations", v);
            require(v == 0, "the arrangement does not satisfy NESTED");
            console.log("NESTED policy holds");
        } else {
            console.log("policy not checked: set PQ_IMPLEMENTATION and LENS");
        }

        string memory j = "root";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeAddress(j, "sEcdsa", sEcdsa);
        vm.serializeAddress(j, "sPq", sPq);
        string memory out = vm.serializeAddress(j, "root", root);
        vm.writeJson(out, string.concat("deployments/", vm.toString(block.chainid), "-root.json"));
    }
}
