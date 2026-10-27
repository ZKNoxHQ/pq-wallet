// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: CreateArrangement.s.sol
// Description: the whole NESTED arrangement on a chain that already has Safe 1.5.0 and the ML-DSA-65 stack.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_PQFactory7702} from "pq-account/ZKNOX_PQFactory7702.sol";
import {ZKNOX_PQAccount7702} from "pq-account/ZKNOX_PQAccount7702.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ISafeProxyFactory, ISafeSetup, ISafeView} from "../src/interfaces/ISafeView.sol";

/// `CreatePqOwner` once per holder, then `DeployNestedSafes`, then `CreateRootSafe`: five invocations, five
/// sets of environment variables, and three addresses copied by hand from one run's output into the next.
/// Walked on Sepolia on 2026-10-27, it cost an hour and two arrangements half-built by a public RPC that
/// moved the nonce between two reads. This is the same work in one run.
///
/// It does not reduce the number of signatures — a device confirms every transaction, and there are still
/// one per post-quantum owner plus three — but nothing is retyped between them and a failed run is resumed
/// rather than restarted. The three other scripts stay: they are the ones to reach for when a single owner
/// has to be added to an arrangement that already exists.
///
///   KEY_FILES=keys/holder-1.hex,keys/holder-2.hex,keys/holder-3.hex \
///   K1_ADDRESSES=0x…,0x…,0x… \
///   ECDSA_OWNERS=0x…,0x…,0x… \
///   K=2 [FUND=0] [SALT_NONCE=0] [L2=false] [FACTORY=0x… LENS=0x… PQ_IMPLEMENTATION=0x…] \
///   forge script script/CreateArrangement.s.sol --rpc-url $RPC --ledger --sender $SENDER \
///     --broadcast --slow --gas-estimate-multiplier 800
///
/// The stack defaults to `deployments/<chainId>-pq65.json`, written by `DeployPqStack65`.
///
/// **Resumable.** Every creation is predicted before it is sent and skipped if the address already holds
/// code: the clones through the factory's own `getAddress`, the Safes through the CREATE2 formula of
/// `SafeProxyFactory.createProxyWithNonce`. The salt of each Safe is derived from its owner set and the
/// threshold rather than from a timestamp, so a second run lands on the same three addresses. Run it again
/// after a failure and it finishes what is missing.
contract CreateArrangement is SafePQScriptBase {
    uint256 constant ML_DSA_65_KEY_BYTES = 38112;

    error BadKeyLength(uint256 index, uint256 got, uint256 expected);
    error OwnerCountMismatch(uint256 keys, uint256 addresses);

    struct Stack {
        ZKNOX_PQFactory7702 factory;
        ZKNOX_SafePQLens lens;
        address implementation;
    }

    function run() external returns (address root, address sEcdsa, address sPq) {
        uint256 k = vm.envUint("K");
        uint256 saltNonce = vm.envOr("SALT_NONCE", uint256(0));
        address singleton = vm.envOr("L2", false) ? singletonL2150() : singleton150();
        ISafeProxyFactory proxies = ISafeProxyFactory(proxyFactory150());
        requireCode(singleton, "Safe 1.5.0 singleton");
        requireCode(address(proxies), "SafeProxyFactory 1.5.0");
        requireCode(handler150(), "CompatibilityFallbackHandler 1.5.0");

        Stack memory stack = _stack();
        address[] memory eoas = vm.envAddress("ECDSA_OWNERS", ",");
        string[] memory keyFiles = vm.envString("KEY_FILES", ",");
        address[] memory k1s = vm.envAddress("K1_ADDRESSES", ",");
        if (keyFiles.length != k1s.length) revert OwnerCountMismatch(keyFiles.length, k1s.length);
        require(k > 0 && k <= eoas.length && k <= keyFiles.length, "K out of range");

        console.log("factory        ", address(stack.factory));
        console.log("implementation ", stack.implementation);
        console.log("lens           ", address(stack.lens));
        console.log("");

        // ---- the post-quantum owners.
        //
        // The factory returns the existing clone instead of reverting when the predicted address already
        // holds code, so calling it twice is harmless — but it is not free: the 38 kB expanded key travels
        // in the calldata either way, and the EIP-7623 floor on that is some 1.2 M gas for a call that
        // does nothing. Measured on Sepolia on 2026-10-27, a resumed run spent 7.4 M re-sending three
        // clones that were already there. So the address is checked here and the transaction is not sent.
        address[] memory clones = new address[](keyFiles.length);
        bool[] memory missing = new bool[](keyFiles.length);
        bytes[] memory keys = new bytes[](keyFiles.length);
        uint256 toCreate;
        for (uint256 i = 0; i < keyFiles.length; i++) {
            keys[i] = vm.parseBytes(vm.trim(vm.readFile(keyFiles[i])));
            if (keys[i].length != ML_DSA_65_KEY_BYTES) {
                revert BadKeyLength(i, keys[i].length, ML_DSA_65_KEY_BYTES);
            }
            clones[i] = stack.factory.getAddress(abi.encodePacked(k1s[i]), keys[i], 0);
            missing[i] = clones[i].code.length == 0;
            if (missing[i]) toCreate++;
            console.log(missing[i] ? "clone (to create)" : "clone (reused)   ", clones[i]);
        }

        vm.startBroadcast();
        for (uint256 i = 0; i < keyFiles.length; i++) {
            if (!missing[i]) continue;
            address made = address(stack.factory.createAccount(abi.encodePacked(k1s[i]), keys[i], 0));
            require(made == clones[i], "clone address moved");
            // what the clone stores is checked on every later signature; a mismatch here costs a second,
            // the same mismatch on chain costs a 3.9 M gas revert
            (bytes32 preH, bytes32 postH) = ZKNOX_PQAccount7702(payable(made)).keyHashes();
            require(preH == keccak256(abi.encodePacked(k1s[i])), "preQ key hash mismatch");
            require(postH == keccak256(keys[i]), "postQ key hash mismatch");
        }

        // ---- the two children and the root
        bool madeA;
        bool madeB;
        bool madeRoot;
        (sEcdsa, madeA) = _safe(proxies, singleton, eoas, k, saltNonce, "S_ecdsa");
        (sPq, madeB) = _safe(proxies, singleton, clones, k, saltNonce, "S_pq");
        address[] memory children = new address[](2);
        children[0] = sEcdsa;
        children[1] = sPq;
        (root, madeRoot) = _safe(proxies, singleton, children, 2, saltNonce, "root");
        if (madeA) toCreate++;
        if (madeB) toCreate++;
        if (madeRoot) toCreate++;

        uint256 fund = vm.envOr("FUND", uint256(0));
        if (fund > 0 && root.balance < fund) {
            // not `transfer`: the 2300 gas stipend does not cover a Safe proxy's fallback
            (bool ok,) = root.call{value: fund - root.balance}("");
            require(ok, "funding the root failed");
            toCreate++;
        }
        vm.stopBroadcast();

        // ---- the arrangement is only worth anything if the policy holds, so it is checked, not assumed
        require(versionIs(root, "1.5.0") && versionIs(sEcdsa, "1.5.0") && versionIs(sPq, "1.5.0"), "not 1.5.0");
        require(ISafeView(root).getThreshold() == 2, "root threshold is not 2");
        uint256 v = stack.lens.nestedViolations(root, sEcdsa, sPq, k, stack.implementation);
        console.log("");
        console.log("transactions   ", toCreate);
        console.log("root           ", root);
        console.log("S_ecdsa        ", sEcdsa);
        console.log("S_pq           ", sPq);
        console.log("nestedViolations", v);
        require(v == 0, "the arrangement does not satisfy NESTED");
        console.log("NESTED policy holds");

        _write(root, sEcdsa, sPq, address(stack.lens), stack.implementation, k, clones);
    }

    // ------------------------------------------------------------------ helpers

    /// The stack from the environment, or from what `DeployPqStack65` wrote for this chain.
    function _stack() internal view returns (Stack memory s) {
        address factory = vm.envOr("FACTORY", address(0));
        address lens = vm.envOr("LENS", address(0));
        address impl = vm.envOr("PQ_IMPLEMENTATION", address(0));
        if (factory == address(0) || lens == address(0)) {
            string memory path = string.concat("deployments/", vm.toString(block.chainid), "-pq65.json");
            string memory json = vm.readFile(path);
            if (factory == address(0)) factory = vm.parseJsonAddress(json, ".factory");
            if (lens == address(0)) lens = vm.parseJsonAddress(json, ".lens");
            if (impl == address(0)) impl = vm.parseJsonAddress(json, ".pqImplementation");
        }
        requireCode(factory, "factory");
        requireCode(lens, "lens");
        s.factory = ZKNOX_PQFactory7702(factory);
        s.lens = ZKNOX_SafePQLens(lens);
        s.implementation = impl == address(0) ? address(s.factory.IMPLEMENTATION()) : impl;
        require(s.implementation == address(s.factory.IMPLEMENTATION()), "PQ_IMPLEMENTATION is not the factory's");
    }

    /// One Safe, created unless it is already there.
    ///
    /// The salt comes from the owner set and the threshold, never from `block.timestamp`: a run that dies
    /// between two transactions — which is what a public RPC with a stale nonce does — has to be resumable,
    /// and a timestamp salt would create a second arrangement beside the half-built one.
    function _safe(
        ISafeProxyFactory proxies,
        address singleton,
        address[] memory owners,
        uint256 threshold,
        uint256 saltNonce,
        string memory label
    ) internal returns (address safe, bool created) {
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup,
            (owners, threshold, address(0), "", handler150(), address(0), 0, payable(address(0)))
        );
        uint256 nonce = uint256(keccak256(abi.encode(owners, threshold, saltNonce, "zknox.nested")));
        safe = _predict(proxies, singleton, init, nonce);
        if (safe.code.length == 0) {
            address made = proxies.createProxyWithNonce(singleton, init, nonce);
            require(made == safe, "predicted proxy address is wrong");
            created = true;
        }
        console.log(string.concat(label, created ? " (created)" : " (reused)"), safe);
    }

    /// `SafeProxyFactory.createProxyWithNonce`, repeated here so an address can be known before it exists.
    function _predict(ISafeProxyFactory proxies, address singleton, bytes memory init, uint256 saltNonce)
        internal
        pure
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(init), saltNonce));
        bytes32 initHash =
            keccak256(abi.encodePacked(proxies.proxyCreationCode(), uint256(uint160(singleton))));
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(proxies), salt, initHash)))));
    }

    function _write(
        address root,
        address sEcdsa,
        address sPq,
        address lens,
        address implementation,
        uint256 k,
        address[] memory clones
    ) internal {
        string memory j = "arrangement";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeUint(j, "k", k);
        vm.serializeAddress(j, "lens", lens);
        vm.serializeAddress(j, "pqImplementation", implementation);
        vm.serializeAddress(j, "pqOwners", clones);
        vm.serializeAddress(j, "sEcdsa", sEcdsa);
        vm.serializeAddress(j, "sPq", sPq);
        string memory out = vm.serializeAddress(j, "root", root);
        string memory path = string.concat("deployments/", vm.toString(block.chainid), "-arrangement.json");
        vm.writeJson(out, path);
        console.log("");
        console.log("wrote %s", path);
    }
}
