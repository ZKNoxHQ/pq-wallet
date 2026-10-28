// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DeployLocalNested.s.sol
// Description: the whole NESTED arrangement on a local chain, so the front can be driven end to end.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {EntryPoint} from "account-abstraction/contracts/core/EntryPoint.sol";
import {ECDSAk1Verifier} from "InterfaceVerifier/VerifierECDSAk1.sol";
import {ZKNOX_dilithium65} from "ETHDILITHIUM/src/ZKNOX_dilithium65.sol";
import {KEY_BYTES65} from "ETHDILITHIUM/src/ZKNOX_dilithium65_core_packed.sol";
import {ZKNOX_PQFactory7702} from "pq-account/ZKNOX_PQFactory7702.sol";
import {ZKNOX_PQAccount7702} from "pq-account/ZKNOX_PQAccount7702.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ISafeView, ISafeProxyFactory, ISafeSetup} from "../src/interfaces/ISafeView.sol";

/// Anvil has no canonical Safe deployments, so everything is deployed here: the Safe 1.5.0 singleton, its
/// proxy factory and handler, the post-quantum account stack, the lens, then the three Safes of the NESTED
/// policy, funded.
///
/// The point is `app/apps/safe-signer`: this writes `deployments/<chainId>-nested.json` and prints the
/// environment the front reads, so the whole path — digest, device, 84 kB transaction, root execution — can
/// be walked on a laptop before anyone touches Sepolia.
///
/// The holders are software holders derived from the seeds in HOLDER_SEEDS, the same ones the front loads
/// into `VITE_HOLDER_SEEDS`. That is only defensible on a chain whose keys are public to begin with.
///
///   anvil &
///   make safe-deploy-local
contract DeployLocalNested is Script {
    string constant SIGNER = "scripts/mldsa65.mjs";
    string constant S150 = "../lib/safe-smart-account/contracts/";
    /// anvil's first accounts: the EOA owners of S_ecdsa
    uint256 constant ANVIL_PK0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// written next to the arrangement: what a front needs to create further clones and Safes on this chain
    address internal pqFactory;
    address internal safeSingleton;
    address internal safeProxyFactory;
    address internal fallbackHandler;

    function run() external {
        uint256 deployerPk = vm.envOr("DEPLOYER_KEY", ANVIL_PK0);
        uint256 k = vm.envOr("K", uint256(2));
        string[] memory seeds = _seeds();
        require(seeds.length >= k, "HOLDER_SEEDS: fewer seeds than the threshold");

        vm.startBroadcast(deployerPk);

        // ---- the account stack
        address helper = _deployHelper("../lib/ETHDILITHIUM/test/f1600_170.hex");
        EntryPoint entryPoint = new EntryPoint();
        ECDSAk1Verifier k1 = new ECDSAk1Verifier();
        ZKNOX_dilithium65 mldsa = new ZKNOX_dilithium65(helper);
        ZKNOX_PQFactory7702 factory = new ZKNOX_PQFactory7702(entryPoint, k1, mldsa, "local");

        // ---- the Safe stack, from the artifacts compiled apart (see foundry.toml)
        address singleton = deployCode(_artifact(S150, "Safe.sol", "Safe"));
        address singletonL2 = deployCode(_artifact(S150, "SafeL2.sol", "SafeL2"));
        ISafeProxyFactory proxies =
            ISafeProxyFactory(deployCode(_artifact(S150, "proxies/SafeProxyFactory.sol", "SafeProxyFactory")));
        address handler =
            deployCode(_artifact(S150, "handler/CompatibilityFallbackHandler.sol", "CompatibilityFallbackHandler"));
        ZKNOX_SafePQLens lens = new ZKNOX_SafePQLens(singleton, singletonL2, handler);
        pqFactory = address(factory);
        safeSingleton = singleton;
        safeProxyFactory = address(proxies);
        fallbackHandler = handler;

        // ---- the owners
        address[] memory eoas = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            eoas[i] = vm.addr(uint256(keccak256(abi.encodePacked("zknox.local.eoa", i))));
        }
        address[] memory clones = new address[](seeds.length);
        for (uint256 i = 0; i < seeds.length; i++) {
            bytes memory key = _signer("key", seeds[i], "");
            require(key.length == KEY_BYTES65, "expanded key length");
            address k1Addr = vm.addr(uint256(keccak256(abi.encodePacked(_seedBytes(seeds[i]), "k1"))));
            clones[i] = address(factory.createAccount(abi.encodePacked(k1Addr), key, 0));
            console.log("  clone", i, clones[i]);
        }

        // ---- the three Safes
        address sEcdsa = _safe(proxies, singleton, handler, eoas, k, 1);
        address sPq = _safe(proxies, singleton, handler, clones, k, 2);
        address[] memory children = new address[](2);
        children[0] = sEcdsa;
        children[1] = sPq;
        address root = _safe(proxies, singleton, handler, children, 2, 3);
        // not `transfer`: the 2300 gas stipend does not cover a Safe proxy's fallback
        (bool funded,) = root.call{value: vm.envOr("FUND", uint256(10 ether))}("");
        require(funded, "funding the root failed");

        vm.stopBroadcast();

        uint256 v = lens.nestedViolations(root, sEcdsa, sPq, k, address(factory.IMPLEMENTATION()));
        require(v == 0, string.concat("the deployed arrangement violates NESTED: ", vm.toString(v)));

        _write(root, sEcdsa, sPq, address(lens), address(factory.IMPLEMENTATION()), k, clones);
    }

    // ------------------------------------------------------------------ helpers

    function _safe(
        ISafeProxyFactory proxies,
        address singleton,
        address handler,
        address[] memory owners,
        uint256 threshold,
        uint256 salt
    ) internal returns (address) {
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup, (owners, threshold, address(0), "", handler, address(0), 0, payable(address(0)))
        );
        return proxies.createProxyWithNonce(singleton, init, salt);
    }

    /// The k1 half of a holder is `keccak256(seed || "k1")`, as `seedSigner` derives it in the front.
    function _seedBytes(string memory seedHex) internal pure returns (bytes memory out) {
        bytes memory s = bytes(seedHex);
        require(s.length == 64, "a seed is 64 hex characters");
        out = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            out[i] = bytes1(uint8(_nibble(s[2 * i]) * 16 + _nibble(s[2 * i + 1])));
        }
    }

    function _nibble(bytes1 c) internal pure returns (uint8) {
        uint8 x = uint8(c);
        if (x >= 48 && x <= 57) return x - 48;
        if (x >= 97 && x <= 102) return x - 87;
        if (x >= 65 && x <= 70) return x - 55;
        revert("not hexadecimal");
    }

    function _seeds() internal view returns (string[] memory) {
        try vm.envString("HOLDER_SEEDS", ",") returns (string[] memory s) {
            return s;
        } catch {
            string[] memory d = new string[](3);
            d[0] = "18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a";
            d[1] = "29e7c5a381df6b4929e7c5a381df6b4929e7c5a381df6b4929e7c5a381df6b49";
            d[2] = "3ad8b69472ea5c583ad8b69472ea5c583ad8b69472ea5c583ad8b69472ea5c58";
            return d;
        }
    }

    function _signer(string memory cmd, string memory seed, string memory arg) internal returns (bytes memory) {
        string[] memory c = new string[](bytes(arg).length == 0 ? 4 : 5);
        c[0] = "node";
        c[1] = SIGNER;
        c[2] = cmd;
        c[3] = seed;
        if (bytes(arg).length != 0) c[4] = arg;
        return vm.ffi(c);
    }

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

    /// Same resolution as the tests: two Safe releases share file and contract names.
    function _artifact(string memory root, string memory rel, string memory name)
        internal
        view
        returns (string memory)
    {
        string memory source = string.concat(root, rel);
        string[] memory parts = vm.split(source, "/");
        string memory suffix = string.concat(parts[parts.length - 1], "/", name, ".json");
        for (uint256 i = parts.length - 1;; i--) {
            string memory candidate = string.concat("out/", suffix);
            if (vm.exists(candidate)) {
                string[] memory targets =
                    vm.parseJsonKeys(vm.readFile(candidate), ".metadata.settings.compilationTarget");
                if (targets.length == 1 && keccak256(bytes(targets[0])) == keccak256(bytes(source))) return candidate;
            }
            if (i == 0) break;
            suffix = string.concat(parts[i - 1], "/", suffix);
        }
        revert(string.concat("artifact not found: ", source));
    }

    function _write(
        address root,
        address sEcdsa,
        address sPq,
        address lens,
        address pqImplementation,
        uint256 k,
        address[] memory clones
    ) internal {
        string memory j = "nested";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeUint(j, "k", k);
        vm.serializeAddress(j, "sEcdsa", sEcdsa);
        vm.serializeAddress(j, "sPq", sPq);
        vm.serializeAddress(j, "lens", lens);
        vm.serializeAddress(j, "pqImplementation", pqImplementation);
        vm.serializeAddress(j, "pqOwners", clones);
        vm.serializeAddress(j, "pqFactory", pqFactory);
        vm.serializeAddress(j, "safeSingleton", safeSingleton);
        vm.serializeAddress(j, "safeProxyFactory", safeProxyFactory);
        vm.serializeAddress(j, "fallbackHandler", fallbackHandler);
        string memory out = vm.serializeAddress(j, "root", root);
        string memory path = string.concat("deployments/", vm.toString(block.chainid), "-nested.json");
        vm.writeJson(out, path);

        console.log("");
        console.log("wrote", path);
        console.log("--- app/apps/safe-signer/.env ---");
        console.log(string.concat("VITE_CHAIN_ID=", vm.toString(block.chainid)));
        console.log(string.concat("VITE_RPC_URL_", vm.toString(block.chainid), "=http://127.0.0.1:8545"));
        console.log(string.concat("VITE_ROOT=", vm.toString(root)));
        console.log(string.concat("VITE_S_ECDSA=", vm.toString(sEcdsa)));
        console.log(string.concat("VITE_S_PQ=", vm.toString(sPq)));
        console.log(string.concat("VITE_K=", vm.toString(k)));
        console.log(string.concat("VITE_LENS=", vm.toString(lens)));
        console.log(string.concat("VITE_PQ_IMPLEMENTATION=", vm.toString(pqImplementation)));
        console.log("VITE_HOLDER_SEEDS=<the seeds this script used, comma separated>");
    }
}
